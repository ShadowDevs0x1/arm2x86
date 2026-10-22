"""
Objective-C / Metal bridge. The guest's objc_msgSend calls are forwarded to the HOST's real ObjC runtime
(ctypes -> libobjc, Foundation, AppKit, Metal, QuartzCore). Host objects (id/Class/SEL) are passed to the guest
as opaque 64-bit values; the guest never dereferences them. Arguments are marshalled using the method's own
type encoding, so no per-method tables are needed except for sized buffer pointers (see SIZED).

Handled: id/Class/SEL/ints/floats, structs (HFA in d-regs, <=16B in x-regs, >16B by pointer - arm64 AAPCS),
guest @"..." CFString constants -> NSString, guest blocks -> host blocks (completion handlers re-enter the guest),
buffer.contents shadowing, NSLog (%@), class/constant symbol binding, retain/release/autorelease family.
NOT handled: classes DEFINED by the guest (AppDelegate etc.), real threads, NSApplicationMain run loop.
Only runs for real on a Mac (needs libobjc); on Linux only the marshalling logic is importable/testable.
"""
import os, sys, re, struct, ctypes, threading
from ctypes import c_void_p
from unicorn.arm64_const import *
from hle import fn, FUNCS, DATA, RESOLVERS, M64, format_c, _FMT

DARWIN = sys.platform == "darwin"
PENDING, _LOCK, _KEEP = [], threading.Lock(), []

def take_pending():
    with _LOCK: p = PENDING[:]; PENDING.clear()
    return p

# ------------------------------------------------------------------ host ----
_H = {}
def host():
    if _H: return _H
    if not DARWIN: raise RuntimeError("ObjC bridge needs a Mac host")
    o = ctypes.CDLL("/usr/lib/libobjc.A.dylib"); _H["objc"] = o
    for f, r, a in (("objc_getClass", c_void_p, [ctypes.c_char_p]), ("sel_registerName", c_void_p, [ctypes.c_char_p]),
                    ("object_getClass", c_void_p, [c_void_p]), ("class_getSuperclass", c_void_p, [c_void_p]), ("sel_getName", ctypes.c_char_p, [c_void_p]),
                    ("class_getInstanceMethod", c_void_p, [c_void_p, c_void_p]), ("method_getTypeEncoding", ctypes.c_char_p, [c_void_p]),
                    ("method_getImplementation", c_void_p, [c_void_p]), ("objc_retain", c_void_p, [c_void_p]),
                    ("objc_release", None, [c_void_p]), ("objc_autorelease", c_void_p, [c_void_p])):
        g = getattr(o, f); g.restype, g.argtypes = r, a
    fw = "/System/Library/Frameworks/"
    libs = []
    for n in ("Foundation", "AppKit", "Metal", "QuartzCore", "CoreGraphics", "OpenGL"):
        try: libs.append(ctypes.CDLL(f"{fw}{n}.framework/{n}"))
        except OSError: pass
    _H["libs"], _H["sys"] = libs, ctypes.CDLL(None)
    return _H

_msg_cache = {}
def hmsg(obj, sel, *args, restype=c_void_p, argtypes=None):
    """Call a host ObjC method directly (used by the bridge itself)."""
    h = host(); argtypes = argtypes or [c_void_p] * len(args)
    key = (restype, tuple(argtypes))
    if key not in _msg_cache:
        _msg_cache[key] = ctypes.CFUNCTYPE(restype, c_void_p, c_void_p, *argtypes)(ctypes.cast(h["objc"].objc_msgSend, c_void_p).value)
    return _msg_cache[key](obj, h["objc"].sel_registerName(sel.encode()), *args)

# -------------------------------------------------------- type encodings ----
def parse_one(s, i):
    while s[i] in "rnNoORV": i += 1
    c = s[i]
    if c == "{":
        j = i + 1
        while s[j] not in "=}": j += 1
        name, fields = s[i+1:j], []
        if s[j] == "=":
            j += 1
            while s[j] != "}":
                t, j = parse_one(s, j); fields.append(t)
        return ("{", name, fields), j + 1
    if c == "^":
        t, j = parse_one(s, i + 1); return ("^@" if t == "@" else "^"), j
    if c == "@":
        if s[i+1:i+2] == "?": return "@?", i + 2
        if s[i+1:i+2] == '"': return "@", s.index('"', i + 2) + 1
        return "@", i + 1
    if c in "([":
        close = {"(": ")", "[": "]"}[c]; d = 0; j = i
        while True:
            d += (s[j] == c) - (s[j] == close); j += 1
            if d == 0: return "?", j
    if c == "b":
        j = i + 1
        while j < len(s) and s[j].isdigit(): j += 1
        return "?", j
    return c, i + 1

def parse_sig(enc):
    out, i = [], 0
    while i < len(enc):
        t, i = parse_one(enc, i)
        while i < len(enc) and enc[i].isdigit(): i += 1
        out.append(t)
    return out

_CT = {"c": ctypes.c_int8, "C": ctypes.c_uint8, "s": ctypes.c_int16, "S": ctypes.c_uint16, "i": ctypes.c_int32,
       "I": ctypes.c_uint32, "l": ctypes.c_int32, "L": ctypes.c_uint32, "q": ctypes.c_int64, "Q": ctypes.c_uint64,
       "f": ctypes.c_float, "d": ctypes.c_double, "B": ctypes.c_uint8, "v": None}
def ctype_of(t):
    if isinstance(t, tuple):
        class S(ctypes.Structure): _fields_ = [(f"f{i}", ctype_of(x)) for i, x in enumerate(t[2])]
        return S
    return _CT[t] if t in _CT else c_void_p

def leaves(t):
    return [x for f in t[2] for x in leaves(f)] if isinstance(t, tuple) else [t]
def hfa(t):
    if not isinstance(t, tuple): return None
    l = leaves(t)
    return l[0] if 1 <= len(l) <= 4 and l[0] in "fd" and all(x == l[0] for x in l) else None

# ------------------------------------------------------------ guest memory ----
def regions(e):
    return [(b, en) for b, en, _ in e.uc.mem_regions()]
# Host ObjC pointers we have handed the guest. A host allocation can numerically
# land inside a guest mapping; those must never be treated as guest objects.
HOST_IDS = set()
def note_host(p):
    if not p: return 0
    p = int(p) & M64
    HOST_IDS.add(p)
    return p
def is_guest(e, a):
    if not a or (int(a) & M64) in HOST_IDS: return False
    return any(b <= a <= en for b, en in regions(e))

class ArgReader:
    """Reads arm64 (Apple) arguments out of the guest's registers/stack."""
    def __init__(s, e, nx=2): s.e, s.nx, s.nd, s.sp = e, nx, 0, e.sp()
    def stack(s, size, align=8):
        s.sp = (s.sp + align - 1) & ~(align - 1); v = bytes(s.e.read(s.sp, size)); s.sp += size; return v
    def xreg(s):
        if s.nx < 8: v = s.e.uc.reg_read(UC_ARM64_REG_X0 + s.nx); s.nx += 1; return v.to_bytes(8, "little")
        return s.stack(8)
    def dreg(s, size):
        if s.nd < 8:
            v = s.e.uc.reg_read(UC_ARM64_REG_D0 + s.nd); s.nd += 1; return (v & M64).to_bytes(8, "little")[:size]
        return s.stack(size, size)
    def read(s, t):
        ct = ctype_of(t); size = ctypes.sizeof(ct)
        if not isinstance(t, tuple):
            raw = s.dreg(size) if t in "fd" else (s.xreg()[:size] if s.nx < 8 else s.stack(size, size))
            return ct.from_buffer_copy(raw).value
        h = hfa(t)
        if h:
            need, fs = len(leaves(t)), (4 if h == "f" else 8)
            if s.nd + need <= 8: raw = b"".join(s.dreg(fs) for _ in range(need))
            else: s.nd = 8; raw = s.stack(size, 8)
        elif size <= 16:
            raw = b"".join(s.xreg() for _ in range((size + 7) // 8))[:size]
        else:
            raw = bytes(s.e.read(int.from_bytes(s.xreg(), "little"), size))   # passed by reference
        return ct.from_buffer_copy(raw)

def write_ret(e, t, v):
    uc = e.uc
    if t == "v" or v is None: return
    if isinstance(t, tuple):
        raw = bytes(v); size = len(raw); h = hfa(t)
        if h:
            fs = 4 if h == "f" else 8
            for i in range(size // fs): uc.reg_write(UC_ARM64_REG_D0 + i, int.from_bytes(raw[i*fs:(i+1)*fs], "little"))
        elif size <= 16:
            raw = raw.ljust(16, b"\0")
            uc.reg_write(UC_ARM64_REG_X0, int.from_bytes(raw[:8], "little")); uc.reg_write(UC_ARM64_REG_X1, int.from_bytes(raw[8:], "little"))
        else: e.write(uc.reg_read(UC_ARM64_REG_X8), raw)
    elif t in "fd":
        fmt, n = ("<f", 4) if t == "f" else ("<d", 8)
        uc.reg_write(UC_ARM64_REG_D0, int.from_bytes(struct.pack(fmt, v), "little"))
    else:
        uc.reg_write(UC_ARM64_REG_X0, (int(v or 0) & ((1 << (8 * ctypes.sizeof(ctype_of(t)))) - 1)) & M64)

# ----------------------------------------------------- guest <-> host objects ----
class State: cf_isa = None; block_isa = None; selcache = {}; strcache = {}; shadows = []
ST = State()

def guest_cell(e, size=16):
    if ST.cf_isa is None: ST.cf_isa = e.malloc(size)
    return ST.cf_isa

def to_sel(e, v):
    if not is_guest(e, v): return v
    if v not in ST.selcache: ST.selcache[v] = host()["objc"].sel_registerName(e.cstr_bytes(v))
    return ST.selcache[v]

def to_nsstring(e, v):
    """Guest __cfstring constant {isa, flags, char*, len} -> host NSString."""
    if v in ST.strcache: return ST.strcache[v]
    ptr, n = struct.unpack("<QQ", bytes(e.read(v + 16, 16)))
    s = hmsg(host()["objc"].objc_getClass(b"NSString"), "stringWithUTF8String:", bytes(e.read(ptr, n)) + b"\0",
             argtypes=[ctypes.c_char_p])
    hmsg(s, "retain"); ST.strcache[v] = s; return s

class BlockLiteral(ctypes.Structure):
    _fields_ = [("isa", c_void_p), ("flags", ctypes.c_int32), ("reserved", ctypes.c_int32), ("invoke", c_void_p), ("desc", c_void_p)]
class BlockDesc(ctypes.Structure): _fields_ = [("reserved", ctypes.c_ulong), ("size", ctypes.c_ulong)]
BLOCK_T = ctypes.CFUNCTYPE(None, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p)

def make_block(e, gblock):
    """Host block whose invoke queues a call into the guest block (runs on the next bridged call / poll)."""
    invoke = struct.unpack("<Q", bytes(e.read(gblock + 16, 8)))[0]
    def thunk(_b, a1, a2, a3, a4):
        with _LOCK: PENDING.append((invoke, [gblock, a1 or 0, a2 or 0, a3 or 0]))
    cb = BLOCK_T(thunk); desc = BlockDesc(0, ctypes.sizeof(BlockLiteral))
    isa = ctypes.addressof(c_void_p.in_dll(host()["sys"], "_NSConcreteGlobalBlock"))
    lit = BlockLiteral(isa, 1 << 28, 0, ctypes.cast(cb, c_void_p), ctypes.addressof(desc))
    _KEEP.append((cb, desc, lit)); return ctypes.addressof(lit)

# sized guest pointers: selector -> (arg index of pointer, fn(args)->byte size). args = converted values.
def _region_bytes(a): return a[3] * max(a[0].f1.f1, 1) * max(a[0].f1.f2, 1)
SIZED = {
    "setVertexBytes:length:atIndex:": (0, lambda a: a[1]), "setFragmentBytes:length:atIndex:": (0, lambda a: a[1]),
    "setBytes:length:atIndex:": (0, lambda a: a[1]), "newBufferWithBytes:length:options:": (0, lambda a: a[1]),
    "replaceRegion:mipmapLevel:withBytes:bytesPerRow:": (2, _region_bytes),
}
GENERIC_PTR = 256   # unknown out-parameters: copy this many bytes in and back (clamped to mapped memory)

def sync_to_host():
    for host_ptr, g, n in ST.shadows: ctypes.memmove(host_ptr, bytes(ST.emu.read(g, n)), n)
def sync_to_guest():
    for host_ptr, g, n in ST.shadows: ST.emu.write(g, ctypes.string_at(host_ptr, n))
SYNC_BEFORE = {"commit", "didModifyRange:", "presentDrawable:", "waitUntilCompleted"}
SYNC_AFTER = {"waitUntilCompleted", "waitUntilScheduled"}

def msg_send(e, super_call=False):
    ST.emu = e; uc = e.uc
    self_, sel_arg = e.arg(0), e.arg(1)
    if self_ == 0:
        uc.reg_write(UC_ARM64_REG_X0, 0); uc.reg_write(UC_ARM64_REG_X1, 0); return
    selname = selector_name(e, sel_arg)
    if selname in ("stop:", "terminate:", "stop"):
        e.stop_app = True
    if selname == "mainBundle" and getattr(e, "app_bundle", None):
        uc.reg_write(UC_ARM64_REG_X0, e.app_bundle & M64); return
    if try_guest_send(e, self_, sel_arg, selname, super_call):
        return
    if selname == "run" and _is_nsapp(e, self_):
        import cocoa
        cocoa.enter_runloop(e); return
    if not DARWIN:
        sys.stderr.write(f"[objc] {selname or hex(sel_arg)} needs a Mac host\n")
        uc.reg_write(UC_ARM64_REG_X0, 0); return
    o = host()["objc"]
    if super_call:
        self_, cls = struct.unpack("<QQ", bytes(e.read(self_, 16)))
        # objc_msgSendSuper2: the class slot is the class whose superclass we search.
        if cls in CLASSES:
            cls = CLASSES[cls]["super"]
            while cls in CLASSES:                 # skip guest classes; the method wasn't there
                cls = CLASSES[cls]["super"]
        elif DARWIN:
            cls = o.class_getSuperclass(cls)
        # The view was already -initWithFrame:pixelFormat:'d on the host so the GL
        # context exists before guest init. A second super init drops that context
        # (and any textures uploaded during init).
        if selname == "initWithFrame:pixelFormat:" and (self_ & M64) in getattr(e, "preinited_views", ()):
            write_ret(e, "@", self_); return
    else:
        if self_ == 0: uc.reg_write(UC_ARM64_REG_X0, 0); uc.reg_write(UC_ARM64_REG_X1, 0); return
        if is_guest(e, self_):
            if not read_isa_is_cf(e, self_):
                sys.stderr.write(f"[objc] message to guest-defined object {self_:#x} (guest classes unsupported)\n"); e.exit(127); return
            self_ = to_nsstring(e, self_)
        elif not host_ok(e, self_):
            uc.reg_write(UC_ARM64_REG_X0, 0); return
        cls = o.object_getClass(self_)
    sel = to_sel(e, sel_arg); selname = o.sel_getName(sel).decode()
    m = o.class_getInstanceMethod(cls, sel)
    if not m:
        sys.stderr.write(f"[objc] no method {selname or hex(sel)} on host class (forwarding unsupported)\n"); uc.reg_write(UC_ARM64_REG_X0, 0); return
    types = parse_sig(o.method_getTypeEncoding(m).decode())
    ret_t, arg_ts = types[0], types[3:]
    rd, args, copyback = ArgReader(e), [], []
    for t in arg_ts: args.append(rd.read(t))
    conv = []
    for i, (t, v) in enumerate(zip(arg_ts, args)):
        if t == ":": v = to_sel(e, v)
        elif t == "@?": v = make_block(e, v) if v and is_guest(e, v) else v
        elif t == "@" and v and is_guest(e, v): v = to_nsstring(e, v)
        elif t in ("^", "^@", "*") and v and is_guest(e, v):
            rule = SIZED.get(selname); n = rule[1](args) if rule and rule[0] == i else (8 if t == "^@" else GENERIC_PTR)
            buf = ctypes.create_string_buffer(bytes(e.read(v, n)), n); copyback.append((v, buf, n)); v = ctypes.addressof(buf)
        conv.append(v)
    if selname in SYNC_BEFORE: sync_to_host()
    fty = ctypes.CFUNCTYPE(ctype_of(ret_t) if ret_t != "v" else None, c_void_p, c_void_p, *[ctype_of(t) for t in arg_ts])
    r = fty(o.method_getImplementation(m))(self_, sel, *conv)
    for gaddr, buf, n in copyback: e.write(gaddr, buf.raw[:n])
    if selname in SYNC_AFTER: sync_to_guest()
    if selname == "contents" and r:                              # MTLBuffer contents: give the guest a shadow copy
        n = hmsg(self_, "length", restype=ctypes.c_ulong)
        g = e.malloc(n); e.write(g, ctypes.string_at(r, n)); ST.shadows.append((r, g, n)); r = g
    rv = r.value if hasattr(r, "value") else r
    # UTF8String and friends return a host char* the guest will deref. Copy it in.
    if ret_t == "*" and rv and selname in ("UTF8String", "cString", "fileSystemRepresentation", "cStringUsingEncoding:"):
        try:
            raw = ctypes.string_at(int(rv))
            rv = e.alloc_cstr(raw.decode("utf-8", "surrogateescape"))
        except Exception:
            rv = 0
    elif ret_t in ("@", "#") and rv:
        note_host(rv)
    write_ret(e, ret_t, rv)
    if selname == "sharedApplication" or selname == "sharedApplication":
        app = uc.reg_read(UC_ARM64_REG_X0)
        if app: _publish_nsapp(e, app)
    p = take_pending()
    if p: e.begin_callbacks(p, uc.reg_read(UC_ARM64_REG_X0))

def read_isa_is_cf(e, a): return ST.cf_isa is not None and struct.unpack("<Q", bytes(e.read(a, 8)))[0] == ST.cf_isa

@fn("objc_msgSend", "objc_msgSend_stret", "objc_msgSend_fpret")
def _ms(e): msg_send(e)
@fn("objc_msgSendSuper2", "objc_msgSendSuper")
def _mss(e): msg_send(e, True)

@fn("objc_getClass", "objc_lookUpClass", "objc_getMetaClass")
def _gc(e):
    name = e.cstr(e.arg(0))
    g = BY_NAME.get(name)
    if g: return g
    if not DARWIN: return 0
    c = host()["objc"].objc_getClass(name.encode())
    return c or 0
@fn("objc_getClassList")
def _gcl(e):
    buf, n = e.arg(0), s32(e.arg(1)) if False else e.arg(1)
    classes = list(BY_NAME.values())
    if DARWIN:
        pass
    if buf and n:
        for i, c in enumerate(classes[:n]):
            e.write(buf + 8 * i, (c & M64).to_bytes(8, "little"))
    return len(classes)
@fn("sel_registerName", "sel_getUid")
def _sr(e):
    name = e.cstr(e.arg(0))
    if name in SEL_ADDR: return SEL_ADDR[name]
    if DARWIN:
        return host()["objc"].sel_registerName(name.encode()) or sel_guest(e, name)
    return sel_guest(e, name)
@fn("sel_getName")
def _sgn(e):
    n = selector_name(e, e.arg(0))
    return e.alloc_cstr(n) if n else 0
@fn("class_getName")
def _cgn(e):
    c = CLASSES.get(e.arg(0))
    if c: return e.alloc_cstr(c["name"])
    if DARWIN:
        try:
            p = host()["objc"].class_getName(e.arg(0)) if hasattr(host()["objc"], "class_getName") else None
            # class_getName isn't bound in host(); use object description fallback
        except Exception:
            p = None
    return e.alloc_cstr(CLASSES.get(e.arg(0), {}).get("name", "NSObject"))
@fn("objc_alloc", "objc_alloc_init", "objc_allocWithZone")
def _oalloc(e):
    cls = e.arg(0)
    if cls in CLASSES:
        p = alloc_instance(e, CLASSES[cls])
        imp = lookup(CLASSES[cls], "init", False)
        # objc_alloc_init calls init. The stub name isn't available; both alloc and alloc_init
        # are this function. alloc_init is the common Swift path, so call init when it exists.
        if imp:
            e.uc.reg_write(UC_ARM64_REG_X0, p)
            e.uc.reg_write(UC_ARM64_REG_X1, sel_guest(e, "init"))
            e.tail_into(imp)
            return None
        return p
    if not DARWIN: return 0
    fn_ = host()["objc"].objc_alloc if hasattr(host()["objc"], "objc_alloc") else None
    if not fn_: return 0
    fn_.restype, fn_.argtypes = c_void_p, [c_void_p]
    return fn_(cls) or 0
@fn("object_getClass")
def _ogc(e):
    v = e.arg(0)
    if v in CLASSES: return CLASSES[v]["isa"] or v
    if is_guest(e, v):
        try:
            isa = struct.unpack("<Q", bytes(e.read(v, 8)))[0]
            if isa in CLASSES: return isa
        except Exception:
            pass
    if not DARWIN or not v: return 0
    return host()["objc"].object_getClass(v) or 0
@fn("class_getInstanceMethod", "class_getClassMethod")
def _cgim(e): return 0
@fn("method_getImplementation", "method_getName")
def _mgi(e): return 0
@fn("objc_allocateClassPair", "objc_registerClassPair", "class_addMethod", "class_addIvar", "class_addProtocol")
def _dynclass(e):
    sys.stderr.write("[objc] guest class_add*/allocateClassPair is not wired to the host runtime\n")
    return 0
@fn("objc_retain", "objc_retainAutoreleasedReturnValue", "objc_retainAutorelease")
def _ret(e):
    v = e.arg(0); return v if (not v or is_guest(e, v)) else host()["objc"].objc_retain(v)
@fn("objc_release")
def _rel(e):
    v = e.arg(0)
    if v and not is_guest(e, v): host()["objc"].objc_release(v)
@fn("objc_autorelease", "objc_autoreleaseReturnValue", "objc_unsafeClaimAutoreleasedReturnValue")
def _ar(e): return e.arg(0)
@fn("objc_storeStrong")
def _ss(e):
    addr, new = e.arg(0), e.arg(1); old = int.from_bytes(e.read(addr, 8), "little")
    if new and not is_guest(e, new): host()["objc"].objc_retain(new)
    e.write(addr, new.to_bytes(8, "little"))
    if old and not is_guest(e, old): host()["objc"].objc_release(old)
@fn("objc_autoreleasePoolPush")
def _pp(e): return 1
@fn("objc_autoreleasePoolPop")
def _pop(e): return None
@fn("MTLCreateSystemDefaultDevice")
def _dev(e):
    f = ctypes.CDLL("/System/Library/Frameworks/Metal.framework/Metal").MTLCreateSystemDefaultDevice
    f.restype, f.argtypes = c_void_p, []; return f()

# dispatch: best effort. Blocks run on the guest at the next bridged call; semaphores never block.
@fn("dispatch_semaphore_create")
def _dsc(e): return e.malloc(8)
@fn("dispatch_semaphore_signal")
def _dss(e): return 0
@fn("dispatch_semaphore_wait")
def _dsw(e):
    p = take_pending()
    if p: e.begin_callbacks(p, 0)
    else: return 0
@fn("dispatch_async", "dispatch_sync")
def _da(e):
    blk = e.arg(1)
    if blk: e.begin_callbacks([(struct.unpack("<Q", bytes(e.read(blk + 16, 8)))[0], [blk])], 0)

# NSLog(fmt, ...): supports %@ via -description
_NSFMT = re.compile(r"%@")
@fn("NSLog")
def _nslog(e):
    fmt = e.arg(0)
    s = e.cstr(struct.unpack("<Q", bytes(e.read(fmt + 16, 8)))[0]) if is_guest(e, fmt) and read_isa_is_cf(e, fmt) else "?"
    sp, n = e.sp(), [0]
    def next_int(): v = int.from_bytes(e.read(sp + 8 * n[0], 8), "little"); n[0] += 1; return v
    def next_double(): return struct.unpack("<d", struct.pack("<Q", next_int()))[0]
    parts = s.split("%@"); out = []
    for k, part in enumerate(parts):
        out.append(format_c(e, part, next_int, next_double))
        if k < len(parts) - 1:
            obj = next_int(); out.append("(null)" if not obj else
                  ctypes.string_at(hmsg(hmsg(to_nsstring(e, obj) if is_guest(e, obj) else obj, "description"), "UTF8String")).decode("utf8", "replace"))
    sys.stderr.write("".join(out) + "\n")

# ------------------------------------------------ guest-defined classes ----
# AppKit apps ship their AppDelegate in __DATA,__objc_classlist. dyld normally
# realizes those classes; we read the on-disk class_ro_t (arm64 relative method
# lists) and dispatch objc_msgSend at the guest IMP. Host classes (NSView, MTLDevice,
# ...) still go through the real ObjC runtime on a Mac.
FAST_DATA = 0x00007ffffffffff8
CLASSES, BY_NAME, SEL_ADDR = {}, {}, {}
_MISSED = set()

def _u64(e, a):
    return int.from_bytes(e.read(a, 8), "little")
def _mapped(e, a, n=1):
    if not a or a < 0x1000: return False
    try:
        e.read(a, n); return True
    except Exception:
        return False

def selector_name(e, sel):
    if not sel: return ""
    if sel in ST.selcache:
        pass
    cached = getattr(ST, "sel_names", {}).get(sel)
    if cached: return cached
    if _mapped(e, sel, 1):
        try:
            s = e.cstr(sel)
            if s and all(c.isalnum() or c in "_:" for c in s) and len(s) < 200:
                SEL_ADDR.setdefault(s, sel); return s
        except Exception:
            pass
        if _mapped(e, sel, 8):
            p = _u64(e, sel)
            if _mapped(e, p, 1):
                try:
                    s = e.cstr(p)
                    if s and ":" in s or s[:1].islower() or s[:1].isupper():
                        SEL_ADDR.setdefault(s, p); return s
                except Exception:
                    pass
    if DARWIN:
        try:
            n = host()["objc"].sel_getName(sel)
            if n:
                s = n.decode(); SEL_ADDR.setdefault(s, sel); return s
        except Exception:
            pass
    return ""

def sel_guest(e, name):
    if name in SEL_ADDR: return SEL_ADDR[name]
    p = e.alloc_cstr(name); SEL_ADDR[name] = p; return p

def parse_methods(e, mp):
    out = {}
    if not mp or not _mapped(e, mp & ~1, 8): return out
    if mp & 1: mp &= ~1          # relative list-of-lists (shared cache); not used by apps
    ents, count = struct.unpack("<II", bytes(e.read(mp, 8)))
    if not count or count > 100000: return out
    flags, esize = ents & 0xffff0000, ents & 0xfffc
    relative = bool(flags & 0x80000000) or esize == 12
    direct = bool(flags & 0x40000000)
    if esize == 0: esize = 12 if relative else 24
    base = mp + 8
    for i in range(count):
        ea = base + i * esize
        try:
            if relative:
                no, to, io = struct.unpack("<iii", bytes(e.read(ea, 12)))
                np, imp = (ea + no) & M64, (ea + 8 + io) & M64
                if not direct and _mapped(e, np, 8):
                    p2 = _u64(e, np)
                    if _mapped(e, p2, 1): np = p2
                if not _mapped(e, np, 1): continue
                name = e.cstr(np)
            else:
                np, tp, imp = struct.unpack("<QQQ", bytes(e.read(ea, 24)))
                if not _mapped(e, np, 1): continue
                name = e.cstr(np)
        except Exception:
            continue
        if name:
            out[name] = imp
            SEL_ADDR.setdefault(name, np)
    return out

def parse_class(e, addr, depth=0):
    if addr in CLASSES or depth > 8 or not _mapped(e, addr, 40): return None
    isa, sup, _cache, _vt, bits = struct.unpack("<5Q", bytes(e.read(addr, 40)))
    ro = bits & FAST_DATA
    if not _mapped(e, ro, 0x30): return None
    flags, _start, isize, _res = struct.unpack("<4I", bytes(e.read(ro, 16)))
    if isize > 1 << 20: return None
    name_p, meth_p = _u64(e, ro + 0x18), _u64(e, ro + 0x20)
    if not _mapped(e, name_p, 1): return None
    try: name = e.cstr(name_p)
    except Exception: return None
    if not name or len(name) > 200 or not all(c.isalnum() or c in "_$" for c in name): return None
    info = CLASSES[addr] = dict(addr=addr, name=name, super=sup & M64, inst_size=max(isize, 16),
                                 isa=isa, methods={}, is_meta=bool(flags & 1), did_init=False)
    if name not in BY_NAME or not info["is_meta"]:
        BY_NAME[name] = addr
    info["methods"] = parse_methods(e, meth_p)
    if isa and isa != addr:
        parse_class(e, isa, depth + 1)
    return info

def lookup(cls, sel, meta=False):
    seen = set(); c = cls
    while c and c["addr"] not in seen:
        seen.add(c["addr"])
        pool = c["methods"]
        if not meta and sel in pool: return pool[sel]
        if meta:
            meta_cls = CLASSES.get(c["isa"])
            if meta_cls and sel in meta_cls["methods"]: return meta_cls["methods"][sel]
            if sel in pool and c["is_meta"]: return pool[sel]
        c = CLASSES.get(c["super"])
    return None

def alloc_instance(e, cls):
    n = max(cls["inst_size"], 16)
    p = e.malloc(n); e.write(p, b"\0" * n)
    e.write(p, (cls["addr"] & M64).to_bytes(8, "little"))
    return p

def _kind_of(cls, want):
    seen = set(); c = cls
    while c and c["addr"] not in seen:
        seen.add(c["addr"])
        if c["addr"] == want: return True
        w = CLASSES.get(want)
        if w and w["name"] == c["name"]: return True
        c = CLASSES.get(c["super"])
    return False

def try_guest_send(e, obj, sel, name, super_call=False):
    """Return True if `obj` is a guest class or instance (handled, even if the method is missing)."""
    if not obj or not CLASSES: return False
    meta = False
    if super_call and _mapped(e, obj, 16):
        try:
            obj, start = struct.unpack("<QQ", bytes(e.read(obj, 16)))
        except Exception:
            return False
        g = CLASSES.get(start)
        if g is None: return False
        sup = g["super"]
        if sup not in CLASSES:
            return False                       # superclass is a host class; real objc_msgSendSuper2
        cls = CLASSES[sup]
        meta = obj in CLASSES
    elif obj in CLASSES:
        cls, meta = CLASSES[obj], True
    elif _mapped(e, obj, 8):
        isa = _u64(e, obj)
        cls = CLASSES.get(isa)
        if cls is None: return False
    else:
        return False
    uc = e.uc
    if meta and name in ("alloc", "allocWithZone:"):
        uc.reg_write(UC_ARM64_REG_X0, alloc_instance(e, cls)); return True
    if meta and name == "new":
        p = alloc_instance(e, cls)
        uc.reg_write(UC_ARM64_REG_X0, p)
        imp = lookup(cls, "init", False)
        if imp:
            uc.reg_write(UC_ARM64_REG_X1, sel_guest(e, "init")); e.tail_into(imp)
        return True
    if name == "respondsToSelector:":
        q = selector_name(e, e.arg(2))
        uc.reg_write(UC_ARM64_REG_X0, 1 if (lookup(cls, q, False) or q in
                     ("retain", "release", "autorelease", "init", "class", "dealloc")) else 0)
        return True
    if name == "isKindOfClass:" or name == "isMemberOfClass:":
        uc.reg_write(UC_ARM64_REG_X0, 1 if _kind_of(cls, e.arg(2)) else 0); return True
    if name in ("release", "dealloc", ".cxx_destruct"):
        return True
    if name in ("retain", "autorelease", "init") and lookup(cls, name, meta) is None:
        uc.reg_write(UC_ARM64_REG_X0, obj); return True
    if name == "class":
        uc.reg_write(UC_ARM64_REG_X0, cls["addr"] if not meta else cls["isa"] or cls["addr"]); return True
    if name == "self":
        uc.reg_write(UC_ARM64_REG_X0, obj); return True
    imp = lookup(cls, name, meta)
    if name == "initialize" and meta:
        cls["did_init"] = True
    if imp and not cls.get("did_init") and not meta and name != "initialize":
        init = lookup(cls, "initialize", True)
        if init:
            cls["did_init"] = True
            saved = [e.arg(i) for i in range(8)]
            def after(emu, saved=saved, imp=imp):
                for i, v in enumerate(saved):
                    emu.uc.reg_write(UC_ARM64_REG_X0 + i, v & M64)
                emu.tail_into(imp)
            emu_after(e, after)
            e.begin_callbacks([(init, [cls["addr"], sel_guest(e, "initialize")]),
                               (e.resolve("__arm2x86_after"), None)], 0)
            return True
    if imp:
        e.tail_into(imp); return True
    if super_call:
        return False                           # not on the guest chain; try the host superclass
    key = (cls["name"], name)
    if key not in _MISSED and name not in ("description", "debugDescription", "forwardingTargetForSelector:"):
        _MISSED.add(key)
        if os.environ.get("ARM2X86_VERBOSE"):
            sys.stderr.write(f"[objc] -[{cls['name']} {name}] not in guest class\n")
    uc.reg_write(UC_ARM64_REG_X0, 0 if name != "description" else obj)
    return True

def emu_after(e, fn):
    e._after = fn
    FUNCS["__arm2x86_after"] = lambda emu: emu._after(emu)

def host_ok(e, p):
    if not p or p < 0x100000000 or p >= 0xffff000000000000: return False
    return not is_guest(e, p)

def _is_nsapp(e, obj):
    if obj and obj == getattr(e, "nsapp", None): return True
    if not DARWIN or not host_ok(e, obj): return False
    try:
        o = host()["objc"]
        g = o.class_getName
        g.restype, g.argtypes = ctypes.c_char_p, [ctypes.c_void_p]
        name = g(o.object_getClass(obj)) or b""
    except Exception:
        return False
    return name in (b"NSApplication", b"NSRunLoop") or name.endswith(b"Application")

def _is_nsapp_OLD(e, obj):
    if not DARWIN or not obj or is_guest(e, obj): return False
    try:
        o = host()["objc"]
        cls = o.object_getClass(obj)
        # NSApplication / NSRunLoop both have -run, and only the former should own the loop.
        name = ctypes.string_at(o.object_getClassName(obj) if hasattr(o, "object_getClassName") else b"")
    except Exception:
        name = b""
    if not hasattr(host()["objc"], "object_getClassName"):
        # class_getName(object_getClass(obj))
        try:
            g = host()["objc"].class_getName
            g.restype, g.argtypes = ctypes.c_char_p, [c_void_p]
            name = g(host()["objc"].object_getClass(obj)) or b""
        except Exception:
            return False
    return name in (b"NSApplication", b"NSRunLoop") or (isinstance(name, bytes) and name.endswith(b"Application"))

def _publish_nsapp(e, ptr):
    try:
        cell = e.cells.get("_NSApp") or e.resolve("_NSApp")
        e.write(cell, (ptr & M64).to_bytes(8, "little"))
    except Exception:
        pass
    e.nsapp = ptr
    note_host(ptr)

def scan(e):
    """Walk __objc_classlist / __objc_selrefs after fixups."""
    for s in getattr(e.mo, "sections", []):
        if s["sect"] == "__objc_classlist":
            for i in range(s["size"] // 8):
                try: parse_class(e, _u64(e, s["addr"] + 8 * i))
                except Exception: continue
        elif s["sect"] == "__objc_selrefs":
            for i in range(s["size"] // 8):
                try:
                    p = _u64(e, s["addr"] + 8 * i)
                    if _mapped(e, p, 1):
                        nm = e.cstr(p)
                        if nm: SEL_ADDR.setdefault(nm, p)
                except Exception:
                    continue
    if BY_NAME and os.environ.get("ARM2X86_VERBOSE"):
        sys.stderr.write("[objc] guest classes: " + ", ".join(sorted(set(BY_NAME))) + "\n")

def guest_load_calls(e):
    """+load methods, in classlist order. dyld runs these before main."""
    calls = []
    seen = set()
    for addr, c in list(CLASSES.items()):
        if c["is_meta"] or addr in seen: continue
        imp = lookup(c, "load", True)
        if imp and imp not in seen:
            seen.add(imp)
            calls.append((imp, [addr, sel_guest(e, "load")]))
    return calls

def find_delegate(e):
    best = None
    for addr, c in CLASSES.items():
        if c["is_meta"]: continue
        if "applicationDidFinishLaunching:" in c["methods"] or lookup(c, "applicationDidFinishLaunching:", False):
            if c["name"].endswith("Delegate") or "AppDelegate" in c["name"]: return addr
            best = addr
        elif c["name"] in ("AppDelegate", "GameDelegate", "ApplicationDelegate"):
            best = best or addr
    return best

# ------------------------------------------------------- symbol resolution ----
_DATA_RE = re.compile(r"^_(NS|MTL|CA|kCF|kCG)\w*(Key|Mode|Name|Notification|Option|Domain|Default|Identifier)$|^_kCF\w+$")
def _cell(e, key, value):
    if key not in e.cells:
        e.cells[key] = e.next_cell; e.write(e.next_cell, (value & M64).to_bytes(8, "little")); e.next_cell += 8
    return e.cells[key]

def resolver(e, name):
    if name.startswith("_OBJC_CLASS_$_") or name.startswith("_OBJC_METACLASS_$_"):
        short = name.split("$", 1)[-1].lstrip("_") if False else name.split("$_", 1)[-1]
        g = BY_NAME.get(short)
        if g: return g
        if not DARWIN: return None
        c = host()["objc"].objc_getClass(short.encode())
        if not c and os.environ.get("ARM2X86_VERBOSE"):
            sys.stderr.write(f"[objc] class {short} not found on host or in guest\n")
        return c or None
    if name == "___CFConstantStringClassReference": return guest_cell(e)
    if name in ("__NSConcreteStackBlock", "__NSConcreteGlobalBlock", "__NSConcreteMallocBlock"): return _cell(e, name, 0)
    if DARWIN and name not in FUNCS and _DATA_RE.match(name):
        for lib in host()["libs"]:
            try: return _cell(e, name, c_void_p.in_dll(lib, name[1:]).value or 0)
            except ValueError: continue
    return None
RESOLVERS.append(resolver)
