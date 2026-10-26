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
import hle
from hle import fn, FUNCS, DATA, RESOLVERS, M64, format_c, _FMT
import spoof

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
    for n in ("Foundation", "AppKit", "Metal", "QuartzCore", "CoreGraphics", "OpenGL",
              "CoreVideo", "CoreServices", "IOKit", "DiskArbitration", "Security",
              "ServiceManagement", "SystemConfiguration", "Installer", "InstallerPlugins",
              "PackageKit"):
        try: libs.append(ctypes.CDLL(f"{fw}{n}.framework/{n}"))
        except OSError: pass
    pfw = "/System/Library/PrivateFrameworks/"
    for n in ("DiskImages", "DiskManagement", "StorageManagement", "OSInstaller",
              "Install", "IASUtilities", "PackageKit"):
        try: libs.append(ctypes.CDLL(f"{pfw}{n}.framework/{n}"))
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
# Cache Structure classes by layout. ctypes identifies argtypes by *class identity*, so a fresh
# `class S` on every call makes CFUNCTYPE reject instances of a later S with the same fields
# ("expected S instance instead of S") — which is exactly what broke substringWithRange:.
_STRUCT_CACHE = {}
_FTY_CACHE = {}
def _struct_key(t):
    if not isinstance(t, tuple):
        return t
    return ("{", t[1], tuple(_struct_key(f) for f in t[2]))
def ctype_of(t):
    if isinstance(t, tuple):
        key = _struct_key(t)
        if key not in _STRUCT_CACHE:
            class S(ctypes.Structure):
                _fields_ = [(f"f{i}", ctype_of(x)) for i, x in enumerate(t[2])]
            _STRUCT_CACHE[key] = S
        return _STRUCT_CACHE[key]
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
    # A host method that returns its receiver (-init, -retain, ...) hands back a GUEST object when the receiver was one.
    # Such a value is not readable in the host process, and marking it as a host id made is_guest() say "no" for a guest
    # heap object -> it was then passed to real host methods as `self` and crashed them (SIGSEGV). Only readable pointers count.
    if is_tagged_ptr(p) or _readable(p): HOST_IDS.add(p)
    return p
def is_tagged_ptr(p):
    """Apple tagged (isa-less) objects: x86_64 sets bit 0 (payload obfuscated), arm64 sets bit 63.
    Guest addresses can also be odd, so callers that must tell guest from host use is_guest(), which checks the guest
    memory regions first."""
    p = int(p) & M64
    if not p: return False
    if os.uname().machine in ("x86_64", "amd64"): return bool(p & 1)
    return bool(p >> 63)

# ------------------------------------------------- safe host-object check ----
# ctypes cannot catch a SIGSEGV: objc_retain/objc_release on a pointer that is not a live host object kills the whole
# emulator ("Fatal Python error: Segmentation fault"). Guest code can hand us such values (stack blocks, half-built guest
# objects, raw scalars stored through a synthesized setter). Probe the memory with write(2) on a pipe first: the kernel
# returns EFAULT for an unreadable address instead of crashing us.
_PROBE = {}
_WARNED_BAD = set()
def _readable(addr, n=8):
    if "p" not in _PROBE:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.write.argtypes, libc.write.restype = [ctypes.c_int, c_void_p, ctypes.c_size_t], ctypes.c_ssize_t
        libc.read.argtypes, libc.read.restype = [ctypes.c_int, c_void_p, ctypes.c_size_t], ctypes.c_ssize_t
        r, w = os.pipe(); _PROBE.update(p=(r, w), libc=libc)
    r, w = _PROBE["p"]; libc = _PROBE["libc"]
    if addr < 0x1000 or addr >= (1 << 47): return False
    k = libc.write(w, addr, n)
    if k <= 0: return False
    buf = ctypes.create_string_buffer(k); libc.read(r, buf, k)           # drain so the pipe never fills
    return True
def host_obj_ok(v):
    """True if v looks like a live host ObjC object (tagged pointer, or readable object whose isa/class is readable)."""
    v = int(v) & M64
    if not v: return False
    if is_tagged_ptr(v): return True
    if v & 7 or not _readable(v): return False
    isa = int.from_bytes(ctypes.string_at(v, 8), "little") & 0x00007ffffffffff8
    return bool(isa) and _readable(isa)
def warn_bad(what, v):
    if v not in _WARNED_BAD:
        _WARNED_BAD.add(v)
        sys.stderr.write(f"[objc] {what}: {v:#x} is not a valid host object -> not retained/released (would have segfaulted)\n")

def is_guest(e, a):
    """True if `a` points into guest (emulated) memory. Region membership is decided FIRST: an odd guest address (a selector
    or string in __TEXT) can look like a tagged pointer, and a stale HOST_IDS entry can shadow a guest address. A HOST_IDS
    entry only counts while the pointer is still live in this process."""
    if not a: return False
    a = int(a) & M64
    if not any(b <= a <= en for b, en in regions(e)): return False
    if a in HOST_IDS and _readable(a): return False
    return True

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
class State: cf_isa = None; block_isa = None; selcache = {}; strcache = {}; shadows = []; enum_slots = {}
ST = State()

def guest_cell(e, size=16):
    if ST.cf_isa is None: ST.cf_isa = e.malloc(size)
    return ST.cf_isa

_SEL_NOTED = set()
def to_sel(e, v):
    """guest selector (pointer to a C string in guest memory) -> host SEL. A pointer that is mapped in the guest but NOT
    readable in this process cannot be a host SEL: sel_getName() would hand it straight back and ctypes would segfault
    dereferencing it, so register it by name even when is_guest() disagrees (e.g. because of HOST_IDS)."""
    if v in ST.selcache: return ST.selcache[v]
    g = is_guest(e, v)
    if not g and v and 0x1000 <= v < (1 << 47) and not _readable(v) and _mapped(e, v, 1):
        g = True
        if v not in _SEL_NOTED:
            _SEL_NOTED.add(v); sys.stderr.write(f"[objc] selector {v:#x}: guest string that is_guest() missed -> registered by name\n")
    if not g: return v
    ST.selcache[v] = host()["objc"].sel_registerName(e.cstr_bytes(v))
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
# NSArray/NSDictionary/NSSet C-array constructors: the pointer is an id[count], NOT a single id (was copied as 8 bytes -> nil objects[1])
_cnt = lambda a: a[-1] * 8
SIZED.update({
    "arrayWithObjects:count:": (0, _cnt), "initWithObjects:count:": (0, _cnt),
    "dictionaryWithObjects:forKeys:count:": ((0, 1), _cnt), "initWithObjects:forKeys:count:": ((0, 1), _cnt),
    "getObjects:range:": (0, lambda a: a[1].f1 * 8), "setWithObjects:count:": (0, _cnt),
})
OBJ_ARRAYS = {"arrayWithObjects:count:", "initWithObjects:count:", "dictionaryWithObjects:forKeys:count:",
              "initWithObjects:forKeys:count:", "setWithObjects:count:"}
GENERIC_PTR = 256   # unknown out-parameters: copy this many bytes in and back (clamped to mapped memory)

def sync_to_host():
    for host_ptr, g, n in ST.shadows: ctypes.memmove(host_ptr, bytes(ST.emu.read(g, n)), n)
def sync_to_guest():
    for host_ptr, g, n in ST.shadows: ST.emu.write(g, ctypes.string_at(host_ptr, n))
SYNC_BEFORE = {"commit", "didModifyRange:", "presentDrawable:", "waitUntilCompleted"}
SYNC_AFTER = {"waitUntilCompleted", "waitUntilScheduled"}

_NULL = []
def null_object():
    if not _NULL: _NULL.append(hmsg(host()["objc"].objc_getClass(b"NSNull"), "null"))
    return _NULL[0]
_CRUMB = None
def crumb(text):
    """Last host ObjC call, written to a file so a host segfault can still be attributed (see loader.py supervisor)."""
    global _CRUMB
    p = os.environ.get("ARM2X86_CRUMB")
    if not p: return
    try:
        if _CRUMB is None: _CRUMB = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
        os.ftruncate(_CRUMB, 0); os.pwrite(_CRUMB, text.encode("utf-8", "replace"), 0)
    except OSError: pass

def _fast_enumerate(e, obj, sel):
    """Host -countByEnumeratingWithState:objects:count: writes host pointers into
    NSFastEnumerationState (itemsPtr, mutationsPtr). The guest immediately
    dereferences both, so park them in guest memory before returning."""
    gstate, gbuf, nlen = e.arg(2), e.arg(3), int(e.arg(4)) & M64
    if not gstate or not gbuf or not is_guest(e, gstate) or nlen == 0 or nlen > 4096:
        return False
    STATE = 64
    try:
        raw = bytearray(e.read(gstate, STATE))
    except Exception:
        return False
    struct.pack_into("<QQ", raw, 8, 0, 0)          # don't hand the host guest pointers
    state_buf = ctypes.create_string_buffer(bytes(raw), STATE)
    obj_buf = (ctypes.c_void_p * nlen)()
    o = host()["objc"]
    cls = o.object_getClass(obj)
    m = o.class_getInstanceMethod(cls, sel) if cls else None
    if not m: return False
    FN = ctypes.CFUNCTYPE(ctypes.c_uint64, c_void_p, c_void_p, c_void_p, c_void_p, ctypes.c_uint64)
    try:
        ret = int(FN(o.method_getImplementation(m))(obj, sel, ctypes.addressof(state_buf), ctypes.addressof(obj_buf), nlen))
    except Exception as ex:
        sys.stderr.write(f"[objc] countByEnumeratingWithState: {ex}\n")
        return False
    ret = max(0, min(ret, nlen))
    st_state, items_ptr, mut_ptr = struct.unpack_from("<QQQ", state_buf.raw)
    extra = state_buf.raw[24:64]
    mut_val = 1
    if mut_ptr:
        try: mut_val = struct.unpack("<Q", ctypes.string_at(mut_ptr, 8))[0]
        except Exception: mut_val = 1
    slot = ST.enum_slots.get(gstate)
    if slot is None:
        slot = e.malloc(8); ST.enum_slots[gstate] = slot
    e.write(slot, (mut_val & M64).to_bytes(8, "little"))
    ids = []
    if ret and items_ptr:
        try: blob = ctypes.string_at(items_ptr, 8 * ret)
        except Exception: blob = b""
        for i in range(ret):
            if 8 * i + 8 <= len(blob):
                p = struct.unpack_from("<Q", blob, 8 * i)[0]
                ids.append(p)
                if p and not is_tagged_ptr(p): note_host(p)
    e.write(gbuf, b"".join((p & M64).to_bytes(8, "little") for p in ids))
    items = (gbuf if ret else 0) & M64
    e.write(gstate, struct.pack("<QQQ", st_state & M64, items, slot & M64) + extra)
    e.uc.reg_write(UC_ARM64_REG_X0, ret & M64)
    if os.environ.get("ARM2X86_VERBOSE"):
        sys.stderr.write(f"[objc] fast-enum -> {ret} items\n")
    return True

def _bundle_executable_path(e, bundle):
    """Best-effort absolute path of an NSBundle's main executable (host object)."""
    if not bundle or not DARWIN or is_guest(e, bundle):
        return None
    try:
        p = hmsg(bundle, "executablePath")
        if p:
            s = ctypes.string_at(hmsg(p, "UTF8String") or 0)
            if s: return s.decode("utf-8", "replace")
        p = hmsg(bundle, "bundlePath")
        if p:
            s = ctypes.string_at(hmsg(p, "UTF8String") or 0)
            if s:
                base = s.decode("utf-8", "replace")
                name = os.path.basename(base)
                if name.endswith(".bundle"): name = name[:-7]
                cand = os.path.join(base, "Contents", "MacOS", name)
                if os.path.isfile(cand): return cand
                return base
    except Exception:
        pass
    return None

def _try_guest_bundle_load(e, bundle, selname):
    """Load an arm64 plugin into the guest instead of letting host NSBundle dlopen it."""
    path = _bundle_executable_path(e, bundle)
    if not path:
        return False
    try:
        import dylib as _dylib
    except ImportError:
        return False
    if not _dylib.is_arm64_macho(path):
        return False
    if selname == "preflightAndReturnError:":
        errp = e.arg(2)
        if errp: e.write(errp, (0).to_bytes(8, "little"))
        e.uc.reg_write(UC_ARM64_REG_X0, 1)
        return True
    ok = _dylib.load_path(e, path)
    if selname == "principalClass":
        name = None
        plist = path
        parts = path.split(os.sep)
        if "Contents" in parts:
            i = parts.index("Contents")
            plist = os.sep.join(parts[:i + 1] + ["Info.plist"])
        try:
            import plistlib
            if os.path.isfile(plist):
                with open(plist, "rb") as f:
                    d = plistlib.load(f) or {}
                    name = d.get("NSPrincipalClass") or d.get("CFBundlePrincipalClass")
        except Exception:
            name = None
        cls = BY_NAME.get(name) if name else None
        if not cls:
            sys.stderr.write(f"[objc] principalClass of {os.path.basename(path)}: plist names {name!r}, not among guest classes "
                             f"{sorted(c['name'] for c in CLASSES.values() if c.get('name') and not c.get('is_meta'))[:40]}\n")
            for addr, c in CLASSES.items():
                if not c.get("is_meta") and c.get("name") and not c["name"].startswith("IAApp_"):
                    cls = addr; break
        e.uc.reg_write(UC_ARM64_REG_X0, (cls or 0) & M64)
        return True
    errp = e.arg(2) if selname.endswith(":") else 0
    if errp: e.write(errp, (0).to_bytes(8, "little"))
    e.uc.reg_write(UC_ARM64_REG_X0, 1 if ok else 0)
    if ok:
        sys.stderr.write(f"[objc] guest-loaded arm64 bundle {os.path.basename(path)}\n")
    else:
        sys.stderr.write(f"[objc] failed to guest-load {path}\n")
    return True

_VARIADIC_FMT = {"stringWithFormat:", "initWithFormat:", "localizedStringWithFormat:", "appendFormat:", "stringByAppendingFormat:"}
def _variadic_format(e, self_, selname):
    """+stringWithFormat: & co. are variadic: the guest passes the extra args on ITS stack, which a fixed-arity host call never
    sees (the host then formats garbage registers: SIGSEGV in CFString). Format here, call the non-variadic twin on the host."""
    text = py_str(e, e.arg(2))
    if text is None: return False
    out = objc_format(e, text, e.sp())
    if selname in ("stringWithFormat:", "localizedStringWithFormat:"):
        r = hmsg(self_, "stringWithUTF8String:", out.encode("utf-8", "replace") + b"\0", argtypes=[ctypes.c_char_p])
    elif selname == "initWithFormat:":
        r = hmsg(self_, "initWithUTF8String:", out.encode("utf-8", "replace") + b"\0", argtypes=[ctypes.c_char_p])
    elif selname == "appendFormat:":
        hmsg(self_, "appendString:", _new_host_string(out)); r = 0
    else:
        r = hmsg(self_, "stringByAppendingString:", _new_host_string(out))
    e.uc.reg_write(UC_ARM64_REG_X0, (r or 0) & M64)
    return True

# ---- variadic collection constructors --------------------------------------------------------------------------------------
# +arrayWithObjects:, -initWithObjects:, +dictionaryWithObjectsAndKeys: ... take a nil-terminated list. The guest (Apple arm64)
# passes the first object in x2 and EVERYTHING AFTER IT ON ITS STACK; the host call through ctypes is fixed-arity, so the host
# read garbage registers as objects -> -[NSArray initWithObjects:] crashed in __NSArrayI_new (SIGSEGV at 0x8). Gather the list
# here and call the non-variadic host twin (...count:).
_VARIADIC_OBJS = {"arrayWithObjects:": ("arrayWithObjects:count:", False), "initWithObjects:": ("initWithObjects:count:", False),
                  "setWithObjects:": ("setWithObjects:count:", False), "orderedSetWithObjects:": ("orderedSetWithObjects:count:", False),
                  "dictionaryWithObjectsAndKeys:": ("dictionaryWithObjects:forKeys:count:", True),
                  "initWithObjectsAndKeys:": ("initWithObjects:forKeys:count:", True)}
def to_nsstring_text(e, p):
    """Python str of a guest __cfstring constant or a host NSString."""
    p = int(p) & M64
    if is_guest(e, p):
        p = to_nsstring(e, p) if read_isa_is_cf(e, p) else 0
    if not p: return ""
    return ctypes.string_at(hmsg(p, "UTF8String")).decode("utf8", "replace")
def _host_elem(e, p):
    p = int(p) & M64
    if p and is_guest(e, p):
        if read_isa_is_cf(e, p): return to_nsstring(e, p)
        return null_object()                       # guest-defined object the host cannot message: NSNull placeholder
    return p
def _variadic_objects(e, self_, selname):
    twin, pairs = _VARIADIC_OBJS[selname]
    h = host()["objc"]
    try:
        if not hmsg(self_, "respondsToSelector:", h.sel_registerName(twin.encode()), restype=ctypes.c_ubyte, argtypes=[c_void_p]): return False
    except Exception: return False
    words, sp = [e.arg(2)], e.sp()
    if words[0]:
        for i in range(4096):
            w = int.from_bytes(e.read(sp + 8 * i, 8), "little")
            if pairs and i % 2 == 1 and w == 0: break          # (obj, key) pairs: the list ends at a nil OBJECT
            if not pairs and w == 0: break
            words.append(w)
    else: words = []
    if pairs:
        objs, keys = words[0::2], words[1::2]; n = min(len(objs), len(keys))
        o_arr = (c_void_p * max(n, 1))(*[_host_elem(e, p) for p in objs[:n]])
        k_arr = (c_void_p * max(n, 1))(*[_host_elem(e, p) for p in keys[:n]])
        r = hmsg(self_, twin, ctypes.addressof(o_arr), ctypes.addressof(k_arr), n, argtypes=[c_void_p, c_void_p, ctypes.c_ulong])
    else:
        n = len(words); arr = (c_void_p * max(n, 1))(*[_host_elem(e, p) for p in words])
        r = hmsg(self_, twin, ctypes.addressof(arr), n, argtypes=[c_void_p, ctypes.c_ulong])
    e.uc.reg_write(UC_ARM64_REG_X0, (r or 0) & M64)
    if r: note_host(r)
    return True

# ---- NSDictionaryOfVariableBindings(a, b, c) --------------------------------------------------------------------------------
# The macro expands to  _NSDictionaryOfVariableBindings(@"a, b, c", a, b, c, nil).  The first VALUE is a named parameter (x1) and the
# rest are variadic (stack, 8 bytes each, from sp). Unemulated it returned nil, so every later
# +constraintsWithVisualFormat:options:metrics:views: threw "<name> is not a key in the views dictionary".
@fn("_NSDictionaryOfVariableBindings")
def _nsdict_of_variable_bindings(e):
    ks = e.arg(0)
    try:
        keys_s = (to_nsstring_text(e, ks) if ks else "")
    except Exception:
        keys_s = ""
    names = [k.strip() for k in keys_s.split(",") if k.strip()]
    h = host()["objc"]
    d = hmsg(hmsg(h.objc_getClass(b"NSMutableDictionary"), "alloc"), "init")
    sp = e.sp()
    for i, name in enumerate(names):
        v = e.arg(1) if i == 0 else int.from_bytes(e.read(sp + 8 * (i - 1), 8), "little")
        v = _host_elem(e, v) if v else 0
        if not v or v == null_object():
            _warn_arg(f"[objc] NSDictionaryOfVariableBindings: '{name}' is nil / a guest-only object -> left out")
            continue
        key = hmsg(h.objc_getClass(b"NSString"), "stringWithUTF8String:", name.encode() + b"\0", argtypes=[ctypes.c_char_p])
        hmsg(d, "setObject:forKey:", v, key)
    note_host(d)
    return d

# ---- a guest pointer passed where the host expects an object -------------------------------------------------------------
# to_nsstring() reads {isa, flags, char*, len} at v+16 and builds an NSString from it. That is only valid for a real
# __cfstring constant. An unresolved IMPORT (a stub, i.e. code: bytes 0xd65f03c0 = `ret`) or any other guest object was fed
# through it too, producing an NSString that points at garbage -> SIGSEGV inside CFPreferences (-[NSUserDefaults objectForKey:]).
_WARNED_ARG = set()
def _warn_arg(msg):
    if msg not in _WARNED_ARG: _WARNED_ARG.add(msg); sys.stderr.write(msg + "\n")
def _host_symbol_object(name):
    """value of an exported host data symbol (e.g. an NSString* constant such as NSFoo), or 0"""
    h = host()
    # CoreFoundation's immortal empty collections (the target of @{} / @[] / @{}-style literals: __NSDictionary0__struct,
    # __NSArray0__struct, ...) are STATIC OBJECTS: the symbol's address is the object. Reading the pointer stored at it
    # yields the object's isa (a class), and every message to it then fails with "unrecognized selector sent to class".
    by_address = name.startswith("__NS") and name.endswith("__struct")
    for lib in [h["sys"]] + h["libs"]:
        try:
            cell = c_void_p.in_dll(lib, name)
            return (ctypes.addressof(cell) if by_address else cell.value) or 0
        except (ValueError, AttributeError, OSError): continue
    return 0
def _guest_obj_arg(e, v, selname):
    if v in _SYMSTR:                                   # placeholder for e.g. NSFontTextStyleLargeTitle: use the host's real constant
        real = _host_symbol_object(_SYMSTR[v])
        if real: return real
    if read_isa_is_cf(e, v): return to_nsstring(e, v)
    nm = stub_symbol(e, v)
    if nm is not None:
        if nm.startswith("_OBJC_CLASS_$_"):
            real, _ = unresolved_class(e, v)
            if real and real not in CLASSES: return real          # a guest-framework class is no host object: falls through to nil
        else:
            real = _host_symbol_object(nm[1:])
            if real:
                _warn_arg(f"[objc] unresolved import {nm} used as an object argument of -[{selname}]: resolved from the host")
                return real
        _warn_arg(f"[objc] unresolved import {nm} used as an object argument of -[{selname}] -> nil")
        return 0
    _warn_arg(f"[objc] guest-defined object {v:#x} passed to host -[{selname}] -> nil (the host cannot message guest objects)")
    return 0
_KEYED_LAST = ("ForKey:", "forKey:", "ForKeyPath:", "forKeyPath:")
def _nil_key(selname, arg_ts, conv):
    """True when a key argument became nil: NSUserDefaults/NSDictionary/CFPreferences crash (not raise) on a nil key."""
    if not selname.endswith(_KEYED_LAST): return False
    objs = [i for i, t in enumerate(arg_ts) if t == "@"]
    return bool(objs) and conv[objs[-1]] in (0, None)

# ---- weak references (arm2x86 had no emulation: the guest's weak ivars/delegates silently became nil) --------------------
@fn("objc_storeWeak", "objc_storeWeakOrNil")
def _store_weak(e):
    loc, obj = e.arg(0), e.arg(1)
    if loc: e.write(loc, (obj & M64).to_bytes(8, "little"))
    return obj
@fn("objc_initWeak")
def _init_weak(e):
    loc, obj = e.arg(0), e.arg(1)
    if loc: e.write(loc, (obj & M64).to_bytes(8, "little"))
    return obj
@fn("objc_loadWeak", "objc_loadWeakRetained")
def _load_weak(e):
    loc = e.arg(0)
    return int.from_bytes(e.read(loc, 8), "little") if loc else 0
@fn("objc_destroyWeak")
def _destroy_weak(e):
    if e.arg(0): e.write(e.arg(0), b"\0" * 8)
@fn("objc_copyWeak", "objc_moveWeak")
def _copy_weak(e):
    dst, src = e.arg(0), e.arg(1)
    if dst and src: e.write(dst, bytes(e.read(src, 8)))

_OBJCTRACE = bool(os.environ.get("ARM2X86_OBJCTRACE"))
def _describe(e, obj):
    try:
        if obj in CLASSES: return "+" + str(CLASSES[obj].get("name"))
        if _mapped(e, obj, 8) and _u64(e, obj) in CLASSES: return "-" + str(CLASSES[_u64(e, obj)].get("name"))
        if DARWIN and not is_guest(e, obj) and host_ok(e, obj):
            g = host()["objc"].object_getClassName; g.restype, g.argtypes = ctypes.c_char_p, [c_void_p]
            return "host " + (g(obj) or b"?").decode()
    except Exception: pass
    return f"{obj:#x}"
def _trace_msg(e, obj, selname, super_call):
    sys.stderr.write(f"[msg] {_describe(e, obj)} {selname}{' (super)' if super_call else ''}  lr={e.uc.reg_read(UC_ARM64_REG_LR):#x}\n")
import collections
_RING = collections.deque(maxlen=120)           # last messages the guest sent; printed when the guest logs a "Cannot ..." error
def dump_ring(e, why=""):
    sys.stderr.write(f"[objc] last {len(_RING)} messages before {why!r}:\n")
    for o, sn, lr, sup in list(_RING):
        sys.stderr.write(f"  {_describe(e, o)} {sn}{' (super)' if sup else ''}  lr={lr:#x}\n")


_FATAL = []
_IMAGE_SINKS = {"setImage:", "setObjectValue:", "setAlternateImage:", "setImageNamed:"}
def _is_nsimage_instance(v):
    """True iff v is a live host object that is an INSTANCE of NSImage (a Class object answers NO)."""
    try:
        o = host()["objc"]
        o.object_isClass.restype, o.object_isClass.argtypes = ctypes.c_bool, [c_void_p]
        if o.object_isClass(v): return False
        return bool(hmsg(v, "isKindOfClass:", o.objc_getClass(b"NSImage"), restype=ctypes.c_ubyte))
    except Exception:
        return False
def _describe_host_obj(v):
    try:
        o = host()["objc"]
        o.object_isClass.restype, o.object_isClass.argtypes = ctypes.c_bool, [c_void_p]
        o.class_getName.restype, o.class_getName.argtypes = ctypes.c_char_p, [c_void_p]
        o.object_getClass.restype, o.object_getClass.argtypes = c_void_p, [c_void_p]
        if o.object_isClass(v): return "a Class object: " + (o.class_getName(v) or b"?").decode()
        return "instance of " + (o.class_getName(o.object_getClass(v)) or b"?").decode()
    except Exception as ex:
        return f"unknown ({ex})"

# ---- guest methods whose real work needs a helper process / system service we cannot run ---------------------------------------
# OSISClient talks to a launchd-started helper ("osis tool") over XPC; without it -isDeviceSupportedWithError: answers NO and the
# installer shows its fatal-error pane (then quits on Continue).  These answers are forced instead.  Extend with
# ARM2X86_GUEST_YES="Class.selector:,Class2.sel2" (BOOL YES) / ARM2X86_GUEST_NO="..." (BOOL NO).
_GUEST_YES = {("OSISClient", "isDeviceSupportedWithError:")}
_GUEST_NO = set()
for _env, _set in (("ARM2X86_GUEST_YES", _GUEST_YES), ("ARM2X86_GUEST_NO", _GUEST_NO)):
    for _x in os.environ.get(_env, "").split(","):
        if "." in _x: _set.add(tuple(_x.strip().split(".", 1)))
_OVR_SEEN = set()
def _guest_override(e, self_, selname):
    if not (_GUEST_YES or _GUEST_NO) or not is_guest(e, self_): return False
    try:
        c = CLASSES.get(self_) or CLASSES.get(_u64(e, self_))
    except Exception:
        return False
    if not c: return False
    nm = (c.get("name") or "").lstrip("_")
    key = (nm, selname)
    if key not in _GUEST_YES and key not in _GUEST_NO: return False
    val = 1 if key in _GUEST_YES else 0
    for i in range(2, 4):                                  # an NSError** out-parameter: clear it
        pass
    if selname.endswith("Error:") and e.arg(2) and is_guest(e, e.arg(2)) is not None:
        try: e.write(e.arg(2), (0).to_bytes(8, "little"))
        except Exception: pass
    e.uc.reg_write(UC_ARM64_REG_X0, val)
    if key not in _OVR_SEEN:
        _OVR_SEEN.add(key); sys.stderr.write(f"[objc] guest override: -[{nm} {selname}] -> {'YES' if val else 'NO'} (its helper service is not emulated)\n")
    return True
def msg_send(e, super_call=False):
    ST.emu = e; uc = e.uc
    self_, sel_arg = e.arg(0), e.arg(1)
    if self_ == 0:
        uc.reg_write(UC_ARM64_REG_X0, 0); uc.reg_write(UC_ARM64_REG_X1, 0); return
    selname = selector_name(e, sel_arg)
    if _OBJCTRACE: _trace_msg(e, self_, selname, super_call)
    _RING.append((self_, selname, uc.reg_read(UC_ARM64_REG_LR), super_call))
    if selname in spoof.SELS and DARWIN and not super_call and spoof.on_msg(e, self_, selname): return
    if selname in ("setMessageText:", "setInformativeText:") and DARWIN: spoof.note_alert(e, selname)
    if selname in ("stop:", "terminate:", "stop"):
        e.stop_app = True
    if selname == "mainBundle" and getattr(e, "app_bundle", None):
        uc.reg_write(UC_ARM64_REG_X0, e.app_bundle & M64); return
    if not super_call and _guest_override(e, self_, selname): return
    if try_guest_send(e, self_, sel_arg, selname, super_call):
        return
    if DARWIN and selname in _VARIADIC_FMT and not super_call:
        if _variadic_format(e, self_, selname): return
    if selname == "run" and _is_nsapp(e, self_):
        import cocoa
        dump_ring(e, "NSApp run")
        _show_proxies(e)
        cocoa.enter_runloop(e); return
    if selname in ("addObserver:forKeyPath:options:context:", "removeObserver:forKeyPath:", "removeObserver:forKeyPath:context:") \
            and is_guest(e, e.arg(2)):
        uc.reg_write(UC_ARM64_REG_X0, 0); return          # KVO observer is a guest object the host can't call back into
    if selname in ("addObserver:selector:name:object:", "removeObserver:", "removeObserver:name:object:") \
            and e.arg(2) and is_guest(e, e.arg(2)):
        # NSNotificationCenter observer that lives in the guest heap: the host would send it the selector on notification and
        # dereference a pointer that does not exist in the host process. Not wired to a guest callback yet -> ignored (logged once).
        _warn_arg(f"[objc] -[{selname}] with guest observer {e.arg(2):#x} ignored: notifications are not delivered to guest objects yet")
        uc.reg_write(UC_ARM64_REG_X0, 0); return
    # NSBundle load of arm64/arm64e plugins must not hit the host dlopen (wrong arch).
    if selname in ("load", "loadAndReturnError:", "preflightAndReturnError:", "principalClass") and \
            _try_guest_bundle_load(e, self_, selname):
        return
    if not DARWIN:
        sys.stderr.write(f"[objc] {selname or hex(sel_arg)} needs a Mac host\n")
        uc.reg_write(UC_ARM64_REG_X0, 0); return
    o = host()["objc"]
    if super_call:
        self_, cls = struct.unpack("<QQ", bytes(e.read(self_, 16)))
        self_ = HOST_PROXY.get(self_, self_)
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
        self_ = HOST_PROXY.get(self_, self_)
        if is_guest(e, self_):
            if stub_symbol(e, self_) is not None:       # receiver is an unresolved class/import stub
                real, nm = unresolved_class(e, self_)
                if not real:
                    spoof.missing_class_msg(e, nm, selname); return   # message to a class nobody can load: log it, BOOL checks say YES
                if real in CLASSES:                                   # a class of a guest-loaded framework (OSISClient ...): run guest code
                    uc.reg_write(UC_ARM64_REG_X0, real & M64)
                    if try_guest_send(e, real, sel_arg, selname, super_call): return
                    spoof.missing_class_msg(e, nm, selname); return   # the guest class has no such method: never hand it to the host
                self_ = real
            elif not read_isa_is_cf(e, self_):
                sys.stderr.write(f"[objc] message to guest-defined object {self_:#x} (guest classes unsupported)\n"); e.exit(127); return
            else:
                self_ = to_nsstring(e, self_)
        elif not host_ok(e, self_):
            uc.reg_write(UC_ARM64_REG_X0, 0); return
        cls = o.object_getClass(self_)
    sel = to_sel(e, sel_arg); selname = o.sel_getName(sel).decode()
    if selname == "displayFatalErrorMessage:": _FATAL.append(1)
    if _FATAL and selname in ("setStringValue:", "setTitle:", "setMessageText:", "setInformativeText:"):
        try:
            txt = ctypes.string_at(hmsg(e.arg(2), "UTF8String")).decode("utf8", "replace") if e.arg(2) and not is_guest(e, e.arg(2)) else ""
            if txt: sys.stderr.write(f"[objc] >>> installer fatal-error text: {txt!r}\n")
        except Exception: pass
        _FATAL.clear()
    if selname == "terminate:" and not os.environ.get("ARM2X86_ALLOW_TERMINATE"):
        sys.stderr.write(f"[objc] >>> the guest asked the app to QUIT: -[terminate:] (guest lr={uc.reg_read(UC_ARM64_REG_LR):#x}); "
                         f"ignored so the window stays up. What led here (newest last):\n")
        dump_ring(e, "terminate:"); write_ret(e, "v", 0); return
    if selname == "bundleForClass:" and not super_call and is_guest(e, e.arg(2)):
        b = _guest_class_bundle(e)                               # +[NSBundle bundleForClass:<guest class>]: the host cannot read it
        if b: write_ret(e, "@", b); return                       # (nil made imageForResource:/nib lookups fail)
    if selname == "countByEnumeratingWithState:objects:count:" and _fast_enumerate(e, self_, sel):
        return
    if selname in _VARIADIC_OBJS and not super_call and _variadic_objects(e, self_, selname): return
    m = o.class_getInstanceMethod(cls, sel)
    if not m:
        sys.stderr.write(f"[objc] no method {selname or hex(sel)} on host class (forwarding unsupported)\n"); uc.reg_write(UC_ARM64_REG_X0, 0); return
    types = parse_sig(o.method_getTypeEncoding(m).decode())
    ret_t, arg_ts = types[0], types[3:]
    if super_call and is_guest(e, self_) and not _readable_obj_ok_for_host(o, cls):
        _skip_super(e, o, cls, self_, selname, ret_t); return
    rd, args, copyback = ArgReader(e), [], []
    crumb_note = []
    for t in arg_ts: args.append(rd.read(t))
    conv = []
    for i, (t, v) in enumerate(zip(arg_ts, args)):
        if t == ":": v = to_sel(e, v)
        elif t == "@?": v = make_block(e, v) if v and is_guest(e, v) else v
        elif t == "@" and v and is_guest(e, v): v = _guest_obj_arg(e, v, selname)
        elif t in ("^", "^@", "*") and v and is_guest(e, v):
            rule = SIZED.get(selname)
            hit = bool(rule) and (i in rule[0] if isinstance(rule[0], tuple) else rule[0] == i)
            n = rule[1](args) if hit else (8 if t == "^@" else GENERIC_PTR)
            n = max(8, min(int(n), 1 << 24))
            raw = bytearray(e.read(v, n))
            if hit and selname in OBJ_ARRAYS and t == "^@":      # id* arrays: guest strings -> host NSStrings
                for k in range(n // 8):
                    p = struct.unpack_from("<Q", raw, 8 * k)[0]
                    q = p
                    if p and is_guest(e, p) and read_isa_is_cf(e, p): q = to_nsstring(e, p)
                    elif (not p) or is_guest(e, p) or (not (p & 1) and p < 0x100000000):   # nil / guest object / junk -> NSNull
                        q = null_object(); crumb_note.append(f"{selname}[{k}]={p:#x} replaced by NSNull")
                    struct.pack_into("<Q", raw, 8 * k, q & M64)
            buf = ctypes.create_string_buffer(bytes(raw), n); copyback.append((v, buf, n)); v = ctypes.addressof(buf)
        conv.append(v)
    conv = spoof.fix_args(selname, arg_ts, conv)
    # Last line of defence: ANY object argument that is not a live host object (stale/garbage/guest-derived pointer) is replaced
    # by nil and reported, instead of letting the host dereference it (SIGSEGV kills the emulator; ctypes cannot catch that).
    conv = list(conv)
    for _i, (_t, _v) in enumerate(zip(arg_ts, conv)):
        if _t in ("@", "#") and _v and not is_tagged_ptr(_v) and not host_obj_ok(_v):
            _warn_arg(f"[objc] -[{selname}] arg{_i} {int(_v):#x} is not a valid host object (guest lr={uc.reg_read(UC_ARM64_REG_LR):#x}"
                      f"{', in guest memory' if is_guest(e, _v) else ''}{', known host id' if int(_v) in HOST_IDS else ''}) -> nil")
            conv[_i] = 0
    # Image sinks: NSImageCell throws (and kills the emulator) unless the value is a real NSImage INSTANCE. A guest that got a
    # Class object / nil-stand-in / non-image back from a mis-emulated call would pass exactly the "NSImage" *class* ("must be an
    # NSImage, not a \"NSImage\"").  Replace anything that is not an NSImage instance by nil and say where it came from.
    if selname in _IMAGE_SINKS:
        for _i, (_t, _v) in enumerate(zip(arg_ts, conv)):
            if _t == "@" and _v and not is_tagged_ptr(_v) and not _is_nsimage_instance(_v):
                _warn_arg(f"[objc] -[{selname}] arg{_i} {int(_v):#x} is not an NSImage instance "
                          f"({_describe_host_obj(_v)}; guest lr={uc.reg_read(UC_ARM64_REG_LR):#x}) -> nil")
                dump_ring(e, "non-NSImage passed to an image setter")
                conv[_i] = 0
    if _nil_key(selname, arg_ts, conv):
        _warn_arg(f"[objc] -[{selname}] called with a nil key (unresolved/guest key): returning nil without calling the host")
        write_ret(e, ret_t, 0); return
    if selname in SYNC_BEFORE: sync_to_host()
    # Cache CFUNCTYPE by layout so Structure class identity stays stable across calls.
    fkey = (_struct_key(ret_t), tuple(_struct_key(t) for t in arg_ts))
    fty = _FTY_CACHE.get(fkey)
    if fty is None:
        fty = ctypes.CFUNCTYPE(ctype_of(ret_t) if ret_t != "v" else None, c_void_p, c_void_p,
                               *[ctype_of(t) for t in arg_ts])
        _FTY_CACHE[fkey] = fty
    if os.environ.get("ARM2X86_CRUMB"):
        try: cn = o.class_getName; cn.restype, cn.argtypes = ctypes.c_char_p, [c_void_p]; cname = (cn(cls) or b"?").decode()
        except Exception: cname = "?"
        crumb(f"-[{cname} {selname}] self={self_:#x} sig={o.method_getTypeEncoding(m).decode()}\n  args=" +
              ", ".join(f"{t}:{(int(x) if isinstance(x, (int, type(None))) else repr(x)) if not isinstance(x, int) else hex(x)}" for t, x in zip(arg_ts, conv)) +
              ("\n  notes: " + "; ".join(crumb_note) if crumb_note else ""))
    try:
        r = fty(o.method_getImplementation(m))(self_, sel, *conv)
    except Exception as ex:
        sys.stderr.write(f"[objc] host -[{selname}] raised: {ex}\n")
        r = 0
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
        if int(rv) in _PROXY_REV: rv = _PROXY_REV[int(rv)]
        else: note_host(rv)
    write_ret(e, ret_t, rv)
    if selname == "sharedApplication" or selname == "sharedApplication":
        app = uc.reg_read(UC_ARM64_REG_X0)
        if app: _publish_nsapp(e, app)
    p = take_pending()
    if p: e.begin_callbacks(p, uc.reg_read(UC_ARM64_REG_X0))


# ---- guest NSWindowController subclasses (e.g. IASetupController): a real host controller behind the guest object ------------
# The guest object lives in the emulated heap, so the host's NSWindowController cannot be its super-object. Create a real host
# controller (a subclass that tolerates the nib's outlets to guest-only properties), load the installer's own nib into it and
# route inherited messages (window, showWindow:, ...) to it. Disable with ARM2X86_NO_WC_PROXY=1.
HOST_PROXY, _PROXY_REV, _WC = {}, {}, {}
_OUTLET_LOG = set()
def guest_ivars(e, cls):
    """{ivar name: byte offset} of a guest class (class_ro_t.ivars)."""
    if "ivars" in cls: return cls["ivars"]
    out = {}
    try:
        lp = _u64(e, cls["ro"] + 0x30) if cls.get("ro") else 0
        if lp and _mapped(e, lp, 8):
            ent, cnt = struct.unpack("<II", bytes(e.read(lp, 8))); ent = (ent & ~3) or 32
            for i in range(min(cnt, 512)):
                a = lp + 8 + i * ent
                offp, namep = struct.unpack("<QQ", bytes(e.read(a, 16)))
                if _mapped(e, offp, 4) and _mapped(e, namep, 1):
                    out[e.cstr(namep)] = struct.unpack("<I", bytes(e.read(offp, 4)))[0]
    except Exception: pass
    cls["ivars"] = out; return out
def set_guest_outlet(e, guest_self, key, value):
    """The nib set outlet `key` on its owner (the proxy). The real owner is the guest object: store the host view in its ivar."""
    c = CLASSES.get(_u64(e, guest_self))
    while c:
        iv = guest_ivars(e, c)
        for nm in ("_" + key, key):
            if nm in iv:
                e.write(guest_self + iv[nm], (value & M64).to_bytes(8, "little")); return c["name"], nm
        c = CLASSES.get(c["super"])
    return None
def _kvc_set(s, c, v, k):
    try:
        gs = _PROXY_REV.get(s); e = ST.emu
        if not (gs and k and e): return
        key = ctypes.string_at(hmsg(k, "UTF8String")).decode("utf8", "replace")
        if v: hmsg(v, "retain")
        hit = set_guest_outlet(e, gs, key, v or 0)
        if (key, bool(hit)) not in _OUTLET_LOG:
            _OUTLET_LOG.add((key, bool(hit)))
            sys.stderr.write(f"[objc] nib outlet '{key}' -> " + (f"{hit[0]}.{hit[1]}" if hit else "no matching ivar in the guest controller (ignored)") + "\n")
    except Exception as ex: sys.stderr.write(f"[objc] outlet bridge failed: {ex}\n")
def _kvc_get(s, c, k): return None
def _action_cb(s, cmd, sender):
    """A control in the host nib sent its action to the proxy: run the guest controller's method of that name."""
    try:
        gs = _PROXY_REV.get(s); e = ST.emu
        name = host()["objc"].sel_getName(cmd).decode()
        cls = CLASSES.get(_u64(e, gs)); imp = lookup(cls, name, False) if cls else None
        if imp:
            sys.stderr.write(f"[objc] action {name} -> guest -[{cls['name']} {name}] queued\n")
            with _LOCK: PENDING.append((imp, [gs, sel_guest(e, name), sender or 0]))
        else: sys.stderr.write(f"[objc] action {name} has no guest implementation\n")
    except Exception as ex: sys.stderr.write(f"[objc] action bridge failed: {ex}\n")
_ACT = {}
def bridge_actions(e, wc, guest_self):
    """Make the host proxy answer every one-argument selector the guest controller implements (button actions, delegates)."""
    o = host()["objc"]; cls = _wc_class(o)
    if "cb" not in _ACT:
        _ACT["cb"] = ctypes.CFUNCTYPE(None, c_void_p, c_void_p, c_void_p)(_action_cb); _KEEP.append(_ACT["cb"]); _ACT["done"] = set()
    g = CLASSES.get(_u64(e, guest_self)); n = 0
    while g:
        for name in g["methods"]:
            if name.count(":") != 1 or not name.endswith(":") or name in _ACT["done"]: continue
            _ACT["done"].add(name)
            if o.class_getInstanceMethod(cls, o.sel_registerName(name.encode())): continue   # the host already implements it
            if o.class_addMethod(cls, o.sel_registerName(name.encode()), ctypes.cast(_ACT["cb"], c_void_p), b"v@:@"): n += 1
        g = CLASSES.get(g["super"])
    if n: sys.stderr.write(f"[objc] bridged {n} guest action/delegate selector(s) onto the host window controller\n")
def _wc_class(o):
    if "cls" in _WC: return _WC["cls"]
    for f, r, a in (("objc_allocateClassPair", c_void_p, [c_void_p, ctypes.c_char_p, ctypes.c_size_t]),
                    ("class_addMethod", ctypes.c_bool, [c_void_p, c_void_p, c_void_p, ctypes.c_char_p]),
                    ("class_getInstanceMethod", c_void_p, [c_void_p, c_void_p]),
                    ("objc_registerClassPair", None, [c_void_p])):
        g = getattr(o, f); g.restype, g.argtypes = r, a
    base = o.objc_getClass(b"NSWindowController")
    cls = o.objc_allocateClassPair(base, b"ARM2X86WindowController", 0)
    if not cls: cls = o.objc_getClass(b"ARM2X86WindowController")
    else:
        setv = ctypes.CFUNCTYPE(None, c_void_p, c_void_p, c_void_p, c_void_p)(_kvc_set)
        getv = ctypes.CFUNCTYPE(c_void_p, c_void_p, c_void_p, c_void_p)(_kvc_get)
        _KEEP.extend([setv, getv])
        o.class_addMethod(cls, o.sel_registerName(b"setValue:forUndefinedKey:"), ctypes.cast(setv, c_void_p), b"v@:@@")
        o.class_addMethod(cls, o.sel_registerName(b"valueForUndefinedKey:"), ctypes.cast(getv, c_void_p), b"@@:@")
        o.objc_registerClassPair(cls)
    _WC["cls"] = cls; return cls
# ---- images of the installer ---------------------------------------------------------------------------------------------
# +[NSImage imageNamed:] (also used by every nib while it loads) searches the HOST's main bundle -- python -- so the installer's
# own images ('arrowbutton', 'moreInfo', 'OSBadge', ...) were "not found": no Continue arrow, no macOS badge.  Before the first
# nib loads, give every image of the installer's bundles (loose files AND Assets.car catalogs) its name in AppKit's named-image
# table with -[NSImage setName:], which is exactly what imageNamed: consults first.
_IMG_DONE = []
_IMG_EXT = (".png", ".pdf", ".tiff", ".tif", ".jpg", ".jpeg", ".icns", ".heic", ".gif")
def register_installer_images(e):
    if _IMG_DONE or not DARWIN: return
    _IMG_DONE.append(1)
    import json, subprocess
    parts = os.path.abspath(getattr(e, "path", "") or "").split(os.sep)
    if "Contents" not in parts: return
    app = os.sep.join(parts[:parts.index("Contents")])
    h = host()["objc"]; NSImage = h.objc_getClass(b"NSImage"); NSBundle = h.objc_getClass(b"NSBundle")
    bundles, loose = [], []
    for root, dirs, files in os.walk(app):
        if root.endswith((".bundle", ".framework", ".app")) or root == app: bundles.append(root)
        for f in files:
            if f.lower().endswith(_IMG_EXT) and "/Resources/" in root + "/": loose.append(os.path.join(root, f))
    named, seen = 0, set()
    def reg(img, nm):
        nonlocal named
        if img and nm not in seen:
            seen.add(nm)
            if hmsg(img, "setName:", _new_host_string(nm), restype=ctypes.c_ubyte): named += 1
    for path in sorted(loose, key=lambda q: (0 if ("Base.lproj" in q or "en.lproj" in q or ".lproj" not in q) else 1, len(q))):
        nm = re.sub(r"(@[23]x)?(~\w+)?$", "", os.path.splitext(os.path.basename(path))[0])
        if nm in seen: continue
        try: reg(hmsg(hmsg(NSImage, "alloc"), "initWithContentsOfFile:", _new_host_string(path)), nm)
        except Exception as ex: _warn_arg(f"[objc] image {path}: {ex}")
    cars = 0
    for b in bundles:
        car = os.path.join(b, "Contents", "Resources", "Assets.car")
        if not os.path.isfile(car): car = os.path.join(b, "Resources", "Assets.car")
        if not os.path.isfile(car): continue
        try:
            j = json.loads(subprocess.check_output(["/usr/bin/assetutil", "-I", car], timeout=60))
            names = sorted({d["Name"] for d in j if isinstance(d, dict) and d.get("Name") and d.get("AssetType") in ("Image", "Icon Image", "PDF", "Vector")})
        except Exception as ex:
            _warn_arg(f"[objc] assetutil {car}: {ex}"); continue
        bund = hmsg(NSBundle, "bundleWithPath:", _new_host_string(b))
        for nm in names[:800]:
            if nm in seen: continue
            try: reg(hmsg(bund, "imageForResource:", _new_host_string(nm)), nm); cars += 1
            except Exception: pass
    sys.stderr.write(f"[objc] installer images registered by name: {named} ({len(loose)} loose files, {cars} from asset catalogs)\n")
    sys.stderr.write("[objc] image names: " + ", ".join(sorted(seen)) + "\n")

_GB = []
def _guest_class_bundle(e):
    """host NSBundle for the installer's plug-in (IA.bundle) -- or the .app -- standing in for the bundle of a guest class"""
    if _GB: return _GB[0]
    parts = os.path.abspath(getattr(e, "path", "") or "").split(os.sep)
    if "Contents" not in parts: return 0
    app = os.sep.join(parts[:parts.index("Contents")]); path = app
    plug = os.path.join(app, "Contents", "PlugIns")
    if os.path.isdir(plug):
        for n in sorted(os.listdir(plug)):
            if n.endswith(".bundle") and os.path.isdir(os.path.join(plug, n, "Contents", "MacOS")): path = os.path.join(plug, n); break
    b = hmsg(host()["objc"].objc_getClass(b"NSBundle"), "bundleWithPath:", _new_host_string(path))
    if b: note_host(b); _GB.append(b); sys.stderr.write(f"[objc] +[NSBundle bundleForClass:] of a guest class -> {path}\n")
    return b or 0
def make_window_controller_proxy(e, guest_self, nib_arg):
    if os.environ.get("ARM2X86_NO_WC_PROXY") == "1" or not DARWIN: return 0
    o = host()["objc"]
    try: register_installer_images(e)
    except Exception as ex: sys.stderr.write(f"[objc] image registration failed: {ex}\n")
    try:
        name = _guest_obj_arg(e, nib_arg, "initWithWindowNibName:") if nib_arg else 0
        nm = ctypes.string_at(hmsg(name, "UTF8String")).decode("utf8", "replace") if name else ""
        found = _find_nib(e, nm) if nm else None
        sys.stderr.write(f"[objc] window controller nib '{nm}': {found or 'NOT FOUND in the installer app'}\n")
        path = _new_host_string(found) if found else 0
        wc = hmsg(_wc_class(o), "alloc")                      # owner = the controller itself (File's Owner -> window outlet)
        wc = hmsg(wc, "initWithWindowNibPath:owner:", path, wc) if path else hmsg(wc, "init")
        if not wc: return 0
        HOST_PROXY[guest_self] = wc; _PROXY_REV[wc] = guest_self; note_host(wc)
        bridge_actions(e, wc, guest_self)
        sys.stderr.write(f"[objc] host NSWindowController proxy {wc:#x} for guest object {guest_self:#x}"
                         f" (nib {'found' if path else 'NOT found'})\n")
        return wc
    except Exception as ex:
        sys.stderr.write(f"[objc] window controller proxy failed: {ex}\n"); return 0

# ---- unresolved DATA imports --------------------------------------------------------------------------------------------
# An import nobody implements becomes a 16-byte stub (4 bytes of `ret`). Code that CALLS it is handled by the stub hook; code
# that READS it as a variable (an extern NSString* constant, e.g. 0xd65f03c0 became the "key" passed to -[NSUserDefaults
# objectForKey:]) used to get the bytes of the `ret` instruction. Catch the first data read of such a stub, and turn that
# stub into a pointer to a real string named after the symbol.
_DATA_PATCHED = set()
_SYMSTR = {}      # guest placeholder string standing in for an extern constant -> symbol name (resolved from the host when used)
def install_stub_data_hook(e):
    from unicorn import UC_HOOK_MEM_READ
    def on_read(uc, access, address, size, value, _):
        try:
            name = stub_symbol(e, address)
            if name is None or name in FUNCS or "$" in name or name in _DATA_PATCHED: return
            _DATA_PATCHED.add(name)
            txt = name.lstrip("_").encode() or b"?"
            sptr = e.malloc(len(txt) + 1); e.write(sptr, txt + b"\0")
            cfs = e.malloc(32); e.write(cfs, struct.pack("<QQQQ", guest_cell(e), 0x7c8, sptr, len(txt)))
            _SYMSTR[cfs] = name.lstrip("_")
            base = address - ((address - _STUB_BASE) % _STUB_STRIDE)
            e.write(base, struct.pack("<Q", cfs))
            sys.stderr.write(f"[resolve] guest READ {name} as data (pc={uc.reg_read(UC_ARM64_REG_PC):#x} "
                             f"lr={uc.reg_read(UC_ARM64_REG_LR):#x}): bound to the string \"{txt.decode(errors='replace')}\"\n")
        except Exception as ex:
            sys.stderr.write(f"[resolve] data-read hook failed: {ex}\n")
    e.uc.hook_add(UC_HOOK_MEM_READ, on_read, begin=_STUB_BASE, end=_STUB_BASE + _STUB_SIZE)

def _find_nib(e, name):
    """<name>.nib anywhere inside the installer .app (the controller's nib lives in a plug-in bundle, not the main one)"""
    parts = os.path.abspath(getattr(e, "path", "") or "").split(os.sep)
    if "Contents" not in parts: return None
    app = os.sep.join(parts[:parts.index("Contents")]); hits = []
    for root, dirs, files in os.walk(app):
        for n in dirs + files:
            if n in (name + ".nib",): hits.append(os.path.join(root, n))
    hits.sort(key=lambda p: (0 if ("Base.lproj" in p or "en.lproj" in p or "English.lproj" in p) else 1, len(p)))
    return hits[0] if hits else None
def _show_proxies(e):
    if not HOST_PROXY: return
    for gs, wc in list(HOST_PROXY.items()):
        try:
            sys.stderr.write(f"[objc] loading window of proxy {wc:#x} ...\n"); w = hmsg(wc, "window")
            sys.stderr.write(f"[objc] proxy window = {w:#x}\n" if w else "[objc] proxy has no window (nib missing or has no window)\n")
            if w:
                hmsg(wc, "showWindow:", 0); hmsg(w, "makeKeyAndOrderFront:", 0)
                sys.stderr.write("[objc] proxy window ordered front\n")
        except Exception as ex:
            sys.stderr.write(f"[objc] showing proxy window failed: {ex}\n")

# ---- super calls from guest-defined classes into REAL host classes -------------------------------------------------------
# The guest object lives in the emulated heap (0x4_xxxx_xxxx), so a host method that reads its own ivars through `self`
# (NSViewController, NSWindowController, NSView ... -init*) dereferences an address that does not exist in the host process.
# NSObject's methods never touch memory, so those are allowed. For everything else: skip the call, say which class/selector
# it was (so the proper fix -- a real host instance behind the guest object -- can be targeted) and answer "self"/0.
_SKIPPED = set()
def _cls_name(o, cls):
    try:
        cn = o.class_getName; cn.restype, cn.argtypes = ctypes.c_char_p, [c_void_p]
        return (cn(cls) or b"?").decode()
    except Exception: return "?"
def _readable_obj_ok_for_host(o, cls):
    return _cls_name(o, cls) == "NSObject"
def _skip_super(e, o, cls, self_, selname, ret_t):
    key = (_cls_name(o, cls), selname)
    if key[0] == "NSWindowController" and selname.startswith("initWithWindow") and self_ not in HOST_PROXY:
        if make_window_controller_proxy(e, self_, e.arg(2)): write_ret(e, "@", self_); return
    if key not in _SKIPPED:
        _SKIPPED.add(key)
        sys.stderr.write(f"[objc] super call [{key[0]} {selname}] on guest-heap object {self_:#x} skipped: the host class would "
                         f"dereference a non-host pointer (guest lr={e.uc.reg_read(UC_ARM64_REG_LR):#x})\n")
    if ret_t != "v": write_ret(e, ret_t, self_ if ret_t == "@" else 0)

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
_STUB_BASE, _STUB_SIZE, _STUB_STRIDE = 0x300000000, 0x100000, 16     # = loader.STUB_*  (not imported: loader runs as __main__)
def stub_symbol(e, a):
    """Name of the unresolved import whose stub lives at address `a` (None if `a` is not a stub)."""
    try:
        if _STUB_BASE <= a < _STUB_BASE + _STUB_SIZE:
            i = (a - _STUB_BASE) // _STUB_STRIDE
            if i < len(e.stub_names): return e.stub_names[i]
    except Exception:
        pass
    return None
_WARNED = set()
_DEPS_DONE = [False]
_MISSING_DEPS = []
def load_host_dependencies(e):
    """dlopen, on the HOST, every system framework/library the guest main binary and its guest-loaded bundles link against.
    (The host Python process only has what Python itself linked, so private frameworks' classes are 'missing' until loaded.)
    Returns True if anything new was loaded."""
    if _DEPS_DONE[0] or not DARWIN: return False
    _DEPS_DONE[0] = True
    import dylib as _d
    paths = [e.path] + list(getattr(_d, "_LOADED", {}))
    names, seen = [], set()
    for p in paths:
        try:
            data = _d.arm64_slice(open(p, "rb").read())
            if data: names += _d.Image(data, p).deps
        except Exception:
            continue
    n_ok = 0
    for nm in names:
        if nm in seen or nm.startswith(("/usr/lib/libSystem", "/usr/lib/libobjc", "/usr/lib/libc++")): continue
        seen.add(nm); cands = []
        if nm.startswith("/"): cands.append(nm)
        elif nm.startswith("@rpath/") and ".framework/" in nm:
            tail = nm[len("@rpath/"):]
            cands += ["/System/Library/PrivateFrameworks/" + tail, "/System/Library/Frameworks/" + tail,
                      "/System/Library/PrivateFrameworks/" + tail.split(".framework/")[0] + ".framework/" + tail.split("/")[-1]]
        _ok_before = n_ok
        for c in cands:
            try:
                ctypes.CDLL(c, mode=ctypes.RTLD_GLOBAL); n_ok += 1
                if os.environ.get("ARM2X86_VERBOSE"): sys.stderr.write(f"[objc] host loaded {c}\n")
                break
            except OSError:
                continue
        if n_ok == _ok_before: _MISSING_DEPS.append(nm)
    sys.stderr.write(f"[objc] host-loaded {n_ok} of {len(seen)} framework dependencies of the guest\n")
    if _MISSING_DEPS: sys.stderr.write("[objc] NOT loadable on the host: " + ", ".join(_MISSING_DEPS) + "\n")
    return n_ok > 0
# ---- arm64 frameworks that ship INSIDE the installer app ---------------------------------------------------------------------
# OSISClient / IADiskManager / OSISSharedUtilities ... are not host classes: they live in arm64 frameworks bundled in the .app
# (Contents/Frameworks, PlugIns/*/Contents/Frameworks, SharedFrameworks). The host cannot dlopen arm64 code, so map them into the
# GUEST like IA.bundle, then re-check the guest class table.
_GFW = {"done": False}
def load_guest_frameworks(e):
    if _GFW["done"] or os.environ.get("ARM2X86_NO_GUEST_FW"): return False
    _GFW["done"] = True
    parts = os.path.abspath(getattr(e, "path", "") or "").split(os.sep)
    if "Contents" not in parts: return False
    app = os.sep.join(parts[:parts.index("Contents")])
    import dylib as _d
    found = []
    for root, dirs, files in os.walk(app):
        if root.endswith(".framework") and os.path.isdir(os.path.join(root, "Versions")):
            dirs[:] = []                                          # only the framework's own binary
            nm = os.path.basename(root)[:-len(".framework")]
            for cand in (os.path.join(root, "Versions", "A", nm), os.path.join(root, nm), os.path.join(root, "Versions", "Current", nm)):
                if os.path.isfile(cand): found.append(cand); break
        elif root.endswith(".framework"):
            nm = os.path.basename(root)[:-len(".framework")]; c = os.path.join(root, nm)
            if os.path.isfile(c): found.append(c)
    n = 0
    for path in found:
        try:
            if _d.is_arm64_macho(path) and _d.load_path(e, path): n += 1
        except Exception as ex:
            sys.stderr.write(f"[objc] guest framework {path}: {ex}\n")
    sys.stderr.write(f"[objc] guest-loaded {n} of {len(found)} frameworks bundled in the installer: "
                     f"{', '.join(os.path.basename(x) for x in found)}\n")
    return n > 0
def unresolved_class(e, cls):
    """`cls` is the address of a stub standing in for a class the host runtime doesn't have (its framework isn't loaded,
    or it is private to the app). Returns (host_class_or_0, printable_name); NEVER hand such an address to the host runtime:
    objc_alloc/objc_msgSend on it is a SIGSEGV that kills the whole emulator."""
    nm = stub_symbol(e, cls)
    short = nm.split("$_", 1)[-1] if nm and nm.startswith(("_OBJC_CLASS_$_", "_OBJC_METACLASS_$_")) else nm
    real = 0
    if DARWIN and short and nm and nm.startswith("_OBJC_CLASS_$_"):
        real = host()["objc"].objc_getClass(short.encode()) or 0
        if not real and load_host_dependencies(e):                       # frameworks the guest links but the host never loaded
            real = host()["objc"].objc_getClass(short.encode()) or 0
        if real: e._resolved[nm] = real
        if not real:                                                       # a class of an arm64 framework bundled in the app?
            try: load_guest_frameworks(e)
            except Exception as ex: sys.stderr.write(f"[objc] load_guest_frameworks: {ex}\n")
            g = BY_NAME.get(short)
            if g: sys.stderr.write(f"[objc] class {short} resolved from a guest-loaded framework\n"); return g, short
    if not real and short not in _WARNED:
        _WARNED.add(short)
        sys.stderr.write(f"[objc] class {short or hex(cls)} is not available (not in the guest, not loaded on the host): "
                         f"treating it as nil\n")
    return real, short or hex(cls)

_HC, _HC_N = set(), [-1]
def host_class_ok(cls):
    """True only if `cls` is a class the HOST runtime really has (membership in objc_getClassList: safe for any value).
    Anything else handed to objc_alloc/objc_msgSend is a SIGSEGV inside libobjc that kills the emulator."""
    if cls in _HC: return True
    o = host()["objc"]
    o.objc_getClassList.restype, o.objc_getClassList.argtypes = ctypes.c_int, [c_void_p, ctypes.c_int]
    n = o.objc_getClassList(None, 0)
    if n != _HC_N[0]:
        buf = (c_void_p * n)(); o.objc_getClassList(buf, n)
        _HC.update(int(x) for x in buf if x); _HC_N[0] = n
    return cls in _HC

def _alloc(e, init):
    cls = e.arg(0)
    if cls not in CLASSES and cls and (stub_symbol(e, cls) is not None):
        real, _ = unresolved_class(e, cls)
        if not real:
            return 0                                   # nil: every later message to it is a harmless no-op
        cls = real
    if cls in CLASSES:
        p = alloc_instance(e, CLASSES[cls])
        if init:                                       # objc_alloc_init == [[cls alloc] init]; plain objc_alloc must NOT init
            imp = lookup(CLASSES[cls], "init", False)
            if imp:
                e.uc.reg_write(UC_ARM64_REG_X0, p)
                e.uc.reg_write(UC_ARM64_REG_X1, sel_guest(e, "init"))
                e.tail_into(imp)
                return None
        return p
    if not DARWIN or not cls: return 0
    if is_guest(e, cls):                               # some other guest address: not a class the host knows
        sys.stderr.write(f"[objc] objc_alloc on unknown guest address {cls:#x}: returning nil\n"); return 0
    if not host_class_ok(cls):
        near = ", ".join(f"{c['name']}@{a:#x}" for a, c in list(CLASSES.items())[:6])
        sys.stderr.write(f"[objc] objc_alloc{'_init' if init else ''}({cls:#x}): not a class on the host and not a guest class -> nil\n"
                         f"       caller lr={e.uc.reg_read(UC_ARM64_REG_LR):#x}  recent calls: {getattr(e, 'last_stubs', [])}\n"
                         f"       guest classes: {near}\n")
        return 0
    o = host()["objc"]
    name = "objc_alloc_init" if init else "objc_alloc"
    f = getattr(o, name, None) or getattr(o, "objc_alloc", None)
    if not f: return 0
    f.restype, f.argtypes = c_void_p, [c_void_p]
    return f(cls) or 0
fn("objc_alloc", "objc_allocWithZone")(lambda e: _alloc(e, False))
fn("objc_alloc_init", "objc_opt_new")(lambda e: _alloc(e, True))      # objc_opt_new(cls) == [cls new] == [[cls alloc] init]
fn("objc_opt_self")(lambda e: e.arg(0))
def _opt_send(selname):
    """objc_opt_isKindOfClass(obj, cls) / objc_opt_respondsToSelector(obj, sel): same as the message, with the selector inserted."""
    def f(e):
        uc = e.uc
        uc.reg_write(UC_ARM64_REG_X2, e.arg(1)); uc.reg_write(UC_ARM64_REG_X1, sel_guest(e, selname))
        msg_send(e)
    return f
fn("objc_opt_isKindOfClass")(_opt_send("isKindOfClass:"))
fn("objc_opt_respondsToSelector")(_opt_send("respondsToSelector:"))
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
def _opt_class(e):                                    # [obj class]: an instance -> its class; a class object -> itself
    v = e.arg(0)
    if not v: return 0
    if v in CLASSES: return v if not CLASSES[v]["is_meta"] else CLASSES[v]["isa"] or v
    if DARWIN and not is_guest(e, v) and not is_tagged_ptr(v) and host_class_ok(v): return v
    return _ogc(e)
fn("objc_opt_class")(_opt_class)
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
    v = e.arg(0)
    if not v or is_guest(e, v): return v
    if not host_obj_ok(v): warn_bad("objc_retain", v); return v
    return host()["objc"].objc_retain(v)
# Host objects are never really released on behalf of the guest. The guest's ARC code releases references it never retained through
# us (nib outlets written straight into its ivars, +0 results of host calls ...): the host then deallocs a live view and AppKit
# throws "<NSTextField> has reached dealloc but still has a super view" (crash right after pressing Continue).  Leaking a few
# views is harmless here.  ARM2X86_REAL_RELEASE=1 restores the old behaviour.
_REAL_RELEASE = os.environ.get("ARM2X86_REAL_RELEASE") == "1"
@fn("objc_release")
def _rel(e):
    v = e.arg(0)
    if v and not is_guest(e, v) and _REAL_RELEASE:
        if host_obj_ok(v): host()["objc"].objc_release(v)
        else: warn_bad("objc_release", v)
@fn("objc_autorelease", "objc_autoreleaseReturnValue", "objc_unsafeClaimAutoreleasedReturnValue")
def _ar(e): return e.arg(0)
@fn("objc_storeStrong")
def _ss(e):
    addr, new = e.arg(0), e.arg(1); old = int.from_bytes(e.read(addr, 8), "little")
    if new and not is_guest(e, new):
        if host_obj_ok(new): host()["objc"].objc_retain(new)
        else: warn_bad("objc_storeStrong(new)", new)
    e.write(addr, new.to_bytes(8, "little"))
    if old and not is_guest(e, old) and _REAL_RELEASE:
        if host_obj_ok(old): host()["objc"].objc_release(old)
        else: warn_bad("objc_storeStrong(old)", old)
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
    msg = "".join(out); sys.stderr.write(msg + "\n")
    if msg.startswith(("Cannot ", "No NSPrincipalClass")): dump_ring(e, msg)

# ---------------------------------------------- strings, class lookup, variadic formatting ----
def py_str(e, v):
    """Text of a guest CFString constant, a host NSString (or any host object's -description), or a guest instance."""
    if not v: return None
    try:
        if is_guest(e, v):
            if read_isa_is_cf(e, v):
                ptr, n = struct.unpack("<QQ", bytes(e.read(v + 16, 16)))
                return bytes(e.read(ptr, n)).decode("utf-8", "replace")
            cls = CLASSES.get(_u64(e, v))
            return "<%s: %#x>" % (cls["name"], v) if cls else None
        if not DARWIN or not host_ok(e, v): return None
        d = hmsg(v, "description"); p = hmsg(d, "UTF8String") if d else 0
        return ctypes.string_at(p).decode("utf-8", "replace") if p else None
    except Exception:
        return None

def _new_host_string(text):
    return hmsg(host()["objc"].objc_getClass(b"NSString"), "stringWithUTF8String:", text.encode("utf-8", "replace") + b"\0",
                argtypes=[ctypes.c_char_p])

_OBJC_FMT = re.compile(r"%([-+ #0]*)(\d+|\*)?(?:\.(\d+|\*))?(hh|h|ll|l|z|j|t|L|q)?([diouxXeEfFgGcCsSp@%])")
def objc_format(e, fmt, sp):
    """printf-style formatting of an ObjC format string; variadic args live on the guest stack at `sp` (Darwin arm64)."""
    slot = [0]
    def ni():
        v = int.from_bytes(e.read(sp + 8 * slot[0], 8), "little"); slot[0] += 1; return v
    out, pos = [], 0
    for m in _OBJC_FMT.finditer(fmt):
        out.append(fmt[pos:m.start()]); pos = m.end()
        flags, width, prec, length, conv = m.groups()
        if conv == "%": out.append("%"); continue
        if width == "*": width = str(hle.s32(ni()))
        if prec == "*": prec = str(hle.s32(ni()))
        spec = "%" + flags + (width or "") + ("." + prec if prec else "")
        wide = length in ("l", "ll", "z", "j", "t", "q")
        if conv == "@":
            t = py_str(e, ni()); out.append((spec + "s") % ("(null)" if t is None else t))
        elif conv in "di":
            v = ni(); out.append((spec + "d") % (hle.s64(v) if wide else hle.s32(v)))
        elif conv in "ouxX":
            v = ni() & (M64 if wide else 0xffffffff); out.append((spec + ("d" if conv == "u" else conv)) % v)
        elif conv in "eEfFgG":
            out.append((spec + conv) % struct.unpack("<d", struct.pack("<Q", ni()))[0])
        elif conv in "cC": out.append((spec + "s") % chr(ni() & 0xffff))
        elif conv == "s":
            p = ni(); out.append((spec + "s") % ("(null)" if not p else e.cstr(p)))
        elif conv == "S": ni(); out.append("?")
        elif conv == "p": out.append("0x%x" % ni())
    out.append(fmt[pos:])
    return "".join(out)

# Foundation functions that take/return ObjC strings: the generic cocoa._bind() passed GUEST CFString addresses straight to the
# host, which then read garbage (it returned a host heap pointer that was not a class).
@fn("NSClassFromString")
def _ncfs(e):
    name = py_str(e, e.arg(0))
    if not name: return 0
    g = BY_NAME.get(name)
    if g: return g
    if not DARWIN: return 0
    c = host()["objc"].objc_getClass(name.encode()) or 0
    if not c and load_host_dependencies(e): c = host()["objc"].objc_getClass(name.encode()) or 0
    if not c:
        sys.stderr.write(f"[objc] NSClassFromString({name!r}) -> nil: not a guest class ({len(BY_NAME)} known: "
                         f"{sorted(BY_NAME)[:12]}) and not a host class\n")
    return c
@fn("NSStringFromClass")
def _nsfc(e):
    c = e.arg(0)
    if not c: return 0
    if c in CLASSES: return _new_host_string(CLASSES[c]["name"]) if DARWIN else 0
    if not DARWIN or not host_class_ok(c): return 0
    n = host()["objc"].class_getName; n.restype, n.argtypes = ctypes.c_char_p, [c_void_p]
    return _new_host_string((n(c) or b"").decode())
@fn("NSSelectorFromString")
def _nssfs(e):
    name = py_str(e, e.arg(0))
    return sel_guest(e, name) if name else 0
@fn("NSProtocolFromString")
def _nspfs(e):
    name = py_str(e, e.arg(0))
    if not name or not DARWIN: return 0
    f = host()["objc"].objc_getProtocol; f.restype, f.argtypes = c_void_p, [ctypes.c_char_p]
    return f(name.encode()) or 0

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
                                 isa=isa, methods={}, is_meta=bool(flags & 1), did_init=False, ro=ro)
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
    if not p: return False
    if is_tagged_ptr(p): return True
    if p < 0x100000000 or p >= 0xffff000000000000: return False
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
        if c["name"] in ("IAAppController", "AppDelegate", "GameDelegate", "ApplicationDelegate"):
            return addr
        if c["name"].endswith("AppController") or c["name"].endswith("AppDelegate"):
            best = addr
        if "applicationDidFinishLaunching:" in c["methods"] or lookup(c, "applicationDidFinishLaunching:", False):
            if "Delegate" in c["name"] or "Controller" in c["name"]: return addr
            best = best or addr
    return best

# ------------------------------------------------------- symbol resolution ----
_GUEST_CONST_RE = re.compile(r"^_[A-Za-z]\w*(Key|Keys|Notification|Identifier|Name|Mode|Domain|Options?|Path|Kind|Prefix|Suffix|Extension|Format)$|^_k[A-Z]\w+$")
_NOT_CONST_RE = re.compile(r"(Get|Copy|Create|Set|From|With|Is[A-Z]|Register|Add|Remove|Release|Retain|Make|Compare|Equal|Start|Stop|Run|Load|Check|Update|Post|Send|ID$|Ref$|Callback|Class)")
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
    if name not in FUNCS and _GUEST_CONST_RE.match(name) and not _NOT_CONST_RE.search(name) and "$" not in name:
        # An extern NSString* constant from a framework nobody could load (OSInstall & co). It used to become a stub whose
        # first 4 bytes are `ret`, so the guest read 0xd65f03c0 as the string pointer (-> NSUserDefaults crash). Bind a real
        # guest string whose text is the symbol name -- what most Apple string constants are anyway.
        if DARWIN:
            for lib in [host()["sys"]] + host()["libs"]:
                try:
                    v = c_void_p.in_dll(lib, name[1:]).value
                    if v: return _cell(e, name, v)
                except (ValueError, AttributeError, OSError): continue
        txt = name[1:].encode()
        sptr = e.malloc(len(txt) + 1); e.write(sptr, txt + b"\0")
        cfs = e.malloc(32); e.write(cfs, struct.pack("<QQQQ", guest_cell(e), 0x7c8, sptr, len(txt)))
        sys.stderr.write(f"[resolve] unresolved constant {name}: bound to the string \"{name[1:]}\"\n")
        return _cell(e, name, cfs)
    return None
RESOLVERS.append(resolver)
