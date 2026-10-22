"""
Extra libSystem / libc++ / CoreGraphics emulation found missing by real apps
(Mazkey, osu!, Godot, PowerPoint). Registered only if nothing else already provides the name.
"""
import os, sys, struct, math, ctypes
from unicorn.arm64_const import *
from hle import FUNCS, M64, s32, format_c

def fn(*names):
    def deco(f):
        for n in names: FUNCS.setdefault("_" + n, f)
        return f
    return deco

# ---- stack probe: must PRESERVE every register (the generic "unimplemented -> 0" stub clobbered x0)
@fn("__chkstk_darwin")
def _chkstk(e): return None

# ---- function-local statics: acquire returns 1 when the initialiser still has to run
@fn("__cxa_guard_acquire")
def _guard_acq(e): return 1 if e.read(e.arg(0), 1)[0] == 0 else 0
@fn("__cxa_guard_release")
def _guard_rel(e): e.write(e.arg(0), b"\x01"); return None
@fn("__cxa_guard_abort")
def _guard_abort(e): return None

# ---- single-threaded: locks are no-ops
for _suffix in ("C1Ev", "C2Ev", "D1Ev", "D2Ev", "4lockEv", "6unlockEv"):
    FUNCS.setdefault("__ZNSt3__115recursive_mutex" + _suffix, lambda e: None)
FUNCS.setdefault("__ZNSt3__115recursive_mutex8try_lockEv", lambda e: 1)

# ---- sincos
def _setd(e, i, v): e.uc.reg_write(UC_ARM64_REG_D0 + i, struct.unpack("<Q", struct.pack("<d", v))[0])
@fn("__sincos_stret")
def _sincos(e):
    x = e.darg(0); _setd(e, 0, math.sin(x)); _setd(e, 1, math.cos(x)); return None
@fn("__sincosf_stret")
def _sincosf(e):
    x = struct.unpack("<f", struct.pack("<I", e.uc.reg_read(UC_ARM64_REG_D0) & 0xffffffff))[0]
    f = lambda v: struct.unpack("<I", struct.pack("<f", v))[0]
    e.uc.reg_write(UC_ARM64_REG_D0, f(math.sin(x))); e.uc.reg_write(UC_ARM64_REG_D0 + 1, f(math.cos(x))); return None

# ---- v*printf: on Darwin arm64 a va_list is just a pointer to 8-byte stack slots
def _vfmt(e, fmt_ptr, ap):
    st = {"p": ap}
    def ni():
        v = int.from_bytes(e.read(st["p"], 8), "little"); st["p"] += 8; return v
    def nd(): return struct.unpack("<d", struct.pack("<Q", ni()))[0]
    return format_c(e, e.cstr(fmt_ptr), ni, nd).encode("latin-1", "replace")
@fn("vsnprintf")                    # (buf, n, fmt, ap)
def _vsnprintf(e):
    b = _vfmt(e, e.arg(2), e.arg(3)); n = e.arg(1)
    if n: e.write(e.arg(0), b[: n - 1] + b"\0")
    return len(b)
@fn("__vsnprintf_chk")              # (buf, n, flags, slen, fmt, ap)
def _vsnprintf_chk(e):
    b = _vfmt(e, e.arg(4), e.arg(5)); n = e.arg(1)
    if n: e.write(e.arg(0), b[: n - 1] + b"\0")
    return len(b)
@fn("vsprintf")
def _vsprintf(e):
    b = _vfmt(e, e.arg(1), e.arg(2)); e.write(e.arg(0), b + b"\0"); return len(b)
@fn("vprintf")
def _vprintf(e):
    b = _vfmt(e, e.arg(0), e.arg(1)); os.write(1, b); return len(b)
@fn("vfprintf")
def _vfprintf(e):
    from hle import fd_of
    b = _vfmt(e, e.arg(1), e.arg(2)); os.write(fd_of(e.arg(0)), b); return len(b)

@fn("realpath$DARWIN_EXTSN", "realpath")
def _realpath(e):
    p = os.path.realpath(e.cstr(e.arg(0)))
    if e.arg(1):
        e.write(e.arg(1), p.encode() + b"\0"); return e.arg(1)
    return e.alloc_cstr(p)

# ---- thread-local variables (Mach-O __thread_vars descriptors: {thunk, key, offset})
@fn("tlv_bootstrap")
def _tlv_bootstrap(e):
    blk = getattr(e, "_tlv_block", None)
    if blk is None:
        secs = [s for s in e.mo.sections if s["sect"] in ("__thread_data", "__thread_bss")]
        if secs:
            lo = min(s["addr"] for s in secs); hi = max(s["addr"] + s["size"] for s in secs)
            data = bytearray(hi - lo)
            for s in secs:
                if s["sect"] == "__thread_data":
                    data[s["addr"] - lo: s["addr"] - lo + s["size"]] = bytes(e.read(s["addr"], s["size"]))
        else:
            data = bytearray(0x1000)
        p = e.malloc(len(data) + 64); e.write(p, bytes(data)); blk = e._tlv_block = p
    off = int.from_bytes(e.read(e.arg(0) + 16, 8), "little")
    return blk + off

# ---- CoreGraphics / CoreFoundation bits forwarded to the host (Mac only)
def _host(fw):
    try: return ctypes.CDLL(f"/System/Library/Frameworks/{fw}.framework/{fw}")
    except OSError: return None
@fn("CGGetOnlineDisplayList", "CGGetActiveDisplayList")
def _cgdl(e):
    main = 1
    cg = _host("CoreGraphics")
    if cg:
        cg.CGMainDisplayID.restype = ctypes.c_uint32; main = cg.CGMainDisplayID()
    if e.arg(1) and e.arg(0): e.write(e.arg(1), struct.pack("<I", main))
    if e.arg(2): e.write(e.arg(2), struct.pack("<I", 1))
    return 0
@fn("CGDisplayIsMain")
def _cgmain(e):
    cg = _host("CoreGraphics")
    if not cg: return 1
    cg.CGMainDisplayID.restype = ctypes.c_uint32
    return int(e.arg(0) & 0xffffffff == cg.CGMainDisplayID())
@fn("CGDisplayMirrorsDisplay")
def _cgmir(e): return 0
@fn("CFURLCopyFileSystemPath")
def _cfurlpath(e):
    cf = _host("CoreFoundation")
    if not cf or not e.arg(0): return 0
    try: e.uc.mem_read(e.arg(0), 1); return 0          # points into GUEST memory -> not a host CFURL
    except Exception: pass
    cf.CFURLCopyFileSystemPath.restype = ctypes.c_void_p
    cf.CFURLCopyFileSystemPath.argtypes = [ctypes.c_void_p, ctypes.c_long]
    return cf.CFURLCopyFileSystemPath(e.arg(0), s32(e.arg(1))) or 0


# ======================= round 3: errno, ctype, stdio files, libc++ strings, float math =======================
from hle import FILE_BASE, fd_of, set_errno
from libcxx import str_get, str_set
M32 = 0xffffffff

# NB: hle registers "___error" via fn("___error") -> "____error" (extra underscore), so it never matched.
@fn("__error")
def _errno_loc(e): return e.errno_addr
@fn("__stack_chk_fail")
def _scf(e): sys.stderr.write("*** stack smashing detected ***\n"); e.exit(134)
@fn("__toupper")
def _toupper(e): c = e.arg(0) & 0xff; return c - 32 if 97 <= c <= 122 else c
@fn("__tolower")
def _tolower(e): c = e.arg(0) & 0xff; return c + 32 if 65 <= c <= 90 else c

# ---- stdio on real files (FILE* = FILE_BASE + host fd, same trick hle uses for stdout/stderr)
_EOF = set()
@fn("fopen$DARWIN_EXTSN", "fopen")
def _fopen(e):
    path, mode = e.cstr(e.arg(0)), e.cstr(e.arg(1))
    plus = "+" in mode
    if mode[:1] == "r": fl = os.O_RDWR if plus else os.O_RDONLY
    elif mode[:1] == "w": fl = (os.O_RDWR if plus else os.O_WRONLY) | os.O_CREAT | os.O_TRUNC
    else: fl = (os.O_RDWR if plus else os.O_WRONLY) | os.O_CREAT | os.O_APPEND
    try: fd = os.open(path, fl, 0o666)
    except OSError as ex: set_errno(e, ex.errno); return 0
    return FILE_BASE + fd
@fn("fclose")
def _fclose(e):
    fd = fd_of(e.arg(0))
    if fd > 2:
        try: os.close(fd)
        except OSError: pass
    _EOF.discard(fd); return 0
@fn("fread")
def _fread(e):
    size, n, fd = e.arg(1), e.arg(2), fd_of(e.arg(3))
    if not size or not n: return 0
    b = os.read(fd, size * n)
    if len(b) < size * n: _EOF.add(fd)
    e.write(e.arg(0), b); return len(b) // size
@fn("fseek", "fseeko")
def _fseek(e):
    fd = fd_of(e.arg(0)); _EOF.discard(fd)
    try: os.lseek(fd, s64(e.arg(1)), e.arg(2) & 3); return 0
    except OSError: return M64
@fn("ftell", "ftello")
def _ftell(e):
    try: return os.lseek(fd_of(e.arg(0)), 0, 1)
    except OSError: return M64
@fn("rewind")
def _rewind(e): fd = fd_of(e.arg(0)); _EOF.discard(fd); os.lseek(fd, 0, 0)
@fn("feof")
def _feof(e): return int(fd_of(e.arg(0)) in _EOF)
@fn("ferror")
def _ferror(e): return 0
@fn("fileno")
def _fileno(e): return fd_of(e.arg(0))
@fn("fgetc", "getc")
def _fgetc(e):
    fd = fd_of(e.arg(0)); b = os.read(fd, 1)
    if not b: _EOF.add(fd); return M64
    return b[0]
def _fgets_any(e):
    fd, n = fd_of(e.arg(2)), e.arg(1); out = b""
    while len(out) < n - 1:
        b = os.read(fd, 1)
        if not b: _EOF.add(fd); break
        out += b
        if b == b"\n": break
    if not out: return 0
    e.write(e.arg(0), out + b"\0"); return e.arg(0)
FUNCS["_fgets"] = _fgets_any          # hle's version only knew stdin and ignored the FILE*
from hle import s64

# ---- libc++ std::string pieces seen in osu!
_S = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE"
_SK = "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE"
FUNCS.setdefault("_" + _S + "6assignEPKc", lambda e: (str_set(e, e.arg(0), e.cstr_bytes(e.arg(1))), e.arg(0))[1])
FUNCS.setdefault("_" + _S + "9push_backEc", lambda e: str_set(e, e.arg(0), str_get(e, e.arg(0)) + bytes([e.arg(1) & 0xff])))
def _find_c(e):
    s, c, pos = str_get(e, e.arg(0)), bytes([e.arg(1) & 0xff]), e.arg(2)
    i = s.find(c, pos); return M64 if i < 0 else i
def _rfind_c(e):
    s, c, pos = str_get(e, e.arg(0)), bytes([e.arg(1) & 0xff]), e.arg(2)
    i = s.rfind(c, 0, min(pos, len(s) - 1) + 1) if pos != M64 else s.rfind(c); return M64 if i < 0 else i
FUNCS.setdefault("_" + _SK + "4findEcm", _find_c)
FUNCS.setdefault("_" + _SK + "5rfindEcm", _rfind_c)

# ---- misc libc++ / libm
for _suf in ("C1Ev", "C2Ev", "D1Ev", "D2Ev", "4lockEv", "6unlockEv", "11lock_sharedEv", "13unlock_sharedEv"):
    FUNCS.setdefault("__ZNSt3__119__shared_mutex_base" + _suf, lambda e: None)
@fn("_ZNSt3__112__next_primeEm")
def _next_prime(e):
    n = max(e.arg(0), 2)
    while True:
        if n < 4 or all(n % d for d in range(2, int(n ** 0.5) + 1)): return n
        n += 1

def _f32(e, i): return struct.unpack("<f", struct.pack("<I", e.uc.reg_read(UC_ARM64_REG_D0 + i) & M32))[0]
def _setf(e, v):
    try: b = struct.unpack("<I", struct.pack("<f", v))[0]
    except OverflowError: b = struct.unpack("<I", struct.pack("<f", math.copysign(math.inf, v)))[0]
    e.uc.reg_write(UC_ARM64_REG_D0, b)
def _safe(f, *a):
    try: return f(*a)
    except (ValueError, OverflowError, ZeroDivisionError): return math.nan
def _reg1f(name, f):
    FUNCS.setdefault("_" + name, lambda e: _setf(e, _safe(f, _f32(e, 0))))
def _reg2f(name, f):
    FUNCS.setdefault("_" + name, lambda e: _setf(e, _safe(f, _f32(e, 0), _f32(e, 1))))
def _reg1d(name, f):
    FUNCS.setdefault("_" + name, lambda e: e.ret_double(_safe(f, e.darg(0))))
def _reg2d(name, f):
    FUNCS.setdefault("_" + name, lambda e: e.ret_double(_safe(f, e.darg(0), e.darg(1))))
for _n, _f in [("sinf", math.sin), ("cosf", math.cos), ("tanf", math.tan), ("sqrtf", math.sqrt), ("expf", math.exp),
               ("logf", math.log), ("floorf", math.floor), ("ceilf", math.ceil), ("fabsf", math.fabs),
               ("atanf", math.atan), ("asinf", math.asin), ("acosf", math.acos), ("log2f", math.log2),
               ("roundf", lambda v: float(math.floor(v + 0.5)) if v >= 0 else -float(math.floor(-v + 0.5)))]:
    _reg1f(_n, _f)
for _n, _f in [("powf", math.pow), ("atan2f", math.atan2), ("fmodf", math.fmod)]:
    _reg2f(_n, _f)
for _n, _f in [("asin", math.asin), ("acos", math.acos), ("log2", math.log2), ("log10", math.log10),
               ("sinh", math.sinh), ("cosh", math.cosh), ("tanh", math.tanh),
               ("round", lambda v: float(math.floor(v + 0.5)) if v >= 0 else -float(math.floor(-v + 0.5))),
               ("trunc", math.trunc)]:
    _reg1d(_n, _f)
for _n, _f in [("atan2", math.atan2), ("fmod", math.fmod)]:
    _reg2d(_n, _f)


# ======================= round 4: TLS name, malloc zones, objc protocols, Win-ish pointer helpers =======================
# Mach-O imports the C symbol _tlv_bootstrap as "__tlv_bootstrap"; fn("tlv_bootstrap") only produced "_tlv_bootstrap".
FUNCS["__tlv_bootstrap"] = FUNCS["_tlv_bootstrap"]

# ---- malloc zones (Chromium/CocCoc's allocator shim walks and patches these)
_ZONE = {}
def _zone(e):
    if "p" in _ZONE: return _ZONE["p"]
    z = e.malloc(256); e.write(z, b"\0" * 256)
    slots = {16: "size", 24: "malloc", 32: "calloc", 40: "valloc", 48: "free", 56: "realloc", 64: "destroy",
             80: "batch_malloc", 88: "batch_free", 112: "memalign", 120: "free_definite_size",
             128: "pressure_relief", 136: "claimed_address"}
    for off, nm in slots.items(): e.write(z + off, e.resolve("__a2x_zone_" + nm).to_bytes(8, "little"))
    e.write(z + 72, e.alloc_cstr("DefaultMallocZone").to_bytes(8, "little"))
    e.write(z + 104, struct.pack("<I", 10))          # version
    _ZONE["p"] = z; return z
def _zfn(nm, f): FUNCS["__a2x_zone_" + nm] = f
_zfn("size",   lambda e: e.heap_sizes.get(e.arg(1), 0))
_zfn("malloc", lambda e: e.malloc(e.arg(1)))
_zfn("calloc", lambda e: (lambda n: (lambda p: (e.write(p, b"\0" * n), p)[1])(e.malloc(n)))(e.arg(1) * e.arg(2)))
_zfn("valloc", lambda e: e.malloc(e.arg(1)))
_zfn("free",   lambda e: None)
_zfn("destroy", lambda e: None)
_zfn("memalign", lambda e: e.malloc(e.arg(2)))
_zfn("free_definite_size", lambda e: None)
_zfn("pressure_relief", lambda e: 0)
_zfn("claimed_address", lambda e: int(e.arg(1) in e.heap_sizes))
_zfn("batch_malloc", lambda e: 0)
_zfn("batch_free", lambda e: None)
def _zrealloc(e):
    old, n = e.arg(1), e.arg(2); p = e.malloc(n)
    if old:
        k = min(e.heap_sizes.get(old, 0), n)
        if k: e.write(p, bytes(e.read(old, k)))
    return p
_zfn("realloc", _zrealloc)

FUNCS.setdefault("_malloc_default_zone", _zone)
FUNCS.setdefault("_malloc_default_purgeable_zone", _zone)
FUNCS.setdefault("_malloc_create_zone", _zone)
FUNCS.setdefault("_malloc_zone_from_ptr", lambda e: _zone(e) if e.arg(0) in e.heap_sizes else 0)
FUNCS.setdefault("_malloc_set_zone_name", lambda e: None)
FUNCS.setdefault("_malloc_get_zone_name", lambda e: e.alloc_cstr("DefaultMallocZone"))
FUNCS.setdefault("_malloc_zone_register", lambda e: None)
FUNCS.setdefault("_malloc_zone_unregister", lambda e: None)
FUNCS.setdefault("_malloc_zone_pressure_relief", lambda e: 0)
FUNCS.setdefault("_malloc_zone_check", lambda e: 1)
FUNCS.setdefault("_malloc_zone_malloc", lambda e: e.malloc(e.arg(1)))
FUNCS.setdefault("_malloc_zone_valloc", lambda e: e.malloc(e.arg(1)))
FUNCS.setdefault("_malloc_zone_memalign", lambda e: e.malloc(e.arg(2)))
FUNCS.setdefault("_malloc_zone_free", lambda e: None)
FUNCS.setdefault("_malloc_zone_calloc", lambda e: (lambda n: (lambda p: (e.write(p, b"\0" * n), p)[1])(e.malloc(n)))(e.arg(1) * e.arg(2)))
def _zone_realloc(e):
    old, n = e.arg(1), e.arg(2); p = e.malloc(n)
    if old:
        k = min(e.heap_sizes.get(old, 0), n)
        if k: e.write(p, bytes(e.read(old, k)))
    return p
FUNCS.setdefault("_malloc_zone_realloc", _zone_realloc)
FUNCS.setdefault("_malloc_size", lambda e: e.heap_sizes.get(e.arg(0), 0))
FUNCS.setdefault("_malloc_good_size", lambda e: (e.arg(0) + 15) & ~15)
FUNCS.setdefault("_malloc_zone_size", lambda e: e.heap_sizes.get(e.arg(1), 0))
FUNCS.setdefault("_malloc_make_purgeable", lambda e: 0)
FUNCS.setdefault("_malloc_make_nonpurgeable", lambda e: 0)
@fn("malloc_get_all_zones")        # kern_return_t (task, reader, vm_address_t **addrs, unsigned *count)
def _get_all_zones(e):
    z = _zone(e)
    if "arr" not in _ZONE:
        _ZONE["arr"] = e.malloc(8); e.write(_ZONE["arr"], z.to_bytes(8, "little"))
    if e.arg(2): e.write(e.arg(2), _ZONE["arr"].to_bytes(8, "little"))
    if e.arg(3): e.write(e.arg(3), struct.pack("<I", 1))
    return 0

# ---- ObjC protocols / runtime queries Godot & friends do at startup
def _host_objc():
    import objc as _o
    return _o.host()["objc"] if _o.DARWIN else None
@fn("objc_getProtocol")
def _getproto(e):
    o = _host_objc()
    if not o: return 0
    f = o.objc_getProtocol; f.restype, f.argtypes = ctypes.c_void_p, [ctypes.c_char_p]
    return f(e.cstr(e.arg(0)).encode()) or 0
@fn("class_conformsToProtocol")
def _conforms(e):
    import objc as _o
    if e.arg(0) in _o.CLASSES: return 0
    o = _host_objc()
    if not o or not e.arg(0) or not e.arg(1): return 0
    f = o.class_conformsToProtocol; f.restype, f.argtypes = ctypes.c_bool, [ctypes.c_void_p, ctypes.c_void_p]
    return int(f(e.arg(0), e.arg(1)))
FUNCS.setdefault("_objc_copyProtocolList", lambda e: (e.arg(1) and e.write(e.arg(1), b"\0\0\0\0"), 0)[1])
FUNCS.setdefault("_objc_allocateProtocol", lambda e: e.malloc(16))
FUNCS.setdefault("_objc_registerProtocol", lambda e: None)
FUNCS.setdefault("_protocol_addMethodDescription", lambda e: None)
FUNCS.setdefault("_protocol_addProtocol", lambda e: None)
FUNCS.setdefault("_protocol_conformsToProtocol", lambda e: int(e.arg(0) == e.arg(1)))
FUNCS.setdefault("_protocol_getName", lambda e: e.alloc_cstr("Protocol"))
FUNCS.setdefault("_protocol_isEqual", lambda e: int(e.arg(0) == e.arg(1)))

# ---- Windows-flavoured helpers PowerPoint's bundled runtime imports (harmless identity/no-op semantics)
FUNCS.setdefault("_EncodePointer", lambda e: e.arg(0))
FUNCS.setdefault("_DecodePointer", lambda e: e.arg(0))
FUNCS.setdefault("_InitializeCriticalSectionEx", lambda e: 1)
FUNCS.setdefault("_InitializeCriticalSection", lambda e: None)
FUNCS.setdefault("_EnterCriticalSection", lambda e: None)
FUNCS.setdefault("_LeaveCriticalSection", lambda e: None)
FUNCS.setdefault("_DeleteCriticalSection", lambda e: None)


# ======================= round 5 =======================
# CVDisplayLinkCreateWithCGDisplay(displayID, CVDisplayLinkRef *out): the out-pointer is arg1 (cocoa.py wrote to arg0 = the display id)
import cocoa as _cocoa
def _dl_make(e, out):
    link = e.malloc(16); e.write(link, b"CVDL" + b"\0" * 12)
    if out: e.write(out, link.to_bytes(8, "little"))
    _cocoa._DL["link"] = link; return 0
FUNCS["_CVDisplayLinkCreateWithCGDisplay"] = lambda e: _dl_make(e, e.arg(1))
FUNCS["_CVDisplayLinkCreateWithActiveCGDisplays"] = lambda e: _dl_make(e, e.arg(0))
FUNCS["_CVDisplayLinkCreateWithCGDisplays"] = lambda e: _dl_make(e, e.arg(2))

# _NSGetExecutablePath(char *buf, uint32_t *bufsize): too-small buffer must return -1 and report the needed size
@fn("_NSGetExecutablePath")
def _nsep2(e):
    b = os.path.abspath(getattr(e, "path", "")).encode() + b"\0"
    szp = e.arg(1); have = int.from_bytes(e.read(szp, 4), "little") if szp else 0
    if szp: e.write(szp, len(b).to_bytes(4, "little"))
    if have < len(b): return M32
    e.write(e.arg(0), b); return 0

# abort_report_np(fmt, ...): prints the message then aborts
@fn("abort_report_np")
def _abort_report(e):
    from hle import do_printf
    try: sys.stderr.write(do_printf(e, e.arg(0), 1).decode("latin-1") + "\n")
    except Exception: pass
    e.exit(134)
