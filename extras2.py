"""
extras2: additions layered on top of extras.py (which stays exactly as the known-good Derelict version).
Everything here either fills a missing name or fixes a wrong-arity/wrong-name registration; set ARM2X86_DEBUG=1 for
crash attribution (runs the emulator under a supervisor that reports the last bridged call).
"""
import os, sys, struct, ctypes
from unicorn.arm64_const import *
import hle
from hle import FUNCS, M64, s32, do_printf
import objc as _objc
import cocoa as _cocoa
M32 = 0xffffffff

def fn(*names):                                   # fills only names nothing else provides
    def deco(f):
        for n in names: FUNCS.setdefault("_" + n, f)
        return f
    return deco
def force(*names):                                # replaces an existing (wrong) registration
    def deco(f):
        for n in names: FUNCS["_" + n] = f
        return f
    return deco
def _host(fw):
    try: return ctypes.CDLL(f"/System/Library/Frameworks/{fw}.framework/{fw}")
    except OSError: return None

# ---- CVDisplayLinkCreateWithCGDisplay(displayID, CVDisplayLinkRef *out): out is arg1 (cocoa.py wrote to arg0 = the display id)
@force("CVDisplayLinkCreateWithCGDisplay")
def _dl_cgdisplay(e):
    link = e.malloc(16); e.write(link, b"CVDL" + b"\0" * 12)
    if e.arg(1): e.write(e.arg(1), link.to_bytes(8, "little"))
    _cocoa._DL["link"] = link; return 0

# ---- _NSGetExecutablePath: too small a buffer -> return -1 and report the needed size
@force("_NSGetExecutablePath")
def _nsep(e):
    b = os.path.abspath(getattr(e, "path", "")).encode() + b"\0"
    szp = e.arg(1); have = int.from_bytes(e.read(szp, 4), "little") if szp else 0
    if szp: e.write(szp, len(b).to_bytes(4, "little"))
    if have < len(b): return M32
    e.write(e.arg(0), b); return 0

@fn("abort_report_np")
def _abort_report(e):
    try: sys.stderr.write(do_printf(e, e.arg(0), 1).decode("latin-1") + "\n")
    except Exception: pass
    e.exit(134)

# ---- malloc zones as a real list: Chromium registers its delegating zone and requires it to become the default
_ZL, _ZP = [], []
def _mk_zone(e):
    z = e.malloc(256); e.write(z, b"\0" * 256)
    slots = {16: "size", 24: "malloc", 32: "calloc", 40: "valloc", 48: "free", 56: "realloc", 64: "destroy",
             80: "batch_malloc", 88: "batch_free", 112: "memalign", 120: "free_definite_size",
             128: "pressure_relief", 136: "claimed_address"}
    for off, nm in slots.items(): e.write(z + off, e.resolve("__a2x_zone_" + nm).to_bytes(8, "little"))
    e.write(z + 72, e.alloc_cstr("DefaultMallocZone").to_bytes(8, "little"))
    e.write(z + 104, struct.pack("<I", 10)); return z
def _zones(e):
    if not _ZL: _ZL.append(_mk_zone(e)); _ZP.append(_mk_zone(e)); _ZL.append(_ZP[0])
    return _ZL
def _zrealloc(e):
    old, n = e.arg(1), e.arg(2); p = e.malloc(n)
    if old:
        k = min(e.heap_sizes.get(old, 0), n)
        if k: e.write(p, bytes(e.read(old, k)))
    return p
def _zcalloc(e):
    n = e.arg(1) * e.arg(2); p = e.malloc(n); e.write(p, b"\0" * n); return p
for _nm, _f in [("size", lambda e: e.heap_sizes.get(e.arg(1), 0)), ("malloc", lambda e: e.malloc(e.arg(1))),
                ("calloc", _zcalloc), ("valloc", lambda e: e.malloc(e.arg(1))), ("free", lambda e: None),
                ("destroy", lambda e: None), ("memalign", lambda e: e.malloc(e.arg(2))),
                ("free_definite_size", lambda e: None), ("pressure_relief", lambda e: 0),
                ("claimed_address", lambda e: int(e.arg(1) in e.heap_sizes)),
                ("batch_malloc", lambda e: 0), ("batch_free", lambda e: None), ("realloc", _zrealloc)]:
    FUNCS["__a2x_zone_" + _nm] = _f
def _zreg(e):
    zs = _zones(e)
    if e.arg(0) and e.arg(0) not in zs: zs.append(e.arg(0))
def _zunreg(e):
    zs = _zones(e)
    if e.arg(0) in zs: zs.remove(e.arg(0))
def _all_zones(e):
    zs = list(_zones(e)); arr = e.malloc(8 * max(len(zs), 1))
    e.write(arr, b"".join(z.to_bytes(8, "little") for z in zs))
    if e.arg(2): e.write(e.arg(2), arr.to_bytes(8, "little"))
    if e.arg(3): e.write(e.arg(3), struct.pack("<I", len(zs)))
    return 0
FUNCS["_malloc_default_zone"] = lambda e: _zones(e)[0]
FUNCS["_malloc_default_purgeable_zone"] = lambda e: (_zones(e), _ZP[0])[1]
FUNCS["_malloc_create_zone"] = lambda e: _mk_zone(e)
FUNCS["_malloc_zone_from_ptr"] = lambda e: _zones(e)[0] if e.arg(0) in e.heap_sizes else 0
FUNCS["_malloc_zone_register"] = _zreg
FUNCS["_malloc_zone_unregister"] = _zunreg
FUNCS["_malloc_get_all_zones"] = _all_zones

# ---- CoreFoundation / CoreGraphics / IOKit bits Mazkey needs
def _ho(e, p):
    try:
        if p and _objc.is_guest(e, p) and _objc.read_isa_is_cf(e, p): return _objc.to_nsstring(e, p)
    except Exception: pass
    return p
@fn("CFStringCompare")
def _cfcmp(e):
    cf = _host("CoreFoundation")
    if not cf: return 0
    cf.CFStringCompare.restype = ctypes.c_long; cf.CFStringCompare.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
    a, b = _ho(e, e.arg(0)), _ho(e, e.arg(1))
    return (cf.CFStringCompare(a, b, e.arg(2)) & M64) if a and b else 0
@fn("CFArrayCreateMutable")
def _cfamut(e):
    cf = _host("CoreFoundation")
    if not cf: return 0
    cf.CFArrayCreateMutable.restype = ctypes.c_void_p; cf.CFArrayCreateMutable.argtypes = [ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p]
    cb = ctypes.addressof(ctypes.c_char.in_dll(cf, "kCFTypeArrayCallBacks")) if e.arg(2) else None
    return cf.CFArrayCreateMutable(None, e.arg(1), cb) or 0
@fn("CFArrayAppendValue")
def _cfaapp(e):
    cf = _host("CoreFoundation")
    if not cf or not e.arg(0): return None
    cf.CFArrayAppendValue.restype = None; cf.CFArrayAppendValue.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    cf.CFArrayAppendValue(e.arg(0), _ho(e, e.arg(1))); return None
def _cgmode(name, restype, default):
    def f(e):
        cg = _host("CoreGraphics"); g = getattr(cg, name, None) if cg else None
        if g is None or not e.arg(0):
            if restype is ctypes.c_double: e.ret_double(60.0); return None
            return default
        g.restype = restype; g.argtypes = [ctypes.c_void_p]; r = g(e.arg(0))
        if restype is ctypes.c_double: e.ret_double(r); return None
        return (r or 0) & M64
    return f
fn("CGDisplayModeIsUsableForDesktopGUI")(_cgmode("CGDisplayModeIsUsableForDesktopGUI", ctypes.c_ubyte, 1))
fn("CGDisplayModeGetIOFlags")(_cgmode("CGDisplayModeGetIOFlags", ctypes.c_uint32, 0))
fn("CGDisplayModeCopyPixelEncoding")(_cgmode("CGDisplayModeCopyPixelEncoding", ctypes.c_void_p, 0))
fn("CGDisplayModeGetRefreshRate")(_cgmode("CGDisplayModeGetRefreshRate", ctypes.c_double, 0))
fn("CGDisplayIOServicePort")(lambda e: 0)
fn("IODisplayCreateInfoDictionary")(lambda e: 0)
# Text Input Source (keyboard layout) — call host Carbon if present, else CFString stubs.
_TIS_SRC = None  # host TISInputSourceRef
_TIS_PROPS = {}

def _tis_host():
    global _TIS_SRC
    if _TIS_SRC is not None:
        return _TIS_SRC
    try:
        ht = ctypes.CDLL("/System/Library/Frameworks/Carbon.framework/Carbon")
        ht.TISCopyCurrentKeyboardLayoutInputSource.restype = ctypes.c_void_p
        ht.TISCopyCurrentKeyboardLayoutInputSource.argtypes = []
        _TIS_SRC = ht.TISCopyCurrentKeyboardLayoutInputSource() or 1
        return _TIS_SRC
    except Exception:
        _TIS_SRC = 1  # non-null fake token
        return _TIS_SRC

def _tis_copy(e):
    return _tis_host() & 0xffffffffffffffff

def _tis_prop(e):
    # TISGetInputSourceProperty(source, propertyKey) -> CFTypeRef
    key = e.arg(1)
    # Resolve key: may be CFString host pointer or guest-bound constant address
    name = None
    try:
        # try reading as C string if it looks like our bound constant
        from cocoa import lib as _cflib  # may fail
    except Exception:
        _cflib = None
    # Always return a CFString for common properties so strlen/CFStringGet* don't see NULL
    try:
        cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        cf.CFStringCreateWithCString.restype = ctypes.c_void_p
        cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
        # kTISPropertyInputSourceID etc. — return a stable ASCII id
        s = b"com.apple.keylayout.US"
        p = cf.CFStringCreateWithCString(None, s, 0x08000100)  # kCFStringEncodingUTF8
        return (p or 1) & 0xffffffffffffffff
    except Exception:
        return 1

fn("TISCopyCurrentKeyboardLayoutInputSource")(_tis_copy)
fn("TISCopyCurrentKeyboardInputSource")(_tis_copy)
fn("TISGetInputSourceProperty")(_tis_prop)
def _iopm(e, idx):
    if e.arg(idx): e.write(e.arg(idx), struct.pack("<I", 1))
    return 0
fn("IOPMAssertionCreateWithDescription")(lambda e: _iopm(e, 7))
fn("IOPMAssertionCreateWithName")(lambda e: _iopm(e, 3))
fn("IOPMAssertionRelease")(lambda e: 0)

# ---- C++ exception runtime. libcxx.py registered these through fn("___cxa_throw") => "____cxa_throw", so they never matched.
def _typename(e, ti):
    try:
        p = int.from_bytes(e.read(ti + 8, 8), "little") & 0x0000ffffffffffff
        return e.cstr(p)
    except Exception: return "?"
def _no_unwind(what):
    def f(e):
        extra = ""
        if what == "throw":
            extra = f" type={_typename(e, e.arg(1))!r} obj={e.arg(0):#x}"
        sys.stderr.write(f"[arm2x86] guest C++ {what}{extra} -- unwinding is not emulated; stopping\n"); e.exit(134)
    return f
for _n in ("__cxa_throw", "__cxa_rethrow", "__cxa_begin_catch", "__cxa_end_catch", "_Unwind_Resume", "__cxa_call_unexpected"):
    FUNCS["_" + _n] = _no_unwind(_n.lstrip("_"))
FUNCS["___cxa_allocate_exception"] = lambda e: e.malloc(e.arg(0) + 128) + 128
FUNCS["___cxa_free_exception"] = lambda e: None
for _n in ("__ZNSt9bad_allocC1Ev", "__ZNSt9bad_allocC2Ev", "__ZNSt9exceptionC1Ev", "__ZNSt9exceptionC2Ev",
           "__ZNSt9exceptionD1Ev", "__ZNSt9exceptionD2Ev", "__ZNSt9bad_allocD1Ev", "__ZNSt9bad_allocD2Ev"):
    FUNCS.setdefault(_n, lambda e: e.arg(0))
# ---- mimalloc (Roblox links its own copy; the dylib isn't loaded) -> map onto the emulated heap
def _mi_calloc(e):
    n = e.arg(0) * e.arg(1); p = e.malloc(n); e.write(p, b"\0" * n); return p
def _mi_zalloc(e):
    p = e.malloc(e.arg(0)); e.write(p, b"\0" * e.arg(0)); return p
def _mi_realloc(e):
    old, n = e.arg(0), e.arg(1); p = e.malloc(n)
    if old:
        k = min(e.heap_sizes.get(old, 0), n)
        if k: e.write(p, bytes(e.read(old, k)))
    return p
for _n in ("mi_malloc", "mi_new", "mi_new_nothrow", "mi_malloc_small", "mi_valloc"):
    FUNCS.setdefault("_" + _n, lambda e: e.malloc(e.arg(0)))
for _n in ("mi_malloc_aligned", "mi_new_aligned", "mi_new_aligned_nothrow"):
    FUNCS.setdefault("_" + _n, lambda e: e.malloc(max(e.arg(0), 1)))
for _n in ("mi_free", "mi_free_size", "mi_free_aligned", "mi_free_size_aligned"):
    FUNCS.setdefault("_" + _n, lambda e: None)
FUNCS.setdefault("_mi_calloc", _mi_calloc); FUNCS.setdefault("_mi_zalloc", _mi_zalloc)
FUNCS.setdefault("_mi_realloc", _mi_realloc)
FUNCS.setdefault("_mi_usable_size", lambda e: e.heap_sizes.get(e.arg(0), 0))
FUNCS.setdefault("_mi_strdup", lambda e: e.alloc_cstr(e.cstr(e.arg(0))) if e.arg(0) else 0)
FUNCS.setdefault("_mi_get_category", lambda e: 0)

# more of the mimalloc surface (names Roblox's fork may import)
_usable = lambda e: e.heap_sizes.get(e.arg(0), 0)
for _n in ("mi_malloc_usable_size", "mi_usable_size"):
    FUNCS["_" + _n] = _usable
FUNCS.setdefault("_mi_good_size", lambda e: (e.arg(0) + 15) & ~15)
FUNCS.setdefault("_mi_expand", lambda e: 0)
FUNCS.setdefault("_mi_rezalloc", lambda e: (lambda p: (e.write(p, b"\0" * e.arg(1)), p)[1])(_mi_realloc(e)))
FUNCS.setdefault("_mi_reallocn", lambda e: (lambda n: (e.write(0, b"") if False else None, e.malloc(n))[1])(e.arg(1) * e.arg(2)))
FUNCS.setdefault("_mi_recalloc", lambda e: (lambda n: (lambda p: (e.write(p, b"\0" * n), p)[1])(e.malloc(n)))(e.arg(1) * e.arg(2)))
FUNCS.setdefault("_mi_aligned_alloc", lambda e: e.malloc(e.arg(1)))
FUNCS.setdefault("_mi_memalign", lambda e: e.malloc(e.arg(1)))
FUNCS.setdefault("_mi_zalloc_aligned", lambda e: (lambda p: (e.write(p, b"\0" * e.arg(0)), p)[1])(e.malloc(e.arg(0))))
FUNCS.setdefault("_mi_calloc_aligned", lambda e: (lambda n: (lambda p: (e.write(p, b"\0" * n), p)[1])(e.malloc(n)))(e.arg(0) * e.arg(1)))
FUNCS.setdefault("_mi_realloc_aligned", lambda e: _mi_realloc(e))
def _mi_posix_memalign(e):
    p = e.malloc(e.arg(2)); e.write(e.arg(0), p.to_bytes(8, "little")); return 0
FUNCS.setdefault("_mi_posix_memalign", _mi_posix_memalign)
FUNCS.setdefault("_mi_strndup", lambda e: e.alloc_cstr(e.cstr(e.arg(0))[: e.arg(1)]) if e.arg(0) else 0)
for _n in ("mi_process_init", "mi_thread_init", "mi_thread_done", "mi_collect", "mi_stats_print", "mi_stats_reset",
           "mi_register_deferred_free", "mi_register_output", "mi_register_error", "mi_option_set", "mi_option_enable",
           "mi_option_disable", "mi_option_set_default", "mi_option_set_enabled", "mi_option_set_enabled_default"):
    FUNCS.setdefault("_" + _n, lambda e: None)
for _n in ("mi_option_get", "mi_option_get_clamp", "mi_option_is_enabled", "mi_is_in_heap_region", "mi_is_redirected",
           "mi_heap_get_default", "mi_heap_get_backing", "mi_heap_new", "mi_check_owned"):
    FUNCS.setdefault("_" + _n, lambda e: 0)
FUNCS.setdefault("_mi_version", lambda e: 190)
for _n, _sz in (("mi_heap_malloc", 1), ("mi_heap_malloc_small", 1), ("mi_heap_zalloc", 1)):
    FUNCS.setdefault("_" + _n, (lambda sz: lambda e: (lambda p: (e.write(p, b"\0" * e.arg(sz)), p)[1])(e.malloc(e.arg(sz))))(_sz))
FUNCS.setdefault("_mi_heap_calloc", lambda e: (lambda n: (lambda p: (e.write(p, b"\0" * n), p)[1])(e.malloc(n)))(e.arg(1) * e.arg(2)))
FUNCS.setdefault("_mi_heap_realloc", lambda e: (lambda old, n: (lambda p: (e.write(p, bytes(e.read(old, min(e.heap_sizes.get(old, 0), n)))) if old and e.heap_sizes.get(old, 0) else None, p)[1])(e.malloc(n)))(e.arg(1), e.arg(2)))
FUNCS.setdefault("_mi_heap_destroy", lambda e: None); FUNCS.setdefault("_mi_heap_delete", lambda e: None)
FUNCS.setdefault("_mi_heap_collect", lambda e: None)

# ---- C++ std / libc / libm odds and ends the Roblox binaries import (all single-address-space, cooperative threads)
import math, time
def _noop(e): return None
for _n in ("__ZNSt3__15mutex4lockEv", "__ZNSt3__15mutex6unlockEv", "__ZNSt3__15mutexD1Ev", "__ZNSt3__118condition_variable10notify_allEv",
           "__ZNSt3__118condition_variable10notify_oneEv", "__ZNSt3__118condition_variableD1Ev", "__ZNSt3__18__sp_mut4lockEv",
           "__ZNSt3__18__sp_mut6unlockEv", "__ZNSt3__16threadD1Ev", "___tlv_atexit", "__tlv_atexit", "___gxx_personality_v0",
           "___register_frame", "___deregister_frame", "___unw_add_dynamic_fde", "__os_log_impl", "_setbuf", "_setvbuf",
           "_pthread_cond_destroy", "_pthread_mutexattr_setpolicy_np", "_pthread_set_qos_class_self_np", "_perror",
           "_mi_register_category_thread_done", "_mi_thread_set_in_threadpool", "_srandomdev", "_sys_icache_invalidate"):
    FUNCS.setdefault(_n if _n.startswith("_") else "_" + _n, _noop)
def _cv_wait(e):                              # lets other emulated threads run, then reports a (legal) spurious wakeup
    try: e.schedule(True)
    except Exception: pass
FUNCS.setdefault("__ZNSt3__118condition_variable4waitERNS_11unique_lockINS_5mutexEEE", _cv_wait)
def _cv_timed(e):
    _cv_wait(e); time.sleep(0.001); return None
FUNCS.setdefault("__ZNSt3__118condition_variable15__do_timed_waitERNS_11unique_lockINS_5mutexEEENS_6chrono10time_pointINS5_12system_clockENS5_8durationIxNS_5ratioILl1ELl1000000000EEEEEEE", _cv_timed)
FUNCS.setdefault("__ZNSt3__16chrono12steady_clock3nowEv", lambda e: time.monotonic_ns())
FUNCS.setdefault("__ZNSt3__16chrono12system_clock3nowEv", lambda e: int(time.time() * 1e6))
FUNCS.setdefault("__ZNSt3__16chrono12system_clock11from_time_tEl", lambda e: e.arg(0) * 1000000)
FUNCS.setdefault("__ZNSt3__16chrono12system_clock9to_time_tERKNS0_10time_pointIS1_NS0_8durationIxNS_5ratioILl1ELl1000000EEEEEEE",
                 lambda e: int.from_bytes(e.read(e.arg(0), 8), "little") // 1000000)
def _sleep_for(e):
    ns = s32(e.arg(0)) if False else int.from_bytes(e.read(e.arg(0), 8), "little")
    time.sleep(min(max(ns, 0) / 1e9, 0.01)); _cv_wait(e)
FUNCS.setdefault("__ZNSt3__111this_thread9sleep_forERKNS_6chrono8durationIxNS_5ratioILl1ELl1000000000EEEEEE", _sleep_for)
FUNCS.setdefault("__ZNSt3__16thread20hardware_concurrencyEv", lambda e: 4)
FUNCS.setdefault("___cxa_get_globals_fast", lambda e: e.malloc(16))
FUNCS.setdefault("___cxa_demangle", lambda e: 0)
FUNCS.setdefault("___cxa_get_exception_ptr", lambda e: e.arg(0))
@fn("__cxa_pure_virtual")
def _pure(e): sys.stderr.write("[arm2x86] pure virtual function called\n"); e.exit(134)
FUNCS.setdefault("___ulock_wait", lambda e: 0); FUNCS.setdefault("___ulock_wake", lambda e: 0)
FUNCS.setdefault("_pthread_cpu_number_np", lambda e: 0)
for _n in ("_sched_get_priority_min", "_getpriority", "_setpriority", "_pthread_getschedparam", "_pthread_setschedparam",
           "_pthread_attr_setschedparam", "_pthread_attr_setschedpolicy", "_pthread_attr_getdetachstate", "_setrlimit",
           "_getppid", "_pthread_get_stackaddr_np", "_pthread_mach_thread_np", "_setsid", "_flock", "_chmod", "_fchmod"):
    FUNCS.setdefault(_n, lambda e: 0)
FUNCS.setdefault("_sched_get_priority_max", lambda e: 31)
FUNCS.setdefault("_pthread_get_stacksize_np", lambda e: 0x800000)
def _getrlimit(e):
    if e.arg(1): e.write(e.arg(1), struct.pack("<QQ", 0x7fffffffffffffff, 0x7fffffffffffffff))
    return 0
FUNCS.setdefault("_getrlimit", _getrlimit)
def _uname(e):
    import spoof
    f = lambda s: s.encode().ljust(256, b"\0")
    e.write(e.arg(0), b"".join(f(x) for x in spoof.uname_fields())); return 0
FUNCS.setdefault("_uname", _uname)
FUNCS.setdefault("_clock", lambda e: int(time.process_time() * 1e6))
FUNCS.setdefault("_random", lambda e: __import__("random").randint(0, 0x7fffffff))
FUNCS.setdefault("_rand_r", lambda e: __import__("random").randint(0, 0x7fffffff))
# strings
def _cs(e, i): return e.cstr_bytes(e.arg(i))
FUNCS.setdefault("_strcspn", lambda e: next((k for k, c in enumerate(_cs(e, 0)) if c in _cs(e, 1)), len(_cs(e, 0))))
FUNCS.setdefault("_strspn", lambda e: next((k for k, c in enumerate(_cs(e, 0)) if c not in _cs(e, 1)), len(_cs(e, 0))))
FUNCS.setdefault("_strpbrk", lambda e: (lambda s, acc: next((e.arg(0) + k for k, c in enumerate(s) if c in acc), 0))(_cs(e, 0), _cs(e, 1)))
def _strncat(e):
    d = e.arg(0); e.write(d + len(e.cstr_bytes(d)), _cs(e, 1)[: e.arg(2)] + b"\0"); return d
FUNCS.setdefault("_strncat", _strncat)
FUNCS.setdefault("_strsignal", lambda e: e.alloc_cstr("signal %d" % s32(e.arg(0))))
def _strlcpy_chk(e):
    s = _cs(e, 1); n = e.arg(2)
    if n: e.write(e.arg(0), s[: n - 1] + b"\0")
    return len(s)
FUNCS.setdefault("___strlcpy_chk", _strlcpy_chk)
def _strlcat_chk(e):
    d = e.cstr_bytes(e.arg(0)); s = _cs(e, 1); n = e.arg(2)
    if n > len(d) + 1: e.write(e.arg(0) + len(d), s[: n - len(d) - 1] + b"\0")
    return len(d) + len(s)
FUNCS.setdefault("___strlcat_chk", _strlcat_chk)
def _memset_s(e):
    n = min(e.arg(3), e.arg(1)); e.write(e.arg(0), bytes([e.arg(2) & 0xff]) * n); return 0
FUNCS.setdefault("_memset_s", _memset_s)
def _wcs(e, p):
    out = []
    while True:
        c = int.from_bytes(e.read(p + 4 * len(out), 4), "little")
        if c == 0: return out
        out.append(c)
FUNCS.setdefault("_wcslen", lambda e: len(_wcs(e, e.arg(0))))
def _wcscmp(e):
    a, b = _wcs(e, e.arg(0)), _wcs(e, e.arg(1)); return M64 if a < b else (1 if a > b else 0)
FUNCS.setdefault("_wcscmp", _wcscmp)
def _wcscpy(e):
    a = _wcs(e, e.arg(1)); e.write(e.arg(0), b"".join(c.to_bytes(4, "little") for c in a) + b"\0\0\0\0"); return e.arg(0)
FUNCS.setdefault("_wcscpy", _wcscpy)
def _wcsncpy(e):
    n = e.arg(2); a = _wcs(e, e.arg(1))[:n]; a += [0] * (n - len(a))
    e.write(e.arg(0), b"".join(c.to_bytes(4, "little") for c in a)); return e.arg(0)
FUNCS.setdefault("_wcsncpy", _wcsncpy)
def _wmemcmp(e):
    a, b = bytes(e.read(e.arg(0), 4 * e.arg(2))), bytes(e.read(e.arg(1), 4 * e.arg(2)))
    return M64 if a < b else (1 if a > b else 0)
FUNCS.setdefault("_wmemcmp", _wmemcmp)
# 128-bit helpers (__divti3 etc.): value = x0 | x1<<64
def _i128(e, i, signed):
    v = e.arg(i) | (e.arg(i + 1) << 64)
    return v - (1 << 128) if signed and v >> 127 else v
def _ret128(e, v):
    v &= (1 << 128) - 1; e.uc.reg_write(UC_ARM64_REG_X0, v & M64); e.uc.reg_write(UC_ARM64_REG_X1, v >> 64)
def _div128(signed):
    def f(e):
        a, b = _i128(e, 0, signed), _i128(e, 2, signed)
        q = 0 if b == 0 else (abs(a) // abs(b)) * (-1 if (a < 0) != (b < 0) else 1)
        _ret128(e, q)
    return f
FUNCS.setdefault("___divti3", _div128(True)); FUNCS.setdefault("___udivti3", _div128(False))
FUNCS.setdefault("___floattidf", lambda e: e.ret_double(float(_i128(e, 0, True))))
# libm
def _m1(name, f, single=False):
    def g(e):
        x = e.darg(0) if not single else struct.unpack("<f", struct.pack("<I", e.uc.reg_read(UC_ARM64_REG_D0) & M32))[0]
        try: r = f(x)
        except (ValueError, OverflowError): r = math.nan
        if single: e.uc.reg_write(UC_ARM64_REG_D0, struct.unpack("<I", struct.pack("<f", r))[0])
        else: e.ret_double(r)
    FUNCS.setdefault("_" + name, g)
for _n, _f in [("cbrt", lambda v: math.copysign(abs(v) ** (1 / 3), v)), ("exp2", lambda v: 2.0 ** v), ("expm1", math.expm1)]: _m1(_n, _f)
for _n, _f in [("sinhf", math.sinh), ("coshf", math.cosh), ("tanhf", math.tanh), ("asinhf", math.asinh), ("erff", math.erf),
               ("erfcf", math.erfc), ("log10f", math.log10), ("exp2f", lambda v: 2.0 ** v),
               ("cbrtf", lambda v: math.copysign(abs(v) ** (1 / 3), v))]: _m1(_n, _f, True)
FUNCS.setdefault("_hypot", lambda e: e.ret_double(math.hypot(e.darg(0), e.darg(1))))
FUNCS.setdefault("_ldexp", lambda e: e.ret_double(math.ldexp(e.darg(0), s32(e.arg(0)))))
FUNCS.setdefault("_scalbn", lambda e: e.ret_double(math.ldexp(e.darg(0), s32(e.arg(0)))))
def _frexp(e):
    m, ex = math.frexp(e.darg(0)); e.write(e.arg(0), struct.pack("<i", ex)); e.ret_double(m)
FUNCS.setdefault("_frexp", _frexp)
def _modf(e):
    f, i = math.modf(e.darg(0)); e.write(e.arg(0), struct.pack("<d", i)); e.ret_double(f)
FUNCS.setdefault("_modf", _modf)
FUNCS.setdefault("_nan", lambda e: e.ret_double(math.nan))
FUNCS.setdefault("_ilogb", lambda e: (math.frexp(e.darg(0))[1] - 1) & M32 if e.darg(0) else 0x80000000)

# ---- thread-local variables: one block PER guest thread (extras.py shared a single block between all threads)
_TLV = {"tmpl": None, "blk": {}}
@force("_tlv_bootstrap")                      # registered as "__tlv_bootstrap" (the name Mach-O actually imports)
def _tlv_per_thread(e):
    if _TLV["tmpl"] is None:
        secs = [s for s in e.mo.sections if s["sect"] in ("__thread_data", "__thread_bss")]
        if secs:
            lo = min(s["addr"] for s in secs); hi = max(s["addr"] + s["size"] for s in secs)
            data = bytearray(hi - lo)
            for s in secs:
                if s["sect"] == "__thread_data":
                    data[s["addr"] - lo: s["addr"] - lo + s["size"]] = bytes(e.read(s["addr"], s["size"]))
        else:
            lo, data = 0, bytearray(0x1000)
        _TLV["tmpl"] = bytes(data)
        if os.environ.get("ARM2X86_VERBOSE"):
            sys.stderr.write(f"[tlv] template at {lo:#x}, {len(data):#x} bytes from sections {[s['sect'] for s in secs]}\n")
    tid = getattr(e, "current_tid", 1)
    blk = _TLV["blk"].get(tid)
    if blk is None:
        blk = e.malloc(len(_TLV["tmpl"]) + 64); e.write(blk, _TLV["tmpl"]); _TLV["blk"][tid] = blk
    return blk + int.from_bytes(e.read(e.arg(0) + 16, 8), "little")
FUNCS["__tlv_bootstrap"] = _tlv_per_thread


# ---- libsystem blocks (Rust block2 / objc blocks) --------------------------------
_BLOCK_RETAIN = {}  # guest_ptr -> host_ptr or count

@fn("Block_copy", "_Block_copy")
def _block_copy(e):
    p = e.arg(0)
    if not p:
        return 0
    # Prefer host _Block_copy when pointer is a real host block
    try:
        lib = ctypes.CDLL(None)
        lib._Block_copy.restype = ctypes.c_void_p
        lib._Block_copy.argtypes = [ctypes.c_void_p]
        # Only call host if p looks like a host pointer (not guest image/heap)
        if not (0x100000000 <= p < 0x600000000 or p >= 0x7f0000000000):
            r = lib._Block_copy(p)
            if r:
                return r & 0xffffffffffffffff
    except Exception:
        pass
    # Guest block: bump a retain count and return same pointer so RcBlock sees non-null
    _BLOCK_RETAIN[p] = _BLOCK_RETAIN.get(p, 0) + 1
    return p

@fn("Block_release", "_Block_release")
def _block_release(e):
    p = e.arg(0)
    if not p:
        return None
    try:
        lib = ctypes.CDLL(None)
        lib._Block_release.restype = None
        lib._Block_release.argtypes = [ctypes.c_void_p]
        if not (0x100000000 <= p < 0x600000000 or p >= 0x7f0000000000):
            lib._Block_release(p)
            return None
    except Exception:
        pass
    c = _BLOCK_RETAIN.get(p, 0)
    if c <= 1:
        _BLOCK_RETAIN.pop(p, None)
    else:
        _BLOCK_RETAIN[p] = c - 1
    return None

# ---- generic: guest CFString constants passed to host-bound CoreFoundation/CoreGraphics wrappers become real NSStrings
def _wrap_bridge(f):
    def g(e):
        for i in range(8):
            v = e.arg(i)
            if v and v > 0x100000000:
                try:
                    if _objc.is_guest(e, v) and _objc.read_isa_is_cf(e, v):
                        e.uc.reg_write(UC_ARM64_REG_X0 + i, _objc.to_nsstring(e, v) & M64)
                except Exception: pass
        return f(e)
    return g
for _k, _f in list(FUNCS.items()):
    if getattr(_f, "__module__", "") == "cocoa" and "_bind" in getattr(_f, "__qualname__", ""):
        FUNCS[_k] = _wrap_bridge(_f)

# ---- debug: breadcrumb of every stub call (only under ARM2X86_DEBUG supervisor)
if os.environ.get("ARM2X86_CRUMB"):
    def _crumbed(name, f):
        def g(e):
            _objc.crumb(f"[stub] {name} x0..x3={e.arg(0):#x},{e.arg(1):#x},{e.arg(2):#x},{e.arg(3):#x}")
            return f(e)
        return g
    for _k, _f in list(FUNCS.items()):
        if not _k.startswith("_objc_msgSend"): FUNCS[_k] = _crumbed(_k, _f)

# ---- objc_setProperty / objc_getProperty (synthesized ivar accessors)
@fn("objc_setProperty_atomic", "objc_setProperty_nonatomic", "objc_setProperty_atomic_copy",
    "objc_setProperty_nonatomic_copy", "objc_setProperty")
def _setprop(e):
    self_, value, off = e.arg(0), e.arg(2), e.arg(3)
    if not self_: return None
    addr = (self_ + s32(off)) & M64
    try:
        old = int.from_bytes(e.read(addr, 8), "little")
    except Exception:
        old = 0
    if value and not _objc.is_guest(e, value) and _objc.DARWIN:
        if _objc.host_obj_ok(value):
            try: _objc.host()["objc"].objc_retain(value)
            except Exception: pass
        else: _objc.warn_bad("objc_setProperty(new)", value)
    try:
        e.write(addr, (value & M64).to_bytes(8, "little"))
    except Exception:
        return None
    if old and not _objc.is_guest(e, old) and _objc.DARWIN:
        if _objc.host_obj_ok(old):
            try: _objc.host()["objc"].objc_release(old)
            except Exception: pass
        else: _objc.warn_bad("objc_setProperty(old)", old)
    return None

@fn("objc_getProperty")
def _getprop(e):
    self_, off = e.arg(0), e.arg(2)
    if not self_: return 0
    try:
        return int.from_bytes(e.read((self_ + s32(off)) & M64, 8), "little")
    except Exception:
        return 0

@fn("syslog$DARWIN_EXTSN", "syslog")
def _syslog(e):
    try:
        msg = do_printf(e, e.arg(1), 2)
        sys.stderr.write(msg.decode("latin-1", "replace") + "\n")
    except Exception as ex:
        sys.stderr.write(f"[syslog] {ex}\n")
    return None

# ---- InstallAssistant / installer missing symbols --------------------------------
def _cf_typeid(name, default=0):
    def f(e, name=name, default=default):
        cf = _host("CoreFoundation")
        if not cf: return default
        try:
            g = getattr(cf, name)
            g.restype = ctypes.c_ulong
            if name == "CFDataGetTypeID":
                g.argtypes = []
                return g() & M64
            g.argtypes = [ctypes.c_void_p]
            return (g(e.arg(0)) if e.arg(0) else 0) & M64
        except Exception:
            return default
    return f
fn("CFGetTypeID")(_cf_typeid("CFGetTypeID"))
fn("CFDataGetTypeID")(_cf_typeid("CFDataGetTypeID"))

@fn("IOObjectRelease")
def _iorel(e):
    iokit = _host("IOKit")
    if not iokit or not e.arg(0): return 0
    try:
        iokit.IOObjectRelease.argtypes = [ctypes.c_void_p]
        iokit.IOObjectRelease.restype = ctypes.c_int
        return iokit.IOObjectRelease(e.arg(0)) & M64
    except Exception:
        return 0

@fn("IORegistryEntryFromPath")
def _ioregpath(e):
    iokit = _host("IOKit")
    if not iokit: return 0
    try:
        iokit.IORegistryEntryFromPath.restype = ctypes.c_void_p
        iokit.IORegistryEntryFromPath.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        path = e.cstr(e.arg(1)).encode() + b"\0" if e.arg(1) else b"\0"
        return iokit.IORegistryEntryFromPath(e.arg(0) or 0, path) or 0
    except Exception:
        return 0

@fn("IORegistryEntryCreateCFProperty")
def _ioregcf(e):
    iokit = _host("IOKit")
    if not iokit or not e.arg(0): return 0
    try:
        iokit.IORegistryEntryCreateCFProperty.restype = ctypes.c_void_p
        iokit.IORegistryEntryCreateCFProperty.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
        key = e.arg(1)
        if key and _objc.is_guest(e, key) and _objc.read_isa_is_cf(e, key):
            key = _objc.to_nsstring(e, key)
        r = iokit.IORegistryEntryCreateCFProperty(e.arg(0), key or None, e.arg(2) or None, e.arg(3) & 0xffffffff)
        return r or 0
    except Exception as ex:
        sys.stderr.write(f"[iokit] IORegistryEntryCreateCFProperty: {ex}\n")
        return 0

@fn("NSRunCriticalAlertPanel")
def _alert(e):
    try:
        def s(a):
            v = e.arg(a)
            if not v: return ""
            if _objc.is_guest(e, v) and _objc.read_isa_is_cf(e, v):
                return e.cstr(struct.unpack("<Q", bytes(e.read(v + 16, 8)))[0])
            if not _objc.is_guest(e, v) and _objc.DARWIN:
                try:
                    p = _objc.hmsg(v, "UTF8String")
                    return ctypes.string_at(p).decode() if p else ""
                except Exception:
                    return ""
            return ""
        sys.stderr.write(f"[alert] {s(0)}: {s(1)}\n")
    except Exception as ex:
        sys.stderr.write(f"[alert] {ex}\n")
    return 1

@fn("_Block_object_assign")
def _blk_assign(e):
    dest, src = e.arg(0), e.arg(1)
    if dest and src:
        try:
            e.write(dest, bytes(e.read(src, 8)))
        except Exception:
            pass
    return None

@fn("_Block_object_dispose")
def _blk_dispose(e):
    return None

@fn("objc_opt_respondsToSelector")
def _opt_resp(e):
    obj, sel = e.arg(0), e.arg(1)
    if not obj: return 0
    if obj in _objc.CLASSES or (_objc.is_guest(e, obj) and _objc.CLASSES):
        try:
            isa = int.from_bytes(e.read(obj, 8), "little") if obj not in _objc.CLASSES else obj
            cls = _objc.CLASSES.get(isa) or _objc.CLASSES.get(obj)
            if cls:
                name = _objc.selector_name(e, sel)
                return 1 if (_objc.lookup(cls, name, obj in _objc.CLASSES) or name in
                             ("retain", "release", "autorelease", "init", "class", "dealloc", "self")) else 0
        except Exception:
            pass
    if not _objc.DARWIN: return 0
    try:
        o = _objc.host()["objc"]
        cls = o.object_getClass(obj)
        return 1 if cls and o.class_getInstanceMethod(cls, sel) else 0
    except Exception:
        return 0

@fn("objc_enumerationMutation")
def _enum_mut(e):
    sys.stderr.write("[objc] collection mutated while being enumerated\n")
    e.exit(134)

def _data_sym(name, maker):
    hle.RESOLVERS.append(lambda e, n, name=name, maker=maker: maker(e) if n == name else None)

def _empty_cache(e):
    if not getattr(e, "_empty_cache", 0):
        e._empty_cache = e.malloc(16)
        e.write(e._empty_cache, b"\0" * 16)
    return e._empty_cache

def _dispatch_main_q(e):
    if not getattr(e, "_main_q", 0):
        e._main_q = e.malloc(64)
        e.write(e._main_q, b"\0" * 64)
    return e._main_q

_data_sym("__objc_empty_cache", _empty_cache)
_data_sym("__dispatch_main_q", _dispatch_main_q)
hle.DATA.setdefault("_kIOMasterPortDefault", 0)

