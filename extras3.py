"""
Round 4: what FreeType (emulated arm64 dylib) and spaghetti_celesti still needed.
setjmp/longjmp (FreeType's rasteriser uses them on EVERY glyph), memset_pattern*, float math, <ctype.h>'s _DefaultRuneLocale,
NSSearchPath enumeration, time helpers, and SteamAPI stand-ins (Steam is not available here: init reports failure).
Registered with setdefault: never overrides something another module already emulates.
"""
import os, sys, math, struct, time
from unicorn.arm64_const import *
import hle
from hle import FUNCS, DATA, M64, s32

def fn(*names):
    def deco(f):
        for n in names: FUNCS.setdefault("_" + n, f)
        return f
    return deco

# ------------------------------------------------------------------ setjmp / longjmp ------------------------------
# Own jmp_buf layout (Darwin's is int[48] = 192 bytes; we use 168): x19..x28, x29, x30, sp, d8..d15.
_CALLEE = [UC_ARM64_REG_X19 + i for i in range(10)] + [UC_ARM64_REG_FP, UC_ARM64_REG_LR, UC_ARM64_REG_SP]
_DREGS = [UC_ARM64_REG_D8 + i for i in range(8)]
def _setjmp(e):
    uc, buf = e.uc, e.arg(0)
    e.write(buf, b"".join((uc.reg_read(r) & M64).to_bytes(8, "little") for r in _CALLEE + _DREGS))
    return 0
def _longjmp(e):
    uc, buf, val = e.uc, e.arg(0), e.arg(1) & 0xffffffff
    raw = bytes(e.read(buf, 8 * (len(_CALLEE) + len(_DREGS))))
    for i, r in enumerate(_CALLEE + _DREGS): uc.reg_write(r, int.from_bytes(raw[8 * i: 8 * i + 8], "little"))
    uc.reg_write(UC_ARM64_REG_X0, val or 1)
    # x30 now holds setjmp's return address; the stub's own `ret` (or the PC write below) resumes right after the setjmp call
    uc.reg_write(UC_ARM64_REG_PC, int.from_bytes(raw[8 * 11: 8 * 12], "little"))
for _n in ("setjmp", "_setjmp", "sigsetjmp"): FUNCS.setdefault("_" + _n, _setjmp)
for _n in ("longjmp", "_longjmp", "siglongjmp"): FUNCS.setdefault("_" + _n, _longjmp)

# ------------------------------------------------------------------ libc odds and ends -----------------------------
@fn("memset_pattern16")
def _msp16(e):
    p = bytes(e.read(e.arg(1), 16)); n = e.arg(2); e.write(e.arg(0), (p * (n // 16 + 1))[:n])
@fn("memset_pattern8")
def _msp8(e):
    p = bytes(e.read(e.arg(1), 8)); n = e.arg(2); e.write(e.arg(0), (p * (n // 8 + 1))[:n])
@fn("memset_pattern4")
def _msp4(e):
    p = bytes(e.read(e.arg(1), 4)); n = e.arg(2); e.write(e.arg(0), (p * (n // 4 + 1))[:n])
@fn("__clear_cache")
def _cc(e): return None
@fn("difftime")
def _difftime(e): e.ret_double(float(hle.s64(e.arg(0)) - hle.s64(e.arg(1)))); return None

def _tm(e, t, utc):
    st = time.gmtime(t) if utc else time.localtime(t)
    p = getattr(e, "_tm_buf", None) or e.malloc(64); e._tm_buf = p
    e.write(p, struct.pack("<9iqq", st.tm_sec, st.tm_min, st.tm_hour, st.tm_mday, st.tm_mon - 1, st.tm_year - 1900,
                           (st.tm_wday + 1) % 7, st.tm_yday - 1, max(st.tm_isdst, 0), 0, 0)[:56])
    return p
fn("gmtime")(lambda e: _tm(e, hle.s64(int.from_bytes(e.read(e.arg(0), 8), "little")), True))
fn("localtime")(lambda e: _tm(e, hle.s64(int.from_bytes(e.read(e.arg(0), 8), "little")), False))
fn("mkstemp")(lambda e: M64)
fn("tmpfile")(lambda e: 0)
fn("popen")(lambda e: 0)
fn("pclose")(lambda e: M64)
fn("system")(lambda e: M64)
fn("setitimer")(lambda e: 0)
fn("utime")(lambda e: 0)
fn("freopen")(lambda e: 0)
fn("fscanf")(lambda e: M64)

# NSSearchPathForDirectoriesInDomains: a one-element enumeration is enough for save-game directories
_NSDIRS = {1: "Applications", 5: "Library", 9: "Documents", 12: "Library/Caches", 14: "Library/Application Support", 15: "Downloads"}
@fn("NSStartSearchPathEnumeration")
def _nsstart(e):
    return (e.arg(0) & 0xffff) | 0x10000 | ((e.arg(1) & 0xffff) << 20)          # opaque state: dir id + "not yet returned"
@fn("NSGetNextSearchPathEnumeration")
def _nsnext(e):
    st, buf = e.arg(0), e.arg(1)
    if not (st & 0x10000): return 0
    d = _NSDIRS.get(st & 0xffff, "Library/Application Support")
    path = os.path.join(os.path.expanduser("~"), d) if d != "Applications" else "/Applications"
    e.write(buf, path.encode() + b"\0")
    return st & ~0x10000

# ------------------------------------------------------------------ float math --------------------------------------
def _f32(e, i=0): return struct.unpack("<f", struct.pack("<I", e.uc.reg_read(UC_ARM64_REG_D0 + i) & 0xffffffff))[0]
def _setf(e, v):
    try: b = struct.unpack("<I", struct.pack("<f", v))[0]
    except OverflowError: b = struct.unpack("<I", struct.pack("<f", math.copysign(math.inf, v)))[0]
    e.uc.reg_write(UC_ARM64_REG_D0, b)
def _safe(f, *a):
    try: return f(*a)
    except (ValueError, OverflowError, ZeroDivisionError): return math.nan
def _rnd(v): return math.copysign(float(math.floor(abs(v) + 0.5)), v) if math.isfinite(v) else v
FUNCS.setdefault("_ldexpf", lambda e: _setf(e, _safe(math.ldexp, _f32(e), hle.s32(e.arg(0)))))
FUNCS.setdefault("_scalbnf", lambda e: _setf(e, _safe(math.ldexp, _f32(e), hle.s32(e.arg(0)))))
FUNCS.setdefault("_scalbn", lambda e: e.ret_double(_safe(math.ldexp, e.darg(0), hle.s32(e.arg(0)))))
FUNCS.setdefault("_ldexp", lambda e: e.ret_double(_safe(math.ldexp, e.darg(0), hle.s32(e.arg(0)))))
for _n, _f in [("sinf", math.sin), ("cosf", math.cos), ("tanf", math.tan), ("sqrtf", math.sqrt), ("expf", math.exp),
               ("logf", math.log), ("floorf", math.floor), ("ceilf", math.ceil), ("fabsf", math.fabs), ("atanf", math.atan),
               ("asinf", math.asin), ("acosf", math.acos), ("log2f", math.log2), ("log10f", math.log10), ("exp2f", lambda v: 2.0 ** v),
               ("truncf", math.trunc), ("roundf", _rnd), ("rintf", lambda v: float(round(v))), ("cbrtf", lambda v: math.copysign(abs(v) ** (1 / 3), v)),
               ("sinhf", math.sinh), ("coshf", math.cosh), ("tanhf", math.tanh)]:
    FUNCS.setdefault("_" + _n, (lambda f: lambda e: _setf(e, _safe(f, _f32(e))))(_f))
for _n, _f in [("powf", math.pow), ("atan2f", math.atan2), ("fmodf", math.fmod), ("fmaxf", max), ("fminf", min),
               ("copysignf", math.copysign), ("hypotf", math.hypot), ("remainderf", math.remainder)]:
    FUNCS.setdefault("_" + _n, (lambda f: lambda e: _setf(e, _safe(f, _f32(e, 0), _f32(e, 1))))(_f))
for _n, _f in [("asin", math.asin), ("acos", math.acos), ("log2", math.log2), ("log10", math.log10), ("exp2", lambda v: 2.0 ** v),
               ("sinh", math.sinh), ("cosh", math.cosh), ("tanh", math.tanh), ("round", _rnd), ("trunc", math.trunc),
               ("rint", lambda v: float(round(v))), ("cbrt", lambda v: math.copysign(abs(v) ** (1 / 3), v)), ("nearbyint", lambda v: float(round(v)))]:
    FUNCS.setdefault("_" + _n, (lambda f: lambda e: e.ret_double(_safe(f, e.darg(0))))(_f))
for _n, _f in [("atan2", math.atan2), ("fmod", math.fmod), ("fmax", max), ("fmin", min), ("copysign", math.copysign),
               ("hypot", math.hypot), ("remainder", math.remainder)]:
    FUNCS.setdefault("_" + _n, (lambda f: lambda e: e.ret_double(_safe(f, e.darg(0), e.darg(1))))(_f))
def _frexp(e):
    m, ex = math.frexp(e.darg(0)); e.write(e.arg(0), struct.pack("<i", ex)); e.ret_double(m)
FUNCS.setdefault("_frexp", _frexp)
def _frexpf(e):
    m, ex = math.frexp(_f32(e)); e.write(e.arg(0), struct.pack("<i", ex)); _setf(e, m)
FUNCS.setdefault("_frexpf", _frexpf)
def _modf(e):
    f, i = math.modf(e.darg(0)); e.write(e.arg(0), struct.pack("<d", i)); e.ret_double(f)
FUNCS.setdefault("_modf", _modf)
FUNCS.setdefault("_lrintf", lambda e: int(round(_f32(e))) & M64)
FUNCS.setdefault("_lrint", lambda e: int(round(e.darg(0))) & M64)
FUNCS.setdefault("_lroundf", lambda e: int(_rnd(_f32(e))) & M64)
FUNCS.setdefault("_lround", lambda e: int(_rnd(e.darg(0))) & M64)

# ------------------------------------------------------------------ <ctype.h> tables --------------------------------
# Apple's isalpha()/toupper()... macros read _DefaultRuneLocale.__runetype[c] directly.
_A, _C, _D, _G, _L, _P, _S, _U, _X, _B, _R = 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000, 0x40000
def _rune_locale(e):
    if getattr(e, "_rune", 0): return e._rune
    blob = bytearray(0x43c + 0x400 * 2 + 16)
    blob[0:8] = b"RuneMagi"; blob[8:13] = b"UTF-8"
    for c in range(256):
        f = 0
        if c < 128:
            ch = chr(c)
            if ch.isalpha(): f |= _A | _G | _R
            if ch.islower(): f |= _L
            if ch.isupper(): f |= _U
            if ch.isdigit(): f |= _D | _G | _R | _X | (c - 48)
            if ch in "abcdefABCDEF": f |= _X | _G | _R | (10 + "abcdef".index(ch.lower()))
            if ch in " \t\n\v\f\r": f |= _S
            if ch in " \t": f |= _B
            if c < 32 or c == 127: f |= _C
            if 32 <= c < 127: f |= _R
            if 33 <= c < 127 and not ch.isalnum(): f |= _P | _G
            if ch == " ": f |= _R
        struct.pack_into("<I", blob, 0x3c + 4 * c, f)
        struct.pack_into("<i", blob, 0x43c + 4 * c, ord(chr(c).lower()) if c < 128 else c)
        struct.pack_into("<i", blob, 0x83c + 4 * c, ord(chr(c).upper()) if c < 128 else c)
    p = e.malloc(len(blob)); e.write(p, bytes(blob)); e._rune = p; return p
hle.RESOLVERS.append(lambda e, name: _rune_locale(e) if name == "__DefaultRuneLocale" else None)

# ------------------------------------------------------------------ SteamAPI stand-ins ------------------------------
# No Steam client: init fails cleanly (0/false); context accessors hand back a zeroed context so null interface pointers are
# at least readable. A game that checks SteamAPI_Init's result (they all do) simply runs without Steam.
for _n in ("SteamInternal_SteamAPI_Init", "SteamAPI_InitFlat", "SteamAPI_Init", "SteamAPI_IsSteamRunning", "SteamAPI_RestartAppIfNecessary",
           "SteamAPI_GetHSteamPipe", "SteamAPI_GetHSteamUser", "SteamAPI_ISteamUser_GetSteamID", "SteamAPI_ManualDispatch_Init",
           "SteamAPI_ManualDispatch_RunFrame", "SteamAPI_ManualDispatch_GetNextCallback", "SteamAPI_ManualDispatch_FreeLastCallback",
           "SteamAPI_ManualDispatch_GetAPICallResult", "SteamInternal_FindOrCreateUserInterface"):
    FUNCS.setdefault("_" + _n, lambda e: 0)
for _n in ("SteamAPI_Shutdown", "SteamAPI_ReleaseCurrentThreadMemory"):
    FUNCS.setdefault("_" + _n, lambda e: None)
FUNCS.setdefault("_SteamInternal_ContextInit", lambda e: e.arg(0) + 16)       # {pfn, counter, ctx...}: return &ctx, never call pfn
for _n in ("_Z27SteamInternal_Init_SteamUGCPP9ISteamUGC", "_Z28SteamInternal_Init_SteamUserPP10ISteamUser",
           "_Z29SteamInternal_Init_SteamUtilsPP11ISteamUtils", "_Z31SteamInternal_Init_SteamFriendsPP13ISteamFriends",
           "_Z33SteamInternal_Init_SteamUserStatsPP15ISteamUserStats"):
    FUNCS.setdefault("_" + _n, lambda e: None)
def _terminate(e): sys.stderr.write("[arm2x86] std::terminate called (an unsupported C++ exception was thrown)\n"); e.exit(134)
FUNCS.setdefault("__ZSt9terminatev", _terminate)

# ------------------------------------------------------------------ libc++ streambuf / istream over GUEST virtuals ----
# spaghetti_celesti defines its own std::streambuf subclass(es) and reads data through std::istream. Those classes override
# underflow/overflow/seekoff themselves; the *defaults* they inherit (xsgetn, uflow, xsputn, ...) and basic_istream's
# members are what libc++.dylib would have supplied. Virtual slots (Itanium, libc++ order): seekoff 0x20, xsgetn 0x40,
# underflow 0x48, uflow 0x50, xsputn 0x60, overflow 0x68. streambuf: eback 0x10 gptr 0x18 egptr 0x20 pbase 0x28 pptr 0x30 epptr 0x38.
# basic_ios sits at this+[vptr-24]: rdstate +0x20, rdbuf +0x28. istream: gcount at +8. eof=2 fail=4 bad=1.
SB = "_ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE"
IS = "_ZNSt3__113basic_istreamIcNS_11char_traitsIcEEE"
def _u64(e, a): return int.from_bytes(e.read(a, 8), "little")
def _u32(e, a): return int.from_bytes(e.read(a, 4), "little")
def _w64(e, a, v): e.write(a, (v & M64).to_bytes(8, "little"))
def _w32(e, a, v): e.write(a, (v & 0xffffffff).to_bytes(4, "little"))
def _vslot(e, obj, off): return _u64(e, _u64(e, obj) + off)
def _ios(e, this): return this + hle.s64(_u64(e, _u64(e, this) - 24))
def _setstate(e, ios, bits): _w32(e, ios + 0x20, _u32(e, ios + 0x20) | bits)

def _sb_ctor(e):
    this = e.arg(0); e.write(this + 8, b"\0" * 0x38); return this
FUNCS["_" + SB + "C2Ev"] = _sb_ctor; FUNCS["_" + SB + "C1Ev"] = _sb_ctor
FUNCS["_" + SB + "D2Ev"] = lambda e: e.arg(0); FUNCS["_" + SB + "D1Ev"] = lambda e: e.arg(0)
FUNCS["_" + SB + "4syncEv"] = lambda e: 0
FUNCS["_" + SB + "9showmanycEv"] = lambda e: 0
FUNCS["_" + SB + "5imbueERKNS_6localeE"] = lambda e: None
FUNCS["_" + SB + "6setbufEPcl"] = lambda e: e.arg(0)
def _sb_swap(e):
    a, b = e.arg(0), e.arg(1); x, y = bytes(e.read(a + 8, 0x38)), bytes(e.read(b + 8, 0x38)); e.write(a + 8, y); e.write(b + 8, x)
FUNCS["_" + SB + "4swapERS3_"] = _sb_swap

def _xsgetn(e):
    this, s, n = e.arg(0), e.arg(1), hle.s64(e.arg(2))
    def g():
        total = 0
        while total < n:
            gp, eg = _u64(e, this + 0x18), _u64(e, this + 0x20)
            if eg > gp:
                k = min(eg - gp, n - total); e.write(s + total, bytes(e.read(gp, k))); _w64(e, this + 0x18, gp + k); total += k
            else:
                c = hle.s32((yield (_vslot(e, this, 0x50), [this])))          # virtual uflow()
                if c == -1: break
                e.write(s + total, bytes([c & 0xff])); total += 1
        return total
    e.begin_gen(g()); return None
FUNCS["_" + SB + "6xsgetnEPcl"] = _xsgetn

def _uflow(e):
    this = e.arg(0)
    def g():
        c = hle.s32((yield (_vslot(e, this, 0x48), [this])))                  # virtual underflow()
        if c == -1: return 0xffffffff
        gp = _u64(e, this + 0x18); ch = e.read(gp, 1)[0]; _w64(e, this + 0x18, gp + 1); return ch
    e.begin_gen(g()); return None
FUNCS["_" + SB + "5uflowEv"] = _uflow

def _xsputn(e):
    this, s, n = e.arg(0), e.arg(1), hle.s64(e.arg(2))
    def g():
        total = 0
        while total < n:
            pp, ep = _u64(e, this + 0x30), _u64(e, this + 0x38)
            if ep > pp:
                k = min(ep - pp, n - total); e.write(pp, bytes(e.read(s + total, k))); _w64(e, this + 0x30, pp + k); total += k
            else:
                c = hle.s32((yield (_vslot(e, this, 0x68), [this, e.read(s + total, 1)[0]])))   # virtual overflow(c)
                if c == -1: break
                total += 1
        return total
    e.begin_gen(g()); return None
FUNCS["_" + SB + "6xsputnEPKcl"] = _xsputn

def _sbumpc(e, sb):
    """generator: next byte of streambuf sb or -1 (inline sbumpc: take from the get area, else virtual uflow)"""
    gp, eg = _u64(e, sb + 0x18), _u64(e, sb + 0x20)
    if gp < eg:
        c = e.read(gp, 1)[0]; _w64(e, sb + 0x18, gp + 1); return c
    return hle.s32((yield (_vslot(e, sb, 0x50), [sb])))

def _istream_read(e):
    this, s, n = e.arg(0), e.arg(1), hle.s64(e.arg(2))
    def g():
        ios = _ios(e, this); _w64(e, this + 8, 0)
        if _u32(e, ios + 0x20): _setstate(e, ios, 4); return this
        sb = _u64(e, ios + 0x28)
        got = hle.s64((yield (_vslot(e, sb, 0x40), [sb, s, n])))               # sgetn -> virtual xsgetn
        _w64(e, this + 8, got)
        if got != n: _setstate(e, ios, 6)
        return this
    e.begin_gen(g()); return None
FUNCS["_" + IS + "4readEPcl"] = _istream_read

def _istream_get(e):
    this = e.arg(0)
    def g():
        ios = _ios(e, this); _w64(e, this + 8, 0)
        if _u32(e, ios + 0x20): _setstate(e, ios, 4); return 0xffffffff
        c = yield from _sbumpc(e, _u64(e, ios + 0x28))
        if c == -1: _setstate(e, ios, 6); return 0xffffffff
        _w64(e, this + 8, 1); return c
    e.begin_gen(g()); return None
FUNCS["_" + IS + "3getEv"] = _istream_get

def _istream_ignore(e):
    this, n, delim = e.arg(0), hle.s64(e.arg(1)), hle.s32(e.arg(2))
    def g():
        ios = _ios(e, this); _w64(e, this + 8, 0)
        if _u32(e, ios + 0x20): _setstate(e, ios, 4); return this
        sb = _u64(e, ios + 0x28); cnt = 0
        while n == 0x7fffffffffffffff or cnt < n:
            c = yield from _sbumpc(e, sb)
            if c == -1: _setstate(e, ios, 2); break
            cnt += 1
            if delim != -1 and c == (delim & 0xff): break
        _w64(e, this + 8, cnt); return this
    e.begin_gen(g()); return None
FUNCS["_" + IS + "6ignoreEli"] = _istream_ignore

def _istream_seekg(e):                                   # seekg(off_type, seekdir)
    this, off, d = e.arg(0), hle.s64(e.arg(1)), e.arg(2) & 0xffffffff
    def g():
        ios = _ios(e, this)
        _w32(e, ios + 0x20, _u32(e, ios + 0x20) & ~2)                         # sentry clears eofbit
        if _u32(e, ios + 0x20) & 5: return this
        sb = _u64(e, ios + 0x28); buf = e.malloc(160); e.write(buf, b"\0" * 160)
        e.uc.reg_write(UC_ARM64_REG_X8, buf)                                    # pos_type (fpos<mbstate_t>) comes back via sret
        yield (_vslot(e, sb, 0x20), [sb, off, d, 8])                            # virtual seekoff(off, dir, ios_base::in)
        if hle.s64(_u64(e, buf + 128)) == -1: _setstate(e, ios, 4)
        return this
    e.begin_gen(g()); return None
FUNCS["_" + IS + "5seekgExNS_8ios_base7seekdirE"] = _istream_seekg
for _d in ("D0Ev", "D1Ev", "D2Ev"):
    FUNCS.setdefault("_" + IS + _d, lambda e: e.arg(0))
