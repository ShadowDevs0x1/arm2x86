"""
libc++ iostream emulation + the 'unimplemented import' fallback policy for C++.

Apple's arm64 C++ ABI: constructors and destructors RETURN `this` in x0, and operator<< / operator= return
the stream/object reference. The old generic fallback (x0 = 0) therefore made the guest use a NULL object
right after an unimplemented ctor (e.g. basic_streambuf::basic_streambuf) -> UC_ERR_WRITE_UNMAPPED.

Now:
  * ctors/dtors/operator=/<</>> that we don't emulate leave x0 untouched (return this)
  * std::cout / cerr / clog / endl / flush / operator<< on them really print (to fd 1 / 2)
  * other streams (stringstream, ofstream, ...) are not emulated: writes are ignored but chaining works
"""
import os, re, struct, sys
from unicorn.arm64_const import *
import hle, libcxx
from hle import FUNCS, DATA, M64, s32, s64

for _n in ("cout", "cerr", "clog", "cin"):          # only their ADDRESS matters (we recognise the std streams by it)
    DATA["__ZNSt3__14%sE" % _n] = 0

OS = "NSt3__113basic_ostreamIcNS_11char_traitsIcEEE"
ENDL  = "__ZNSt3__14endlIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_"
FLUSH = "__ZNSt3__15flushIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_"
ENDS  = "__ZNSt3__14endsIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_"

def fd_for(e, p):
    for nm, fd in (("cout", 1), ("cerr", 2), ("clog", 2)):
        if p == e.resolve("__ZNSt3__14%sE" % nm): return fd
    return None
def emit(e, os_ptr, data):
    fd = fd_for(e, os_ptr)
    if fd is not None and data:
        os.write(fd, data if isinstance(data, bytes) else data.encode("latin-1", "replace"))
    return os_ptr                                       # operator<< returns the stream (this)
def f32(e): return struct.unpack("<f", struct.pack("<I", e.uc.reg_read(UC_ARM64_REG_D0) & 0xffffffff))[0]
def g(v): return ("%g" % v)                             # default ostream float formatting (precision 6, %g)

# ---- ios_base::Init (static init of <iostream>) and friends: no-ops that return this
for _s in ("C1Ev", "C2Ev", "D1Ev", "D2Ev"):
    FUNCS.setdefault("__ZNSt3__18ios_base4Init" + _s, lambda e: e.arg(0))
FUNCS.setdefault("__ZNSt3__18ios_base4initEPv", lambda e: None)

# ---- manipulators
FUNCS.setdefault(ENDL,  lambda e: emit(e, e.arg(0), b"\n"))
FUNCS.setdefault(ENDS,  lambda e: emit(e, e.arg(0), b"\0"))
FUNCS.setdefault(FLUSH, lambda e: e.arg(0))
FUNCS.setdefault("__Z" + OS + "5flushEv", lambda e: e.arg(0))
FUNCS.setdefault("__Z" + OS + "3putEc", lambda e: emit(e, e.arg(0), bytes([e.arg(1) & 0xff])))
FUNCS.setdefault("__Z" + OS + "5writeEPKcl", lambda e: emit(e, e.arg(0), bytes(e.read(e.arg(1), e.arg(2)))))

# ---- libc++'s internal helper behind operator<<(ostream&, const char*) / (ostream&, const string&)
FUNCS.setdefault("__ZNSt3__124__put_character_sequenceIcNS_11char_traitsIcEEEERNS_13basic_ostreamIT_T0_EES7_PKS4_m",
                 lambda e: emit(e, e.arg(0), bytes(e.read(e.arg(1), e.arg(2)))))

# ---- member operator<<(arithmetic): basic_ostream::operator<<(int) ... ; name = ls + mangled param type
def _mk(conv):
    return lambda e: emit(e, e.arg(0), conv(e))
for _t, _c in {
    "i": lambda e: str(s32(e.arg(1))),         "j": lambda e: str(e.arg(1) & 0xffffffff),
    "l": lambda e: str(s64(e.arg(1))),         "m": lambda e: str(e.arg(1) & M64),
    "x": lambda e: str(s64(e.arg(1))),         "y": lambda e: str(e.arg(1) & M64),
    "s": lambda e: str(((e.arg(1) & 0xffff) ^ 0x8000) - 0x8000), "t": lambda e: str(e.arg(1) & 0xffff),
    "b": lambda e: str(int(bool(e.arg(1) & 0xff))),
    "d": lambda e: g(e.darg(0)),               "f": lambda e: g(f32(e)),
    "PKv": lambda e: "0x%x" % e.arg(1),
}.items():
    FUNCS.setdefault("__Z" + OS + "lsE" + _t, _mk(_c))

# ---- policy for names with no emulation --------------------------------------------------------------------
_THIS = re.compile(r"^__ZN.*(C[12]E|D[012]E)")      # constructors / destructors (Itanium C1/C2/D0/D1/D2)
def returns_this(name):
    if _THIS.match(name): return True
    # operator= (aS), +=(pL), <<(ls), >>(rs) on a member / non-member taking the object first -> returns it
    return bool(re.match(r"^__ZN.*(aSE|pLE|lsE|rsE)", name)) or name.startswith(("__ZNSt3__1ls", "__ZNSt3__1rs"))

def fallback(e, name):
    """Called for an import with no emulation. Return hle.KEEP (leave x0), an int (new x0), or None (not handled)."""
    # non-member operator<<(ostream&, X) : decide X from the tail of the mangled name
    if name.startswith("__ZNSt3__1ls") and "basic_ostream" in name:
        os_p = e.arg(0)
        if name.endswith("PKc"):                        return emit(e, os_p, e.cstr_bytes(e.arg(1)))
        if re.search(r"_c$", name) or name.endswith("Ec") or name.endswith("EEc"):
            return emit(e, os_p, bytes([e.arg(1) & 0xff]))
        if "basic_string" in name and name.endswith("E"):   # (ostream&, const std::string&)
            return emit(e, os_p, libcxx.str_get(e, e.arg(1)))
        return os_p
    # member operator<<(manipulator function pointer): endl / flush / ends passed as &func
    if name.startswith("__Z" + OS) and "lsEPF" in name:
        fp = e.arg(1)
        if fp == e.resolve(ENDL):  return emit(e, e.arg(0), b"\n")
        if fp == e.resolve(ENDS):  return emit(e, e.arg(0), b"\0")
        return e.arg(0)
    if returns_this(name): return hle.KEEP
    return None
hle.FALLBACKS.append(fallback)

# ======================================================================================================
# Real std::cout / cerr / clog / cin objects. The game's own inlined code (__put_character_sequence,
# __pad_and_output) reads these fields directly, so they must look like libc++ objects (Apple arm64):
#   obj+0x00 vptr -> vtable, with vbase offset at vptr-0x18 (0 here: basic_ios is placed at the object start)
#   ios: +0x08 fmtflags(4)  +0x10 precision  +0x18 width  +0x20 rdstate  +0x28 rdbuf*  +0x90 fill char
#   streambuf vtable slots: +0x30 sync, +0x60 xsputn(this,s,n), +0x68 overflow(this,c)
# Our streambuf keeps the host fd at +0x40; its virtual functions are Python stubs.
# ======================================================================================================
def _sb_xsputn(e):
    fd = int.from_bytes(e.read(e.arg(0) + 0x40, 8), "little"); n = e.arg(2)
    if n: os.write(fd, bytes(e.read(e.arg(1), n)))
    return n
def _sb_overflow(e):
    fd = int.from_bytes(e.read(e.arg(0) + 0x40, 8), "little"); c = e.arg(1) & 0xff
    os.write(fd, bytes([c])); return c
FUNCS["__arm2x86_sb_xsputn"] = _sb_xsputn
FUNCS["__arm2x86_sb_overflow"] = _sb_overflow
FUNCS["__arm2x86_sb_sync"] = lambda e: 0
FUNCS["__arm2x86_nop_this"] = lambda e: None           # leaves x0 (this) alone: dtors, misc virtuals
_STDOBJ, _STDFD = {}, {"cout": 1, "cerr": 2, "clog": 2, "cin": 0}
def _w(e, a, v, n=8): e.write(a, int(v).to_bytes(n, "little"))
def std_stream(e, nm):
    if nm in _STDOBJ: return _STDOBJ[nm]
    nop = e.resolve("__arm2x86_nop_this")
    sbvt = e.malloc(0x80); e.write(sbvt, b"\0" * 0x80)
    for off in range(0, 0x80, 8): _w(e, sbvt + off, nop)
    _w(e, sbvt + 0x30, e.resolve("__arm2x86_sb_sync")); _w(e, sbvt + 0x60, e.resolve("__arm2x86_sb_xsputn"))
    _w(e, sbvt + 0x68, e.resolve("__arm2x86_sb_overflow"))
    sb = e.malloc(0x60); e.write(sb, b"\0" * 0x60); _w(e, sb, sbvt); _w(e, sb + 0x40, _STDFD[nm])
    osvt = e.malloc(0x60); e.write(osvt, b"\0" * 0x60)
    for off in range(0x18, 0x60, 8): _w(e, osvt + off, nop)        # vptr = osvt+0x18; [vptr-0x18] vbase offset = 0
    obj = e.malloc(0xb0); e.write(obj, b"\0" * 0xb0)
    _w(e, obj, osvt + 0x18); _w(e, obj + 8, 0x1010, 4); _w(e, obj + 0x10, 6); _w(e, obj + 0x28, sb); _w(e, obj + 0x90, 0x20, 4)
    _STDOBJ[nm] = obj; return obj
def _std_resolver(e, name):
    for nm in _STDFD:
        if name == "__ZNSt3__14%sE" % nm: return std_stream(e, nm)
    return None
hle.RESOLVERS.append(_std_resolver)

# sentry: byte 0 is __ok_; the destructor would flush only if unitbuf is set
FUNCS["__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_"] = lambda e: (e.write(e.arg(0), b"\1" + b"\0" * 7), e.write(e.arg(0) + 8, e.arg(1).to_bytes(8, "little")), e.arg(0))[2]
FUNCS["__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryD1Ev"] = lambda e: e.arg(0)
FUNCS["__ZNSt3__18ios_base5clearEj"] = lambda e: None

# ---- locale / ctype<char> facet: enough for inlined std::endl -> os.widen('\n')
#   getloc() returns a locale BY VALUE (non-trivial dtor => sret in x8); use_facet(locale*, id&) returns the facet.
#   The game calls  facet->widen(c)  as virtual slot +0x38 (ctype::do_widen(char)).
_LOC = {}
FUNCS["__arm2x86_ctype_widen"] = lambda e: e.arg(1) & 0xff
FUNCS["__arm2x86_ctype_narrow"] = lambda e: e.arg(1) & 0xff
def _ctype_obj(e):
    if "ctype" not in _LOC:
        nop, wid = e.resolve("__arm2x86_nop_this"), e.resolve("__arm2x86_ctype_widen")
        vt = e.malloc(0x100); e.write(vt, b"\0" * 0x100)
        for off in range(0, 0x100, 8): _w(e, vt + off, nop)
        for off in (0x38, 0x40, 0x48): _w(e, vt + off, wid)          # do_widen variants
        _w(e, vt + 0x50, e.resolve("__arm2x86_ctype_narrow")); _w(e, vt + 0x58, e.resolve("__arm2x86_ctype_narrow"))
        obj = e.malloc(0x40); e.write(obj, b"\0" * 0x40); _w(e, obj, vt)
        impl = e.malloc(0x40); e.write(impl, b"\0" * 0x40)
        _LOC["ctype"], _LOC["impl"] = obj, impl
    return _LOC["ctype"]
def _getloc(e):
    _ctype_obj(e); e.write(e.uc.reg_read(UC_ARM64_REG_X8), _LOC["impl"].to_bytes(8, "little")); return None
def _use_facet(e):
    obj = _ctype_obj(e)
    if e.arg(1) != e.resolve("__ZNSt3__15ctypeIcE2idE") and not _LOC.get("warned"):
        _LOC["warned"] = 1; sys.stderr.write("[arm2x86] use_facet for a non-ctype<char> facet: returning ctype<char> anyway\n")
    return obj
FUNCS["__ZNKSt3__18ios_base6getlocEv"] = _getloc
FUNCS["__ZNKSt3__16locale9use_facetERNS0_2idE"] = _use_facet
FUNCS["__ZNKSt3__16locale9has_facetERNS0_2idE"] = lambda e: 1
FUNCS["__ZNSt3__16localeC1ERKS0_"] = lambda e: (e.write(e.arg(0), bytes(e.read(e.arg(1), 8))), e.arg(0))[1]
FUNCS["__ZNSt3__16localeD1Ev"] = lambda e: e.arg(0)
