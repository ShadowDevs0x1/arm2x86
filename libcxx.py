"""
Minimal libc++ (std::__1) emulation. std::string uses the layout Apple's arm64 libc++ actually emits
(verified by disassembling the game: it tests the sign bit of byte 23 to tell long from short):
  short: chars at +0 (max 22), size in byte 23 (top bit clear)
  long : [+0] data pointer, [+8] size, [+16] allocated capacity | 1<<63
The game's inlined code (c_str(), size(), ~string()) reads this layout directly, so we must match it.
"""
import struct
from unicorn.arm64_const import *
from hle import fn, FUNCS, M64, s32, s64

LONG = 1 << 63
def _is_long(e, p): return e.read(p + 23, 1)[0] & 0x80

def str_get(e, p):
    if _is_long(e, p):
        data, size = struct.unpack("<QQ", bytes(e.read(p, 16)))
        return bytes(e.read(data, size))
    return bytes(e.read(p, e.read(p + 23, 1)[0]))

def str_set(e, p, data):
    n = len(data)
    if n <= 22:
        e.write(p, data + b"\0" * (23 - n) + bytes([n])); return
    if _is_long(e, p):
        olddata, _, cap = struct.unpack("<QQQ", bytes(e.read(p, 24))); oldcap = (cap & ~LONG) - 1
        if n <= oldcap:
            e.write(olddata, data + b"\0"); e.write(p + 8, struct.pack("<Q", n)); return
    else:
        oldcap = 22
    alloc = max((n + 1 + 15) & ~15, 2 * oldcap)
    buf = e.malloc(alloc); e.write(buf, data + b"\0")
    e.write(p, struct.pack("<QQQ", buf, n, alloc | LONG))

def sret(e): return e.uc.reg_read(UC_ARM64_REG_X8)

@fn("_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc")
def _append(e): this = e.arg(0); str_set(e, this, str_get(e, this) + e.cstr_bytes(e.arg(1))); return this
@fn("_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm")
def _append_n(e): this = e.arg(0); str_set(e, this, str_get(e, this) + bytes(e.read(e.arg(1), e.arg(2)))); return this
@fn("_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmPKc")
def _insert(e):
    this, pos = e.arg(0), e.arg(1); cur = str_get(e, this)
    str_set(e, this, cur[:pos] + e.cstr_bytes(e.arg(2)) + cur[pos:]); return this
@fn("_ZNSt3__19to_stringEi")
def _to_string_i(e): str_set(e, sret(e), str(s32(e.arg(0))).encode())
@fn("_ZNSt3__19to_stringEl", "_ZNSt3__19to_stringEx")
def _to_string_l(e): str_set(e, sret(e), str(s64(e.arg(0))).encode())
@fn("_ZNSt3__19to_stringEj", "_ZNSt3__19to_stringEm", "_ZNSt3__19to_stringEy")
def _to_string_u(e): str_set(e, sret(e), str(e.arg(0) & M64).encode())
@fn("_ZNSt3__19to_stringEd")
def _to_string_d(e): str_set(e, sret(e), ("%f" % e.darg(0)).encode())
@fn("_ZNSt3__19to_stringEf")
def _to_string_f(e):
    v = struct.unpack("<f", struct.pack("<I", e.uc.reg_read(UC_ARM64_REG_D0) & 0xffffffff))[0]
    str_set(e, sret(e), ("%f" % v).encode())

@fn("_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_",
    "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSEOS5_")
def _assign(e):
    this, other = e.arg(0), e.arg(1)
    if this != other: str_set(e, this, str_get(e, other))
    return this
@fn("_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSEPKc")
def _assign_c(e):
    this = e.arg(0); str_set(e, this, e.cstr_bytes(e.arg(1))); return this
@fn("_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5clearEv")
def _clear(e):
    str_set(e, e.arg(0), b""); return None

@fn("_Znwm", "_Znam", "_ZnwmRKSt9nothrow_t", "_ZnamRKSt9nothrow_t")
def _new(e): return e.malloc(e.arg(0))
@fn("_ZdlPv", "_ZdaPv", "_ZdlPvm", "_ZdaPvm")
def _delete(e): return None
@fn("__Unwind_Resume", "___cxa_throw", "___cxa_begin_catch", "___cxa_end_catch")
def _unwind(e):
    import sys; sys.stderr.write("[arm2x86] C++ exception unwinding is not supported\n"); e.exit(134)
