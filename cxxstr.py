"""
std::string / std::wstring (libc++, Apple arm64 *alternate* layout) member functions.
Layout (24 bytes): short: chars at +0, size in byte 23 (top bit clear), capacity = 23//w - 1 chars
                   long : [+0] data, [+8] size, [+16] (alloc_units | 1<<63)
w = sizeof(char type): 1 for std::string, 4 for std::wstring.  Everything is done on raw bytes.
"""
import sys, struct, re as _re
from unicorn.arm64_const import UC_ARM64_REG_X8, UC_ARM64_REG_LR
from hle import FUNCS, M64
LONG = 1 << 63
NPOS = M64

def is_long(e, p): return bool(e.read(p + 23, 1)[0] & 0x80)
def short_cap(w): return 23 // w - 1
def sget(e, p, w=1):
    if is_long(e, p):
        d, n = struct.unpack("<QQ", bytes(e.read(p, 16))); return bytes(e.read(d, n * w))
    return bytes(e.read(p, e.read(p + 23, 1)[0] * w))
def sset(e, p, data, w=1, fresh=False):
    n = len(data) // w
    if n <= short_cap(w):
        e.write(p, data + b"\0" * (23 - len(data)) + bytes([n])); return
    oldcap = short_cap(w)
    if not fresh and is_long(e, p):
        od, _, cw = struct.unpack("<QQQ", bytes(e.read(p, 24))); oldcap = (cw & ~LONG) - 1
        if n <= oldcap:
            e.write(od, data + b"\0" * w); e.write(p + 8, struct.pack("<Q", n)); return
    alloc = max(((n + 1) * w + 15) // 16 * 16 // w, 2 * oldcap)
    buf = e.malloc(alloc * w); e.write(buf, data + b"\0" * w)
    e.write(p, struct.pack("<QQQ", buf, n, alloc | LONG))
def data_ptr(e, p): return struct.unpack("<Q", bytes(e.read(p, 8)))[0] if is_long(e, p) else p
def _cstr(e, p, w):
    out = bytearray()
    while True:
        u = bytes(e.read(p + len(out), w))
        if u == b"\0" * w: return bytes(out)
        out += u
def _copy(e, w):
    s = sget(e, e.arg(0), w); n, pos = e.arg(2), e.arg(3); part = s[pos * w:(pos + n) * w]
    e.write(e.arg(1), part); return len(part) // w
def _absurd(e, what, n):
    """An earlier unemulated call produced a garbage length. Say where, and stop cleanly instead of a Python traceback."""
    sys.stderr.write(f"[arm2x86] {what}({n:#x}) with an absurd size: this={e.arg(0):#x} x2={e.arg(2):#x} "
                     f"lr={e.uc.reg_read(UC_ARM64_REG_LR):#x}\n  last calls: {getattr(e, 'last_stubs', [])}\n")
    e.exit(139)

def register(w, cp):
    P, K = "__Z" + cp, "__ZNK" + cp[1:]
    def reg(names, f):
        for n in names.split("|"): FUNCS.setdefault(n, f)
    unit = lambda v: (v & ((1 << (8 * w)) - 1)).to_bytes(w, "little")
    def copy_ctor(e): this = e.arg(0); sset(e, this, sget(e, e.arg(1), w), w, fresh=True); return this
    def sub_ctor(e):
        this, s = e.arg(0), sget(e, e.arg(1), w); pos, n = e.arg(2), e.arg(3)
        sset(e, this, s[pos * w:(pos + n) * w if n != NPOS else None], w, fresh=True); return this
    reg(P + "C1ERKS5_|" + P + "C2ERKS5_", copy_ctor)
    reg(P + "C1ERKS5_mmRKS4_|" + P + "C2ERKS5_mmRKS4_", sub_ctor)
    reg(P + "D1Ev|" + P + "D2Ev", lambda e: e.arg(0))
    reg(P + "aSERKS5_", lambda e: (sset(e, e.arg(0), sget(e, e.arg(1), w), w), e.arg(0))[1])
    def erase(e):
        this = e.arg(0); s = sget(e, this, w); pos, n = e.arg(1), e.arg(2)
        sset(e, this, s[:pos * w] + (s[(pos + n) * w:] if n != NPOS else b""), w); return this
    reg(P + "5eraseEmm", erase)
    def append_n_c(e):
        this = e.arg(0)
        if e.arg(1) > (1 << 31): return _absurd(e, "std::string::append(n, c)", e.arg(1))
        sset(e, this, sget(e, this, w) + unit(e.arg(2)) * e.arg(1), w); return this
    reg(P + "6appendEmc|" + P + "6appendEmw", append_n_c)
    def ins_ptr_n(e):
        this = e.arg(0); s = sget(e, this, w); pos = e.arg(1)
        sset(e, this, s[:pos * w] + bytes(e.read(e.arg(2), e.arg(3) * w)) + s[pos * w:], w); return this
    reg(P + "6insertEmPKcm|" + P + "6insertEmPKwm", ins_ptr_n)
    def ins_ptr(e):
        this = e.arg(0); s = sget(e, this, w); pos = e.arg(1); add = _cstr(e, e.arg(2), w)
        sset(e, this, s[:pos * w] + add + s[pos * w:], w); return this
    reg(P + "6insertEmPKw", ins_ptr)
    def ins_n_c(e):
        this = e.arg(0); s = sget(e, this, w); pos = e.arg(1)
        sset(e, this, s[:pos * w] + unit(e.arg(3)) * e.arg(2) + s[pos * w:], w); return this
    reg(P + "6insertEmmc|" + P + "6insertEmmw", ins_n_c)
    def ins_iter_c(e):
        this = e.arg(0); d = data_ptr(e, this); pos = (e.arg(1) - d) // w; s = sget(e, this, w)
        sset(e, this, s[:pos * w] + unit(e.arg(2)) + s[pos * w:], w); return data_ptr(e, this) + pos * w
    reg(P + "6insertENS_11__wrap_iterIPKcEEc|" + P + "6insertENS_11__wrap_iterIPKwEEw", ins_iter_c)
    def resize(e):
        this = e.arg(0); s = sget(e, this, w); n = e.arg(1)
        if n > (1 << 31): return _absurd(e, "std::string::resize", n)
        sset(e, this, s[:n * w] if n <= len(s) // w else s + unit(e.arg(2)) * (n - len(s) // w), w)
    reg(P + "6resizeEmc|" + P + "6resizeEmw", resize)
    def replace_ptr(e):
        this = e.arg(0); s = sget(e, this, w); pos, n1 = e.arg(1), e.arg(2)
        sset(e, this, s[:pos * w] + bytes(e.read(e.arg(3), e.arg(4) * w)) + s[(pos + n1) * w:], w); return this
    reg(P + "7replaceEmmPKcm|" + P + "7replaceEmmPKwm", replace_ptr)
    def replace_c(e):
        this = e.arg(0); s = sget(e, this, w); pos, n1 = e.arg(1), e.arg(2)
        sset(e, this, s[:pos * w] + unit(e.arg(4)) * e.arg(3) + s[(pos + n1) * w:], w); return this
    reg(P + "7replaceEmmmc|" + P + "7replaceEmmmw", replace_c)
    reg(P + "6assignEPKw", lambda e: (sset(e, e.arg(0), _cstr(e, e.arg(1), w), w), e.arg(0))[1])
    reg(P + "6appendEPKwm", lambda e: (sset(e, e.arg(0), sget(e, e.arg(0), w) + bytes(e.read(e.arg(1), e.arg(2) * w)), w), e.arg(0))[1])
    reg(P + "9push_backEw", lambda e: sset(e, e.arg(0), sget(e, e.arg(0), w) + unit(e.arg(1)), w))
    def grow_by(e):
        this, old_cap, delta, old_sz, n_copy, n_del, n_add = (e.arg(i) for i in range(7))
        cap = max(old_cap + delta, 2 * old_cap); alloc = max(((cap + 1) * w + 15) // 16 * 16 // w, short_cap(w) + 1)
        old = data_ptr(e, this); buf = e.malloc(alloc * w)
        if n_copy: e.write(buf, bytes(e.read(old, n_copy * w)))
        tail = old_sz - n_del - n_copy
        if tail > 0: e.write(buf + (n_copy + n_add) * w, bytes(e.read(old + (n_copy + n_del) * w, tail * w)))
        e.write(this, struct.pack("<Q", buf)); e.write(this + 16, struct.pack("<Q", alloc | LONG))
    reg(P + "9__grow_byEmmmmmm", grow_by)
    reg(K + "4copyEPcmm", lambda e: _copy(e, w))
    def rfind_ptr(e):
        s = sget(e, e.arg(0), w); pat = bytes(e.read(e.arg(1), e.arg(3) * w)); pos = e.arg(2)
        end = len(s) if pos == NPOS else min(len(s), pos * w + len(pat))
        i = s.rfind(pat, 0, end)
        while i >= 0 and i % w: i = s.rfind(pat, 0, i + len(pat) - 1)
        return NPOS if i < 0 else i // w
    reg(K + "5rfindEPKcmm", rfind_ptr)
    def cmp(a, b): return M64 if a < b else (1 if a > b else 0)
    reg(K + "7compareEPKc", lambda e: cmp(sget(e, e.arg(0), w), _cstr(e, e.arg(1), w)))
    reg(K + "7compareEmmPKc", lambda e: cmp(sget(e, e.arg(0), w)[e.arg(1) * w:(e.arg(1) + e.arg(2)) * w], _cstr(e, e.arg(3), w)))
register(1, "NSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE")
register(4, "NSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEE")

def _sto(bits):
    def f(e):
        s = sget(e, e.arg(0), 1).decode("latin-1"); idxp, base = e.arg(1), (e.arg(2) & 0xffffffff) or 10
        digs = "0123456789abcdefghijklmnopqrstuvwxyz"[:base]
        m = _re.match(r"\s*([+-]?)(0[xX])?([%s]+)" % digs, s, _re.I) if base != 10 else _re.match(r"\s*([+-]?)()(\d+)", s)
        if not m: return 0
        v = int(m.group(3), base) * (-1 if m.group(1) == "-" else 1)
        if idxp: e.write(idxp, struct.pack("<Q", m.end()))
        return v & M64 if bits == 64 else v & 0xffffffff
    return f
_P = "__ZNSt3__1%d%s" + "ERKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEPmi"
for _n, _b in (("stoi", 32), ("stol", 64), ("stoll", 64), ("stoul", 64), ("stoull", 64)):
    FUNCS.setdefault(_P % (len(_n), _n), _sto(_b))
def _plus(e):
    sset(e, e.uc.reg_read(UC_ARM64_REG_X8), _cstr(e, e.arg(0), 1) + sget(e, e.arg(1), 1), 1, fresh=True)
FUNCS.setdefault("__ZNSt3__1plIcNS_11char_traitsIcEENS_9allocatorIcEEEENS_12basic_stringIT_T0_T1_EEPKS6_RKS9_", _plus)

# ---- codecvt_utf8_utf16<wchar_t>: wstring_convert<...>::to_bytes / from_bytes. Every virtual the wrapper can call is
# implemented: an unimplemented do_max_length/do_length/do_unshift returns 0 and makes the caller size its buffers from garbage.
#  do_out(this, mbstate&, const wchar_t* from, from_end, const wchar_t*& from_next, char* to, to_end, char*& to_next)
#  result: 0 ok, 1 partial, 2 error, 3 noconv.  wchar_t is 4 bytes on Darwin; the facet treats units as UTF-16 (surrogate pairs allowed).
CVT = "__ZNKSt3__120__codecvt_utf8_utf16IwE"
def _units(raw):
    return [int.from_bytes(raw[i:i + 4], "little") for i in range(0, len(raw) - len(raw) % 4, 4)]
def _do_out(e):
    frm, fend, pfn, to, tend, ptn = e.arg(2), e.arg(3), e.arg(4), e.arg(5), e.arg(6), e.arg(7)
    units = _units(bytes(e.read(frm, max(fend - frm, 0)))); out = bytearray(); i = 0; res = 0
    while i < len(units):
        u = units[i]; used = 1
        if 0xD800 <= u < 0xDC00 and i + 1 < len(units) and 0xDC00 <= units[i + 1] < 0xE000:
            u = 0x10000 + ((u - 0xD800) << 10) + (units[i + 1] - 0xDC00); used = 2
        elif 0xD800 <= u < 0xE000: res = 2; break
        try: enc = chr(u).encode("utf-8")
        except (ValueError, OverflowError): res = 2; break
        if to + len(out) + len(enc) > tend: res = 1; break
        out += enc; i += used
    if out: e.write(to, bytes(out))
    e.write(pfn, struct.pack("<Q", frm + 4 * i)); e.write(ptn, struct.pack("<Q", to + len(out))); return res
def _utf8_len(b):
    return 1 if b < 0x80 else 2 if b >> 5 == 6 else 3 if b >> 4 == 14 else 4 if b >> 3 == 30 else 0
def _do_in(e):                                         # (this, state&, const char* from, from_end, const char*& from_next, wchar_t* to, to_end, wchar_t*& to_next)
    frm, fend, pfn, to, tend, ptn = e.arg(2), e.arg(3), e.arg(4), e.arg(5), e.arg(6), e.arg(7)
    data = bytes(e.read(frm, max(fend - frm, 0))); out = bytearray(); pos = 0; res = 0
    while pos < len(data):
        ln = _utf8_len(data[pos])
        if ln == 0: res = 2; break
        if pos + ln > len(data): res = 1; break
        try: ch = data[pos:pos + ln].decode("utf-8")
        except UnicodeDecodeError: res = 2; break
        cp = ord(ch); units = [cp] if cp < 0x10000 else [0xD800 + ((cp - 0x10000) >> 10), 0xDC00 + ((cp - 0x10000) & 0x3ff)]
        if to + len(out) + 4 * len(units) > tend: res = 1; break
        for u in units: out += u.to_bytes(4, "little")
        pos += ln
    if out: e.write(to, bytes(out))
    e.write(pfn, struct.pack("<Q", frm + pos)); e.write(ptn, struct.pack("<Q", to + len(out))); return res
def _do_length(e):                                     # (this, state&, const char* frm, const char* end, size_t mx) -> bytes consumed
    frm, fend, mx = e.arg(2), e.arg(3), e.arg(4)
    data = bytes(e.read(frm, max(fend - frm, 0))); pos = used = 0
    while pos < len(data):
        ln = _utf8_len(data[pos])
        if ln == 0 or pos + ln > len(data): break
        try: cp = ord(data[pos:pos + ln].decode("utf-8"))
        except UnicodeDecodeError: break
        u = 1 if cp < 0x10000 else 2
        if used + u > mx: break
        used += u; pos += ln
    return pos
def _do_unshift(e):                                    # (this, state&, char* to, char* to_end, char*& to_next): stateless -> ok, nothing written
    e.write(e.arg(4), struct.pack("<Q", e.arg(2))); return 0
FUNCS.setdefault(CVT + "6do_outER11__mbstate_tPKwS5_RS5_PcS7_RS7_", _do_out)
FUNCS.setdefault(CVT + "5do_inER11__mbstate_tPKcS5_RS5_PwS7_RS7_", _do_in)
FUNCS.setdefault(CVT + "9do_lengthER11__mbstate_tPKcS5_m", _do_length)
FUNCS.setdefault(CVT + "10do_unshiftER11__mbstate_tPcS4_RS4_", _do_unshift)
FUNCS.setdefault(CVT + "13do_max_lengthEv", lambda e: 4)
FUNCS.setdefault(CVT + "11do_encodingEv", lambda e: 0)
FUNCS.setdefault(CVT + "16do_always_noconvEv", lambda e: 0)
