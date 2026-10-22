"""
High-level emulation of a slice of libSystem.

Every imported function the guest binds to (printf, malloc, strlen, ...) is
resolved to a tiny stub inside the emulator. When the guest calls it, the
stub's code hook runs the Python function registered here, puts the result
in x0, and the stub's `ret` returns to the guest.

Darwin arm64 ABI notes that matter here:
  * integer/pointer args: x0..x7, floating args: d0..d7
  * VARIADIC args (printf & co) are passed on the STACK, 8 bytes each,
    starting at sp - not in registers.
"""
import os, re, sys, math, struct, time, random

FUNCS = {}      # "_name" -> callable(emu) -> int | None
DATA  = {}
RESOLVERS = []  # callables(emu, name) -> address | None, consulted before DATA/stubs      # "_name" -> initial 8-byte cell value (callable(emu) or int)

def fn(*names):
    def deco(f):
        for n in names: FUNCS["_" + n] = f
        return f
    return deco

M64 = (1 << 64) - 1
def s64(v): return v - (1 << 64) if v >> 63 else v
def s32(v): v &= 0xffffffff; return v - (1 << 32) if v >> 31 else v

FILE_BASE = 0xF0000000           # fake FILE* values: FILE_BASE + fd
def fd_of(fp):
    if FILE_BASE <= fp < FILE_BASE + 0x100000:
        return fp - FILE_BASE
    return 1

def set_errno(e, n):
    addr = getattr(e, "errno_addr", 0)
    if addr:
        e.write(addr, (int(n) & 0xffffffff).to_bytes(4, "little") + b"\0\0\0\0")


DATA["___stdinp"]  = FILE_BASE + 0
DATA["___stdoutp"] = FILE_BASE + 1
DATA["___stderrp"] = FILE_BASE + 2
DATA["___stack_chk_guard"] = 0x2f6a1c7d5b3e9a40

# ---------------------------------------------------------------- printf ----
_FMT = re.compile(r"%([-+ #0]*)(\d+|\*)?(?:\.(\d+|\*))?(hh|h|ll|l|z|j|t|L)?([diouxXeEfFgGcspn%])")

def format_c(emu, fmt, next_int, next_double):
    out, pos = [], 0
    for m in _FMT.finditer(fmt):
        out.append(fmt[pos:m.start()]); pos = m.end()
        flags, width, prec, length, conv = m.groups()
        if conv == "%": out.append("%"); continue
        if width == "*":
            width = s32(next_int()); 
            if width < 0: flags += "-"; width = -width
        if prec == "*": prec = s32(next_int())
        spec = "%" + flags + (str(width) if width not in (None, "") else "") \
                   + ("." + str(prec) if prec not in (None, "") else "")
        wide = length in ("l", "ll", "z", "j", "t")
        if conv in "di":
            v = next_int(); v = s64(v) if wide else s32(v)
            out.append((spec + "d") % v)
        elif conv in "ouxX":
            v = next_int() & (M64 if wide else 0xffffffff)
            out.append((spec + conv) % v if conv != "u" else (spec + "d") % v)
        elif conv in "eEfFgG":
            out.append((spec + conv) % next_double())
        elif conv == "c":
            out.append((spec + "s") % chr(next_int() & 0xff))
        elif conv == "s":
            p = next_int(); out.append((spec + "s") % ("(null)" if p == 0 else emu.cstr(p)))
        elif conv == "p":
            out.append("0x%x" % next_int())
        elif conv == "n":
            next_int()
    out.append(fmt[pos:])
    return "".join(out)

def do_printf(emu, fmt_ptr, fixed):
    """fixed = number of named args before the '...' (they sit in registers)."""
    sp = emu.sp()
    state = {"i": 0}
    def next_int():
        v = int.from_bytes(emu.read(sp + 8 * state["i"], 8), "little"); state["i"] += 1; return v
    def next_double():
        return struct.unpack("<d", struct.pack("<Q", next_int()))[0]
    return format_c(emu, emu.cstr(fmt_ptr), next_int, next_double).encode("latin-1", "replace")

def _out(fd, data): os.write(fd, data); return len(data)

@fn("printf")
def _printf(e): return _out(1, do_printf(e, e.arg(0), 1))
@fn("fprintf")
def _fprintf(e): return _out(fd_of(e.arg(0)), do_printf(e, e.arg(1), 2))
@fn("dprintf")
def _dprintf(e): return _out(e.arg(0) & 0xffff, do_printf(e, e.arg(1), 2))
@fn("sprintf")
def _sprintf(e):
    b = do_printf(e, e.arg(1), 2); e.write(e.arg(0), b + b"\0"); return len(b)
@fn("snprintf")
def _snprintf(e):
    b = do_printf(e, e.arg(2), 3); n = e.arg(1)
    if n: e.write(e.arg(0), b[: n - 1] + b"\0")
    return len(b)
@fn("puts")
def _puts(e): return _out(1, e.cstr(e.arg(0)).encode("latin-1") + b"\n") and 1
@fn("putchar")
def _putchar(e): _out(1, bytes([e.arg(0) & 0xff])); return e.arg(0) & 0xff
@fn("fputs")
def _fputs(e): _out(fd_of(e.arg(1)), e.cstr(e.arg(0)).encode("latin-1")); return 1
@fn("fputc", "putc")
def _fputc(e): _out(fd_of(e.arg(1)), bytes([e.arg(0) & 0xff])); return e.arg(0) & 0xff
@fn("fwrite")
def _fwrite(e):
    n = e.arg(1) * e.arg(2); _out(fd_of(e.arg(3)), bytes(e.read(e.arg(0), n))); return e.arg(2)
@fn("fflush")
def _fflush(e): return 0
@fn("write")
def _write(e): return _out(e.arg(0) & 0xffff, bytes(e.read(e.arg(1), e.arg(2))))
@fn("read")
def _read(e):
    b = os.read(e.arg(0) & 0xffff, e.arg(2)); e.write(e.arg(1), b); return len(b)
@fn("getchar")
def _getchar(e):
    b = os.read(0, 1); return b[0] if b else M64
@fn("fgets")
def _fgets(e):
    line = sys.stdin.buffer.readline(max(e.arg(1) - 1, 0))
    if not line: return 0
    e.write(e.arg(0), line + b"\0"); return e.arg(0)

# --------------------------------------------------------------- process ----
@fn("exit", "_exit")
def _exit(e): e.exit(e.arg(0) & 0xff)
@fn("abort")
def _abort(e): e.exit(134)
@fn("___stack_chk_fail")
def _scf(e): sys.stderr.write("*** stack smashing detected ***\n"); e.exit(134)
@fn("getpid")
def _getpid(e): return os.getpid()
@fn("getenv")
def _getenv(e):
    v = os.environ.get(e.cstr(e.arg(0)))
    return 0 if v is None else e.alloc_cstr(v)
@fn("time")
def _time(e):
    t = int(time.time())
    if e.arg(0): e.write(e.arg(0), t.to_bytes(8, "little"))
    return t
@fn("usleep")
def _usleep(e): time.sleep(e.arg(0) / 1e6); return 0
@fn("sleep")
def _sleep(e): time.sleep(e.arg(0)); return 0
@fn("rand")
def _rand(e): return random.randint(0, 0x7fffffff)
@fn("srand")
def _srand(e): random.seed(e.arg(0))
@fn("___error")
def _error(e): return e.errno_addr

# ------------------------------------------------------------------ heap ----
@fn("malloc")
def _malloc(e): return e.malloc(e.arg(0))
@fn("calloc")
def _calloc(e):
    n = e.arg(0) * e.arg(1); p = e.malloc(n); e.write(p, b"\0" * n); return p
@fn("realloc")
def _realloc(e):
    old, n = e.arg(0), e.arg(1)
    p = e.malloc(n)
    if old:
        k = min(e.heap_sizes.get(old, 0), n); e.write(p, bytes(e.read(old, k)))
    return p
@fn("free")
def _free(e): return None

# -------------------------------------------------------- string / memory ----
@fn("memcpy", "memmove", "__platform_memmove")
def _memcpy(e): e.write(e.arg(0), bytes(e.read(e.arg(1), e.arg(2)))); return e.arg(0)
@fn("memset", "__platform_memset")
def _memset(e): e.write(e.arg(0), bytes([e.arg(1) & 0xff]) * e.arg(2)); return e.arg(0)
@fn("memcmp", "bcmp")
def _memcmp(e):
    a, b = bytes(e.read(e.arg(0), e.arg(2))), bytes(e.read(e.arg(1), e.arg(2)))
    return M64 if a < b else (1 if a > b else 0)
@fn("strlen")
def _strlen(e): return len(e.cstr_bytes(e.arg(0)))
@fn("strcmp")
def _strcmp(e):
    a, b = e.cstr_bytes(e.arg(0)), e.cstr_bytes(e.arg(1)); return M64 if a < b else (1 if a > b else 0)
@fn("strncmp")
def _strncmp(e):
    n = e.arg(2); a, b = e.cstr_bytes(e.arg(0))[:n], e.cstr_bytes(e.arg(1))[:n]
    return M64 if a < b else (1 if a > b else 0)
@fn("strcpy")
def _strcpy(e): e.write(e.arg(0), e.cstr_bytes(e.arg(1)) + b"\0"); return e.arg(0)
@fn("strncpy")
def _strncpy(e):
    n = e.arg(2); s = e.cstr_bytes(e.arg(1))[:n]; e.write(e.arg(0), s.ljust(n, b"\0")); return e.arg(0)
@fn("strcat")
def _strcat(e):
    d = e.arg(0); e.write(d + len(e.cstr_bytes(d)), e.cstr_bytes(e.arg(1)) + b"\0"); return d
@fn("strchr")
def _strchr(e):
    s = e.cstr_bytes(e.arg(0)) + b"\0"; i = s.find(bytes([e.arg(1) & 0xff]))
    return 0 if i < 0 else e.arg(0) + i
@fn("strrchr")
def _strrchr(e):
    s = e.cstr_bytes(e.arg(0)) + b"\0"; i = s.rfind(bytes([e.arg(1) & 0xff]))
    return 0 if i < 0 else e.arg(0) + i
@fn("strstr")
def _strstr(e):
    i = e.cstr_bytes(e.arg(0)).find(e.cstr_bytes(e.arg(1))); return 0 if i < 0 else e.arg(0) + i
@fn("strdup")
def _strdup(e): return e.alloc_cstr(e.cstr(e.arg(0)))
@fn("atoi")
def _atoi(e):
    m = re.match(r"\s*[-+]?\d+", e.cstr(e.arg(0))); return int(m.group()) & M64 if m else 0
@fn("atol", "atoll")
def _atol(e): return _atoi(e)
@fn("abs")
def _abs(e): return abs(s32(e.arg(0))) & 0xffffffff
@fn("toupper")
def _toupper(e): c = e.arg(0) & 0xff; return c - 32 if 97 <= c <= 122 else c
@fn("tolower")
def _tolower(e): c = e.arg(0) & 0xff; return c + 32 if 65 <= c <= 90 else c
@fn("isdigit")
def _isdigit(e): return int(48 <= e.arg(0) & 0xff <= 57)
@fn("isalpha")
def _isalpha(e): c = e.arg(0) & 0xff; return int(65 <= c <= 90 or 97 <= c <= 122)
@fn("isspace")
def _isspace(e): return int((e.arg(0) & 0xff) in (32, 9, 10, 11, 12, 13))

# ------------------------------------------------------------------ math ----
def _math1(name, f):
    @fn(name)
    def _m(e): e.ret_double(f(e.darg(0)))
for _n, _f in [("sqrt", math.sqrt), ("sin", math.sin), ("cos", math.cos), ("tan", math.tan),
               ("exp", math.exp), ("log", math.log), ("floor", math.floor), ("ceil", math.ceil),
               ("fabs", math.fabs), ("atan", math.atan)]:
    _math1(_n, _f)
@fn("pow")
def _pow(e): e.ret_double(math.pow(e.darg(0), e.darg(1)))

@fn("dyld_stub_binder")
def _binder(e): sys.stderr.write("[arm2x86] lazy binder called (should not happen)\n"); e.exit(127)

# ---- _FORTIFY_SOURCE variants (Xcode's clang emits these by default) --------
@fn("__memcpy_chk", "__memmove_chk")
def _memcpy_chk(e): e.write(e.arg(0), bytes(e.read(e.arg(1), e.arg(2)))); return e.arg(0)
@fn("__memset_chk")
def _memset_chk(e): e.write(e.arg(0), bytes([e.arg(1) & 0xff]) * e.arg(2)); return e.arg(0)
@fn("__strcpy_chk")
def _strcpy_chk(e): e.write(e.arg(0), e.cstr_bytes(e.arg(1)) + b"\0"); return e.arg(0)
@fn("__strncpy_chk")
def _strncpy_chk(e):
    n = e.arg(2); e.write(e.arg(0), e.cstr_bytes(e.arg(1))[:n].ljust(n, b"\0")); return e.arg(0)
@fn("__strcat_chk")
def _strcat_chk(e):
    d = e.arg(0); e.write(d + len(e.cstr_bytes(d)), e.cstr_bytes(e.arg(1)) + b"\0"); return d
@fn("__sprintf_chk")        # (s, flags, slen, fmt, ...)
def _sprintf_chk(e):
    b = do_printf(e, e.arg(3), 4); e.write(e.arg(0), b + b"\0"); return len(b)
@fn("__snprintf_chk")       # (s, maxlen, flags, slen, fmt, ...)
def _snprintf_chk(e):
    b = do_printf(e, e.arg(4), 5); n = e.arg(1)
    if n: e.write(e.arg(0), b[: n - 1] + b"\0")
    return len(b)
@fn("bzero")
def _bzero(e): e.write(e.arg(0), b"\0" * e.arg(1))
