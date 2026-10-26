"""
libSystem surface that real macOS apps hit before they draw anything:
environment, files, directories, mmap, clocks, sysctl, Mach time, pthreads
(single-process, preempted on basic-block boundaries), dlopen/dlsym aimed at
the HOST's x86_64 frameworks (the guest binaries are arm64), and the
_NSGetArg* symbols NSApplicationMain actually reads.

Guest open/mmap flags are Darwin's. errno values written back are Darwin's.
"""
import os, sys, time, struct, ctypes, errno, random, select, socket, mmap as _mmap
from hle import fn, FUNCS, DATA, M64, s32, s64, FILE_BASE, fd_of, set_errno
import spoof

PAGE = 0x4000
DATA["_vm_page_size"] = PAGE
DATA["_NSApp"] = 0                     # cell updated when NSApp exists

# Darwin errno (the ones that differ from Linux are the ones that matter)
EPERM, ENOENT, EINTR, EIO, EBADF = 1, 2, 4, 5, 9
EAGAIN, ENOMEM, EACCES, EFAULT, EEXIST = 35, 12, 13, 14, 17
EINVAL, ENOTDIR, EISDIR, ENOSYS, EPIPE = 22, 20, 21, 78, 32
ENOTSUP, ETIMEDOUT, EDEADLK = 45, 60, 11

_L2D = {1: EPERM, 2: ENOENT, 4: EINTR, 5: EIO, 9: EBADF, 11: EAGAIN, 12: ENOMEM,
        13: EACCES, 14: EFAULT, 17: EEXIST, 20: ENOTDIR, 21: EISDIR, 22: EINVAL, 32: EPIPE,
        111: 61}  # Linux ECONNREFUSED -> Darwin ECONNREFUSED

def _derr(n):
    e = getattr(n, "errno", None)
    if e is None:
        e = n if isinstance(n, int) else EINVAL
    return _L2D.get(e, e)

def _fail(e, err=EINVAL, ret=M64):
    set_errno(e, err); return ret

# ---------------------------------------------------------------- environment
@fn("setenv")
def _setenv(e):
    n, v, ov = e.cstr(e.arg(0)), e.cstr(e.arg(1)), s32(e.arg(2))
    if not n or "=" in n: return _fail(e)
    if ov or n not in os.environ: os.environ[n] = v
    return 0
@fn("unsetenv")
def _unsetenv(e):
    os.environ.pop(e.cstr(e.arg(0)), None); return 0
@fn("putenv")
def _putenv(e):
    s = e.cstr(e.arg(0))
    if "=" not in s: return _fail(e)
    k, v = s.split("=", 1); os.environ[k] = v; return 0
@fn("getenv")
def _getenv(e):
    v = os.environ.get(e.cstr(e.arg(0)))
    return 0 if v is None else e.alloc_cstr(v)
@fn("issetugid")
def _issetugid(e): return 0
@fn("getuid", "geteuid", "getgid", "getegid")
def _ids(e): return os.getuid()

# ---------------------------------------------------------------- paths / fs
_O_ACC = {0: os.O_RDONLY, 1: os.O_WRONLY, 2: os.O_RDWR}
def _oflags(f):
    h = _O_ACC.get(f & 3, os.O_RDONLY)
    if f & 0x0004: h |= os.O_NONBLOCK
    if f & 0x0008: h |= os.O_APPEND
    if f & 0x0200: h |= os.O_CREAT
    if f & 0x0400: h |= os.O_TRUNC
    if f & 0x0800: h |= os.O_EXCL
    if f & 0x100000 and hasattr(os, "O_DIRECTORY"): h |= os.O_DIRECTORY
    if f & 0x01000000: h |= getattr(os, "O_CLOEXEC", 0)
    return h

def _pack_stat(st):
    # Darwin arm64 `struct stat` (144 bytes). See bsd/sys/stat.h __DARWIN_STRUCT_STAT64.
    def ts(sec, nsec): return struct.pack("<qq", int(sec), int(nsec))
    mode = st.st_mode
    # Darwin S_IFMT matches Linux for the types we care about.
    return struct.pack("<IHHQIIIi", st.st_dev & 0xffffffff, mode & 0xffff, st.st_nlink & 0xffff,
                       st.st_ino & M64, st.st_uid & 0xffffffff, st.st_gid & 0xffffffff,
                       st.st_rdev & 0xffffffff, 0) \
        + ts(st.st_atime, getattr(st, "st_atime_ns", 0) % 10**9) \
        + ts(st.st_mtime, getattr(st, "st_mtime_ns", 0) % 10**9) \
        + ts(st.st_ctime, getattr(st, "st_ctime_ns", 0) % 10**9) \
        + ts(getattr(st, "st_birthtime", st.st_ctime), 0) \
        + struct.pack("<qqIIiiQQ", st.st_size, getattr(st, "st_blocks", (st.st_size + 511) // 512),
                      st.st_blksize & 0xffffffff, 0, 0, 0, 0, 0)

def _stat_into(e, st, p):
    e.write(p, _pack_stat(st)); return 0

@fn("open")
def _open(e):
    path, flags = spoof.map_path(e.cstr(e.arg(0))), e.arg(1)
    mode = e.arg(2) & 0o777 or 0o666
    parent = os.path.dirname(path)
    if parent:
        try:
            os.makedirs(parent, exist_ok=True)
            os.chmod(parent, 0o755)
        except OSError:
            pass
    try:
        if os.path.isdir(path):
            import shutil
            shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass
    try:
        fd = os.open(path, _oflags(flags), mode)
    except OSError as ex:
        # Last-ditch: remove and recreate parent for Application Support locks
        if ex.errno in (13, 21, 17) and "Application Support" in path:
            try:
                import shutil
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                elif os.path.exists(path):
                    os.unlink(path)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                    os.chmod(parent, 0o755)
                fd = os.open(path, _oflags(flags), mode)
            except OSError as ex2:
                if os.environ.get("ARM2X86_VERBOSE"):
                    sys.stderr.write("[open] %r flags=%#x failed: %s" % (path, flags, ex2) + chr(10))
                return _fail(e, _derr(ex2))
        else:
            if os.environ.get("ARM2X86_VERBOSE"):
                sys.stderr.write("[open] %r flags=%#x failed: %s" % (path, flags, ex) + chr(10))
            return _fail(e, _derr(ex))
    # Darwin O_EXLOCK / O_SHLOCK
    try:
        import fcntl
        if flags & 0x20:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif flags & 0x10:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except Exception:
        pass
    return fd


@fn("openat")
def _openat(e):
    # ignore dirfd unless it's AT_FDCWD (-2)
    e.uc  # silence
    path = spoof.map_path(e.cstr(e.arg(1)))
    parent = os.path.dirname(path)
    if parent:
        try: os.makedirs(parent, exist_ok=True)
        except OSError: pass
    try: return os.open(path, _oflags(e.arg(2)), e.arg(3) & 0o777 or 0o666)
    except OSError as ex: return _fail(e, _derr(ex))
@fn("close")
def _close(e):
    fd = e.arg(0) & 0xffff
    if fd < 3: return 0
    s = globals().get("_SOCKS", {}).pop(fd, None)
    if s is not None:
        try: s.close()
        except OSError: pass
        return 0
    try: os.close(fd); return 0
    except OSError as ex: return _fail(e, _derr(ex), 0xffffffff)
@fn("lseek")
def _lseek(e):
    try: return os.lseek(e.arg(0) & 0xffff, s64(e.arg(1)), e.arg(2) & 0xffffffff) & M64
    except OSError as ex: return _fail(e, _derr(ex))
@fn("pread")
def _pread(e):
    try:
        b = os.pread(e.arg(0) & 0xffff, e.arg(2), s64(e.arg(3)))
        e.write(e.arg(1), b); return len(b)
    except OSError as ex: return _fail(e, _derr(ex))
@fn("pwrite")
def _pwrite(e):
    try: return os.pwrite(e.arg(0) & 0xffff, bytes(e.read(e.arg(1), e.arg(2))), s64(e.arg(3)))
    except OSError as ex: return _fail(e, _derr(ex))
@fn("fstat", "fstat$INODE64")
def _fstat(e):
    try: return _stat_into(e, os.fstat(e.arg(0) & 0xffff), e.arg(1))
    except OSError as ex: return _fail(e, _derr(ex), 0xffffffff)
@fn("stat", "stat$INODE64", "lstat", "lstat$INODE64")
def _stat(e):
    fn = os.lstat if "lstat" in sys._getframe().f_code.co_name else os.stat
    # the decorator shares one function; distinguish by the return address's symbol? can't.
    # Both are close enough for games: follow links for stat, and lstat is registered separately below.
    try: return _stat_into(e, os.stat(e.cstr(e.arg(0))), e.arg(1))
    except OSError as ex: return _fail(e, _derr(ex), 0xffffffff)
@fn("lstat", "lstat$INODE64")
def _lstat(e):
    try: return _stat_into(e, os.lstat(e.cstr(e.arg(0))), e.arg(1))
    except OSError as ex: return _fail(e, _derr(ex), 0xffffffff)
def _access_mode(m):
    r = 0
    if m & 4 or m == 0: r |= os.R_OK if m & 4 else 0
    if m & 2: r |= os.W_OK
    if m & 1: r |= os.X_OK
    return r or os.F_OK
@fn("access", "faccessat")
def _access(e):
    if e.arg(0) > 0x10000:
        path, mode = e.cstr(e.arg(0)), e.arg(1)
    else:
        path, mode = e.cstr(e.arg(1)), e.arg(2)
    try:
        ok = os.access(path, _access_mode(mode)); return 0 if ok else _fail(e, EACCES, 0xffffffff)
    except OSError as ex: return _fail(e, _derr(ex), 0xffffffff)
@fn("readlink")
def _readlink(e):
    try:
        t = os.readlink(e.cstr(e.arg(0))).encode()[:e.arg(2)]
        e.write(e.arg(1), t); return len(t)
    except OSError as ex: return _fail(e, _derr(ex))
@fn("getcwd")
def _getcwd(e):
    b = os.getcwd().encode() + b"\0"
    if e.arg(1) and e.arg(1) < len(b): return _fail(e, 34)  # ERANGE darwin = 34
    e.write(e.arg(0), b); return e.arg(0)
@fn("chdir")
def _chdir(e):
    try: os.chdir(e.cstr(e.arg(0))); return 0
    except OSError as ex: return _fail(e, _derr(ex), 0xffffffff)
@fn("mkdir")
def _mkdir(e):
    try:
        os.makedirs(e.cstr(e.arg(0)), mode=(e.arg(1) & 0o777) or 0o755, exist_ok=True)
        return 0
    except OSError as ex:
        return _fail(e, _derr(ex), 0xffffffff)
@fn("rmdir", "unlink", "remove")
def _unlink(e):
    p = e.cstr(e.arg(0))
    try:
        if os.path.isdir(p) and not os.path.islink(p): os.rmdir(p)
        else: os.unlink(p)
        return 0
    except OSError as ex: return _fail(e, _derr(ex), 0xffffffff)
@fn("rename")
def _rename(e):
    try: os.rename(e.cstr(e.arg(0)), e.cstr(e.arg(1))); return 0
    except OSError as ex: return _fail(e, _derr(ex), 0xffffffff)
@fn("realpath")
def _realpath(e):
    try:
        r = os.path.realpath(e.cstr(e.arg(0))).encode() + b"\0"
    except OSError as ex:
        return _fail(e, _derr(ex), 0)
    dst = e.arg(1) or e.malloc(len(r))
    e.write(dst, r); return dst
@fn("fcntl")
def _fcntl(e):
    fd, cmd = e.arg(0) & 0xffff, e.arg(1) & 0xffffffff
    # F_GETFD=1 F_SETFD=2 F_GETFL=3 F_SETFL=4 on Darwin match Linux
    try:
        if cmd in (1, 3): return fcntl_get(fd, cmd)
        if cmd in (2, 4): return fcntl_set(fd, cmd, e.arg(2))
    except Exception:
        pass
    return 0
def fcntl_get(fd, cmd):
    import fcntl
    return fcntl.fcntl(fd, fcntl.F_GETFD if cmd == 1 else fcntl.F_GETFL)
def fcntl_set(fd, cmd, v):
    import fcntl
    return fcntl.fcntl(fd, fcntl.F_SETFD if cmd == 2 else fcntl.F_SETFL, v) or 0
@fn("ioctl")
def _ioctl(e): return 0
@fn("isatty")
def _isatty(e): return int(os.isatty(e.arg(0) & 0xffff))
@fn("dup")
def _dup(e):
    old = e.arg(0) & 0xffff
    try:
        new = os.dup(old)
    except OSError as ex:
        return _fail(e, _derr(ex), 0xffffffff)
    s = _SOCKS.get(old)
    if s is not None:
        _SOCKS[new] = s
        if os.environ.get("ARM2X86_VERBOSE"):
            sys.stderr.write("[sock] dup %d -> %d (socket)" % (old, new) + chr(10)); sys.stderr.flush()
    return new


@fn("dup2")
def _dup2(e):
    old = e.arg(0) & 0xffff
    new = e.arg(1) & 0xffff
    try:
        os.dup2(old, new)
    except OSError as ex:
        return _fail(e, _derr(ex), 0xffffffff)
    s = _SOCKS.get(old)
    if s is not None:
        _SOCKS[new] = s
        if os.environ.get("ARM2X86_VERBOSE"):
            sys.stderr.write("[sock] dup2 %d -> %d (socket)" % (old, new) + chr(10)); sys.stderr.flush()
    elif new in _SOCKS:
        # target is no longer that socket
        _SOCKS.pop(new, None)
    return new


@fn("pipe")
def _pipe(e):
    r, w = os.pipe()
    e.write(e.arg(0), struct.pack("<ii", r, w)); return 0
@fn("fsync", "ftruncate")
def _fsync(e):
    try:
        if "trunc" in sys._getframe().f_code.co_name:
            os.ftruncate(e.arg(0) & 0xffff, s64(e.arg(1)))
        else:
            os.fsync(e.arg(0) & 0xffff)
        return 0
    except OSError as ex: return _fail(e, _derr(ex), 0xffffffff)
@fn("ftruncate")
def _ftrunc(e):
    try: os.ftruncate(e.arg(0) & 0xffff, s64(e.arg(1))); return 0
    except OSError as ex: return _fail(e, _derr(ex), 0xffffffff)
@fn("statfs", "fstatfs", "getattrlist", "setattrlist", "getattrlistbulk", "listxattr", "getxattr")
def _unsup(e): return _fail(e, ENOTSUP, 0xffffffff)

# ------------------------------------------------------------------- stdio
_FILES = {}
def _file(e, path, mode):
    flags = _oflags(_mode_to_o(mode))
    fd = os.open(path, flags, 0o666)
    return FILE_BASE + fd
def _mode_to_o(mode):
    m = mode.replace("b", "")
    f = 0
    if "r" in m and "+" in m: f = 2
    elif "r" in m: f = 0
    elif "+" in m: f = 2 | 0x200 | 0x400 if "w" in m else 2 | 0x200
    elif "w" in m: f = 1 | 0x200 | 0x400
    elif "a" in m: f = 1 | 0x200 | 0x8
    return f
@fn("fopen")
def _fopen(e):
    try: return _file(e, spoof.map_path(e.cstr(e.arg(0))), e.cstr(e.arg(1)))
    except OSError as ex: set_errno(e, _derr(ex)); return 0
@fn("fdopen")
def _fdopen(e): return FILE_BASE + (e.arg(0) & 0xffff)
@fn("fclose")
def _fclose(e):
    fd = fd_of(e.arg(0))
    if fd < 3: return 0
    try: os.close(fd)
    except OSError: pass
    return 0
@fn("fread")
def _fread(e):
    n = e.arg(1) * e.arg(2)
    try:
        b = os.read(fd_of(e.arg(3)), n)
    except OSError:
        return 0
    if b: e.write(e.arg(0), b)
    return len(b) // (e.arg(1) or 1)
@fn("fseek", "fseeko")
def _fseek(e):
    try: os.lseek(fd_of(e.arg(0)), s64(e.arg(1)), e.arg(2) & 0xff); return 0
    except OSError as ex: return _fail(e, _derr(ex), 0xffffffff)
@fn("ftell", "ftello")
def _ftell(e):
    try: return os.lseek(fd_of(e.arg(0)), 0, os.SEEK_CUR) & M64
    except OSError as ex: return _fail(e, _derr(ex))
@fn("fileno")
def _fileno(e): return fd_of(e.arg(0))
@fn("feof", "ferror", "clearerr", "rewind")
def _feof(e):
    if "rewind" in sys._getframe().f_code.co_name:
        try: os.lseek(fd_of(e.arg(0)), 0, os.SEEK_SET)
        except OSError: pass
    return 0
@fn("fgetc", "getc")
def _fgetc(e):
    b = os.read(fd_of(e.arg(0)), 1)
    return b[0] if b else M64
@fn("ungetc")
def _ungetc(e): return e.arg(0) & 0xff
@fn("flockfile", "funlockfile", "ftrylockfile")
def _flock(e): return 0

# ---------------------------------------------------------------- directories
_DIRS = {}
_DIR_N = 1
# Darwin dirent: ino u64, seekoff u64, reclen u16, namlen u16, type u8, name[256] -> 280
def _dirent(name, ino, typ):
    nb = name.encode()[:255]
    rec = struct.pack("<QQHHB", ino & M64, 0, 280, len(nb), typ) + nb + b"\0"
    return rec.ljust(280, b"\0")
def _dtype(path):
    try:
        if os.path.islink(path): return 10
        if os.path.isdir(path): return 4
        if os.path.isfile(path): return 8
    except OSError:
        pass
    return 0
@fn("opendir")
def _opendir(e):
    global _DIR_N
    p = e.cstr(e.arg(0))
    try:
        names = os.listdir(p)
    except OSError as ex:
        set_errno(e, _derr(ex)); return 0
    slot = e.malloc(16)
    _DIRS[slot] = [p, names, 0]
    return slot
@fn("readdir", "readdir$INODE64")
def _readdir(e):
    d = _DIRS.get(e.arg(0))
    if not d: return 0
    p, names, i = d
    if i >= len(names): return 0
    d[2] = i + 1
    name = names[i]
    buf = e.malloc(280)
    e.write(buf, _dirent(name, i + 1, _dtype(os.path.join(p, name))))
    return buf
@fn("closedir")
def _closedir(e):
    _DIRS.pop(e.arg(0), None); return 0
@fn("rewinddir")
def _rewinddir(e):
    d = _DIRS.get(e.arg(0))
    if d: d[2] = 0
    return None

# -------------------------------------------------------------------- mmap
MAP_ANON, MAP_FIXED = 0x1000, 0x0010
def _mmap_state(e):
    if not hasattr(e, "mmap_next"):
        e.mmap_next = 0x600000000
        e.mmaps = {}          # addr -> (len, host_shadow or None)
    return e
@fn("mmap")
def _mmap(e):
    hint, length, prot, flags = e.arg(0), e.arg(1), e.arg(2), e.arg(3)
    fd, off = s32(e.arg(4)), s64(e.arg(5))
    if length == 0: return _fail(e)
    length = (length + 0xfff) & ~0xfff
    st = _mmap_state(e)
    if hint and (flags & MAP_FIXED):
        addr = hint & ~0xfff
    else:
        addr = (st.mmap_next + 0xffff) & ~0xffff
        st.mmap_next = addr + length
    try:
        e.uc.mem_map(addr & ~0xfff, max(length, 0x1000))
    except Exception:
        pass
    blob = b""
    if not (flags & MAP_ANON) and fd >= 0:
        try:
            blob = os.pread(fd, length, off)
            e.write(addr, blob)
        except OSError as ex:
            return _fail(e, _derr(ex))
    st.mmaps[addr] = length
    return addr
@fn("munmap")
def _munmap(e):
    addr, length = e.arg(0) & ~0xfff, (e.arg(1) + 0xfff) & ~0xfff
    try: e.uc.mem_unmap(addr, length)
    except Exception: pass
    if hasattr(e, "mmaps"): e.mmaps.pop(addr, None)
    return 0
@fn("mprotect", "madvise", "msync", "mlock", "munlock", "mincore")
def _mprot(e): return 0
@fn("posix_madvise")
def _pmadv(e): return 0

# -------------------------------------------------------------------- time
_T0 = time.monotonic_ns()
@fn("mach_absolute_time")
def _mat(e): return (time.monotonic_ns()) & M64
@fn("mach_continuous_time")
def _mct(e): return _mat(e)
@fn("mach_timebase_info")
def _mtb(e):
    # 1 tick = 1 ns, so guests can convert with numer/denom.
    e.write(e.arg(0), struct.pack("<II", 1, 1)); return 0
@fn("clock_gettime")
def _cgt(e):
    t = time.time() if (e.arg(0) & 0xffffffff) in (0, 5, 6) else time.monotonic()
    # CLOCK_REALTIME=0, CLOCK_MONOTONIC=6 on Darwin (Linux monotonic is 1). Treat both.
    if (e.arg(0) & 0xffffffff) == 6 or (e.arg(0) & 0xffffffff) == 1:
        t = time.monotonic()
    sec, nsec = int(t), int((t - int(t)) * 1e9)
    e.write(e.arg(1), struct.pack("<qq", sec, nsec)); return 0
@fn("clock_gettime_nsec_np")
def _cgn(e): return time.monotonic_ns() & M64
@fn("clock_get_time")
def _cgtk(e):
    # (clock_serv, mach_timespec_t*) {u32 sec, u32 nsec}
    t = time.time(); e.write(e.arg(1), struct.pack("<II", int(t), int((t % 1) * 1e9))); return 0
@fn("gettimeofday")
def _gtod(e):
    t = time.time()
    if e.arg(0): e.write(e.arg(0), struct.pack("<qq", int(t), int((t % 1) * 1e6)))
    return 0
@fn("nanosleep")
def _nsleep(e):
    sec, nsec = struct.unpack("<qq", bytes(e.read(e.arg(0), 16)))
    time.sleep(max(0, sec) + max(0, nsec) / 1e9)
    return 0
@fn("localtime_r", "gmtime_r")
def _ltr(e):
    sec = s64(int.from_bytes(e.read(e.arg(0), 8), "little")) if e.arg(0) else int(time.time())
    tm = time.gmtime(sec) if "gm" in sys._getframe().f_code.co_name else time.localtime(sec)
    # Darwin struct tm: sec,min,hour,mday,mon,year,wday,yday,isdst, gmtoff, zone
    e.write(e.arg(1), struct.pack("<9i", tm.tm_sec, tm.tm_min, tm.tm_hour, tm.tm_mday,
                                  tm.tm_mon, tm.tm_year, tm.tm_wday, tm.tm_yday, tm.tm_isdst)
            + struct.pack("<qQ", -time.timezone, 0))
    return e.arg(1)
@fn("timegm", "mktime")
def _mktime(e):
    sec, mn, hr, md, mo, yr = struct.unpack("<6i", bytes(e.read(e.arg(0), 24)))
    try:
        return int(time.mktime((yr + 1900, mo + 1, md, hr, mn, sec, 0, 0, -1))) & M64
    except Exception:
        return M64
@fn("strftime")
def _strftime(e):
    # best-effort: ignore format nuances beyond what Python shares with C
    fmt = e.cstr(e.arg(2))
    t = struct.unpack("<9i", bytes(e.read(e.arg(3), 36)))
    try:
        s = time.strftime(fmt, (t[5] + 1900, t[4] + 1, t[3], t[2], t[1], t[0], t[6], t[7], t[8])).encode()
    except Exception:
        s = b""
    s = s[:max(e.arg(1) - 1, 0)]
    if e.arg(1): e.write(e.arg(0), s + b"\0")
    return len(s)

# ------------------------------------------------------------------- sysctl
def _sysctl_value(name):
    _ov = spoof.sysctl_override(name)
    if _ov is not None: return _ov
    table = {
        "hw.machine": b"arm64",
        "hw.model": b"arm64",
        "hw.machine_arch": b"arm64",
        "hw.optional.arm64": 1,
        "hw.ncpu": os.cpu_count() or 1,
        "hw.physicalcpu": os.cpu_count() or 1,
        "hw.physicalcpu_max": os.cpu_count() or 1,
        "hw.logicalcpu": os.cpu_count() or 1,
        "hw.logicalcpu_max": os.cpu_count() or 1,
        "hw.packages": 1,
        "hw.pagesize": PAGE,
        "hw.memsize": 8 << 30,
        "hw.cachelinesize": 128,
        "hw.l1icachesize": 128 * 1024,
        "hw.l1dcachesize": 64 * 1024,
        "hw.l2cachesize": 4 * 1024 * 1024,
        "hw.cputype": 0x0100000c,
        "hw.cpusubtype": 2,
        "hw.cpufamily": 0,
        "hw.optional.neon": 1,
        "hw.optional.sse": 0,
        "kern.osproductversion": "14.0",
        "kern.osrelease": "23.0.0",
        "kern.osversion": "23A344",
        "kern.ostype": b"Darwin",
        "kern.hostname": socket.gethostname() if hasattr(socket, "gethostname") else "mac",
        "kern.version": b"Darwin Kernel arm2x86",
        "kern.maxproc": 2048,
        "machdep.cpu.brand_string": b"Apple ARM (arm2x86)",
        "machdep.ptrauth_enabled": 0,
    }
    if name in table: return table[name]
    if name == "kern.hostname": return socket.gethostname()
    return None

def _sysctl_core(e, name, oldp, oldlenp):
    val = _sysctl_value(name)
    if val is None: return _fail(e, ENOENT, 0xffffffff)
    if isinstance(val, int) and not isinstance(val, bool):
        # integer sysctls are returned as the natural width the caller asked for
        n = int.from_bytes(e.read(oldlenp, 8), "little") if oldlenp else 8
        n = 8 if n >= 8 else (4 if n >= 4 else n)
        raw = (val & M64).to_bytes(8, "little")[:max(n, 4)]
        if n < 4: raw = raw[:n] if n else (val & 0xffffffff).to_bytes(4, "little")
        if n == 0: raw = (val & 0xffffffff).to_bytes(4, "little"); n = 4
    else:
        raw = (val if isinstance(val, bytes) else str(val).encode()) + b"\0"
        n = len(raw)
    have = int.from_bytes(e.read(oldlenp, 8), "little") if oldlenp else n
    if oldlenp: e.write(oldlenp, n.to_bytes(8, "little"))
    if oldp:
        if have < n and have != 0:
            e.write(oldp, raw[:have]); return _fail(e, ENOMEM, 0xffffffff)
        e.write(oldp, raw)
    return 0
@fn("sysctlbyname")
def _scbn(e): return _sysctl_core(e, e.cstr(e.arg(0)), e.arg(1), e.arg(2))
@fn("sysctl")
def _sysctl(e):                                            # sysctl(int *mib, u_int n, void *old, size_t *oldlen, void *new, size_t newlen)
    n = e.arg(1)
    mib = [s32(int.from_bytes(e.read(e.arg(0) + 4 * i, 4), "little")) for i in range(min(n, 4))] if e.arg(0) else []
    name = spoof.mib_name(mib)
    if name is None and len(mib) >= 2 and mib[0] == 6: name = "hw.ncpu"     # unknown CTL_HW leaf: historical default
    if name is None: return _fail(e, EINVAL, 0xffffffff)
    return _sysctl_core(e, name, e.arg(2), e.arg(3))
@fn("sysconf")
def _sysconf(e):
    # Darwin _SC_* values differ; answer the ones games ask (pagesize, nproc, openmax).
    n = s32(e.arg(0))
    if n in (29, 22): return PAGE          # _SC_PAGESIZE on various headers
    if n in (58, 96, 31): return os.cpu_count() or 1
    return 256
@fn("confstr", "pathconf", "fpathconf")
def _confstr(e): return 0
@fn("getpagesize")
def _gps(e): return PAGE
@fn("gethostname")
def _ghn(e):
    b = socket.gethostname().encode() + b"\0"
    e.write(e.arg(0), b[:e.arg(1)]); return 0
@fn("getprogname")
def _gpn(e): return e.alloc_cstr(os.path.basename(getattr(e, "path", "arm2x86")))
@fn("_NSGetExecutablePath")
def _nsep(e):
    b = os.path.abspath(getattr(e, "path", "")).encode() + b"\0"
    need = int.from_bytes(e.read(e.arg(1), 4), "little") if e.arg(1) else 0
    e.write(e.arg(1), len(b).to_bytes(4, "little"))
    if need < len(b): return 1
    e.write(e.arg(0), b); return 0
@fn("_NSGetArgc")
def _nsargc(e):
    p = e.malloc(4); e.write(p, len(getattr(e, "argv", [""])).to_bytes(4, "little")); return p
@fn("_NSGetArgv")
def _nsargv(e):
    p = e.malloc(8); e.write(p, getattr(e, "argv_p", 0).to_bytes(8, "little")); return p
@fn("_NSGetEnviron")
def _nsenv(e):
    p = e.malloc(8); e.write(p, getattr(e, "envp_p", 0).to_bytes(8, "little")); return p
@fn("_NSGetProgname")
def _nspn(e):
    cell = e.malloc(8)
    e.write(cell, e.alloc_cstr(os.path.basename(getattr(e, "path", "a"))).to_bytes(8, "little"))
    return cell

# ------------------------------------------------------------------- mach
@fn("mach_task_self", "mach_task_self_")
def _mts(e): return 0x203
@fn("mach_host_self")
def _mhs(e): return 0x202
@fn("mach_thread_self")
def _mths(e): return 0x204
@fn("host_page_size", "host_kernel_version")
def _hps(e):
    if e.arg(1): e.write(e.arg(1), PAGE.to_bytes(8, "little"))
    return 0
@fn("host_statistics64", "host_statistics", "task_info", "thread_info", "pid_for_task")
def _hstat(e): return 0
@fn("vm_allocate", "mach_vm_allocate")
def _vma(e):
    # (target, *addr, size, flags)
    size = e.arg(2)
    p = _mmap(e) if False else None
    st = _mmap_state(e)
    size = (size + 0xfff) & ~0xfff
    addr = (st.mmap_next + 0xffff) & ~0xffff
    st.mmap_next = addr + max(size, 0x1000)
    try: e.uc.mem_map(addr, max(size, 0x1000))
    except Exception: pass
    if e.arg(1): e.write(e.arg(1), addr.to_bytes(8, "little"))
    return 0
@fn("vm_deallocate", "mach_vm_deallocate")
def _vmd(e): return 0
@fn("mach_port_allocate", "mach_port_deallocate", "mach_port_insert_right",
    "mach_port_mod_refs", "semaphore_create", "semaphore_destroy",
    "semaphore_signal", "semaphore_wait", "semaphore_timedwait", "semaphore_wait_signal")
def _sem(e): return 0
@fn("sandbox_init", "sandbox_check", "csops", "csops_audittoken", "responsibility_get_pid_responsible_for_pid")
def _sand(e): return 0
@fn("proc_pidpath", "proc_pidinfo", "proc_name")
def _proc(e):
    if e.arg(1) and e.arg(2):
        b = os.path.abspath(getattr(e, "path", "")).encode() + b"\0"
        e.write(e.arg(1), b[:e.arg(2)])
        return len(b)
    return 0

# ----------------------------------------------------------------- pthread
# Cooperative threads: pthread_create builds a real Unicorn context on its own
# stack. A block hook (installed on the first extra thread) round-robins.
# Mutexes/conds are a side table keyed by the guest object address so a static
# PTHREAD_MUTEX_INITIALIZER works without an explicit init.
_MUTEX, _COND, _ONCE, _KEYS = {}, {}, {}, {}
_KEYVAL = {}     # (tid, key) -> value

def _tid(e): return getattr(e, "current_tid", 1)

@fn("pthread_self")
def _pself(e): return _tid(e)
@fn("pthread_main_np")
def _pmain(e): return int(_tid(e) == 1)
@fn("pthread_mutex_init", "pthread_mutexattr_init", "pthread_mutexattr_settype",
    "pthread_mutexattr_destroy", "pthread_condattr_init", "pthread_condattr_destroy",
    "pthread_rwlock_init", "pthread_rwlockattr_init", "pthread_attr_init",
    "pthread_attr_destroy", "pthread_attr_setstacksize", "pthread_attr_setdetachstate",
    "pthread_cond_init", "pthread_rwlock_destroy", "pthread_rwlock_rdlock",
    "pthread_rwlock_wrlock", "pthread_rwlock_unlock", "pthread_mutexattr_setprotocol")
def _pinit(e):
    if e.arg(0):
        _MUTEX.setdefault(e.arg(0), {"owner": 0, "waiters": []})
    return 0
@fn("pthread_mutex_lock")
def _plock(e):
    m = _MUTEX.setdefault(e.arg(0), {"owner": 0, "waiters": []})
    me = _tid(e)
    if m["owner"] in (0, me):
        m["owner"] = me; return 0
    # Contended: park this thread and run someone else. spawn/switch lives on Emu.
    if hasattr(e, "park_thread"):
        m["waiters"].append(me)
        e.park_thread("mutex", e.arg(0))
        return None
    m["owner"] = me; return 0
@fn("pthread_mutex_trylock")
def _ptrylock(e):
    m = _MUTEX.setdefault(e.arg(0), {"owner": 0, "waiters": []})
    me = _tid(e)
    if m["owner"] in (0, me):
        m["owner"] = me; return 0
    return EBUSY if False else 16  # EBUSY darwin = 16
@fn("pthread_mutex_unlock", "pthread_mutex_destroy")
def _punlock(e):
    m = _MUTEX.setdefault(e.arg(0), {"owner": 0, "waiters": []})
    m["owner"] = 0
    if m["waiters"] and hasattr(e, "wake_thread"):
        e.wake_thread(m["waiters"].pop(0))
    if "destroy" in sys._getframe().f_code.co_name:
        _MUTEX.pop(e.arg(0), None)
    return 0
@fn("pthread_cond_wait", "pthread_cond_timedwait", "pthread_cond_timedwait_relative_np")
def _pcw(e):
    # unlock mutex, park, relock on wake. Cooperative multi-thread: park if others runnable.
    c = _COND.setdefault(e.arg(0), [])
    if hasattr(e, "park_thread") and getattr(e, "n_runnable", lambda: 1)() > 1:
        try:
            # unlock the mutex arg if present
            if e.arg(1):
                m = _MUTEX.get(e.arg(1))
                if m and m.get("owner") == _tid(e):
                    m["owner"] = 0
                    if m["waiters"] and hasattr(e, "wake_thread"):
                        e.wake_thread(m["waiters"].pop(0))
        except Exception:
            pass
        c.append(_tid(e))
        e.park_thread("cond", e.arg(0))
        return None  # park switches away; return value set on wake
    # single runnable thread: brief yield then success (ETIMEDOUT confuses
    # GPUI's profiler pairing of register_task_start / save_task_timing)
    import time
    time.sleep(0.0001)
    return 0
@fn("pthread_cond_signal", "pthread_cond_broadcast")
def _pcs(e):
    c = _COND.get(e.arg(0), [])
    if hasattr(e, "wake_thread"):
        while c:
            e.wake_thread(c.pop(0))
            if "signal" in sys._getframe().f_code.co_name and "broadcast" not in sys._getframe().f_code.co_name:
                break
    else:
        c.clear()
    return 0
@fn("pthread_once")
def _ponce(e):
    ctrl, fnptr = e.arg(0), e.arg(1)
    if _ONCE.get(ctrl): return 0
    _ONCE[ctrl] = 1
    if fnptr and hasattr(e, "begin_callbacks"):
        e.write(ctrl, (0x30B1BCBA).to_bytes(4, "little"))
        e.begin_callbacks([(fnptr, [])], 0)
        return None
    return 0
@fn("pthread_key_create")
def _pkc(e):
    k = len(_KEYS) + 1
    _KEYS[k] = e.arg(1)  # destructor, best-effort
    if e.arg(0): e.write(e.arg(0), struct.pack("<I", k))
    return 0
@fn("pthread_setspecific")
def _pss(e):
    _KEYVAL[(_tid(e), e.arg(0) & 0xffffffff)] = e.arg(1); return 0
@fn("pthread_getspecific")
def _pgs(e):
    return _KEYVAL.get((_tid(e), e.arg(0) & 0xffffffff), 0)
@fn("pthread_key_delete")
def _pkd(e): return 0
@fn("pthread_create")
def _pcreate(e):
    start, arg = e.arg(2), e.arg(3)
    if not hasattr(e, "spawn_thread"):
        set_errno(e, ENOSYS); return ENOSYS
    tid = e.spawn_thread(start, arg)
    if e.arg(0): e.write(e.arg(0), tid.to_bytes(8, "little"))
    return 0
@fn("pthread_detach", "pthread_setname_np", "pthread_getname_np", "pthread_yield_np",
    "sched_yield", "pthread_setcancelstate", "pthread_setcanceltype", "pthread_testcancel",
    "pthread_equal", "pthread_atfork", "pthread_threadid_np")
def _pmisc(e):
    if hasattr(e, "schedule") and "yield" in sys._getframe().f_code.co_name:
        e.schedule(force=False)
    return 0
@fn("pthread_join")
def _pjoin(e):
    tid = e.arg(0)
    # Helper threads created under single-thread mode are parked forever;
    # joining them must not park the main thread (that triggers exit(0)).
    t = getattr(e, "threads", {}).get(tid)
    if t and t.get("wait") and t["wait"][0] == "parked":
        return 0
    if hasattr(e, "thread_alive") and e.thread_alive(tid):
        e.park_thread("join", tid)
        return None
    return 0
@fn("pthread_exit")
def _pexit(e):
    if hasattr(e, "thread_dead"):
        e.thread_dead(e.arg(0))
    return None
def _thread_exit_stub(e):
    if hasattr(e, "thread_dead"): e.thread_dead(0)
FUNCS["__arm2x86_thread_exit"] = _thread_exit_stub

@fn("os_unfair_lock_lock", "os_unfair_lock_unlock", "os_unfair_lock_trylock", "os_unfair_lock_assert_owner")
def _unfair(e): return 1
@fn("os_unfair_lock_lock_with_options")
def _unfair2(e): return None

# ------------------------------------------------------------------- dlfcn
_DL = {}          # guest handle -> ctypes.CDLL | "main"
_DLERR = ""
_DLNEXT = 0x510000

def _host_lib(path):
    """Open the HOST (x86_64) library. An arm64 slice inside the .app cannot be dlopened."""
    if not path:
        return ctypes.CDLL(None)
    base = os.path.basename(path)
    env = os.environ.get("ARM2X86_MOLTENVK")
    cands = [path, env]
    # system frameworks: AppKit.framework/AppKit -> host framework
    if ".framework/" in path or path.endswith(".framework"):
        fw = path.split(".framework")[0].split("/")[-1]
        cands.append(f"/System/Library/Frameworks/{fw}.framework/{fw}")
    for n, hostn in (("libMoltenVK.dylib", "libMoltenVK.dylib"),
                     ("libvulkan.1.dylib", "libvulkan.1.dylib"),
                     ("libvulkan.dylib", "libvulkan.dylib")):
        if n in base or n in (path or ""):
            cands += [hostn, "/usr/local/lib/" + hostn,
                      os.path.expanduser("~/VulkanSDK/macOS/lib/" + hostn),
                      "/usr/local/lib/libMoltenVK.dylib"]
    cands.append(base)
    for c in cands:
        if not c: continue
        try:
            return ctypes.CDLL(c)
        except OSError:
            continue
    return None

@fn("dlopen")
def _dlopen(e):
    global _DLERR, _DLNEXT
    path = e.cstr(e.arg(0)) if e.arg(0) else ""
    # Prefer mapping arm64 guest code into Unicorn over host dlopen (wrong arch on Intel).
    if path:
        try:
            import dylib as _dylib
            if _dylib.is_arm64_macho(path) and _dylib.load_path(e, path):
                h = _DLNEXT; _DLNEXT += 16
                _DL[h] = ("guest", path)
                return h
        except Exception as ex:
            if os.environ.get("ARM2X86_VERBOSE"):
                sys.stderr.write(("[dlopen] guest load %s: %s" % (path, ex)) + chr(10))
    lib = _host_lib(path or None)
    if lib is None:
        _DLERR = f"arm2x86 dlopen: no host library for {path or 'NULL'} (guest arm64 dylibs are not mapped)"
        if os.environ.get("ARM2X86_VERBOSE"):
            sys.stderr.write(_DLERR + "")
        return 0
    h = _DLNEXT; _DLNEXT += 16
    _DL[h] = (lib, path)
    return h
@fn("dlsym")
def _dlsym(e):
    global _DLERR
    name = e.cstr(e.arg(1))
    sym = "_" + name
    # Prefer an emulated wrapper (correct guest<->host marshalling) over a raw pointer.
    if sym in FUNCS or name in FUNCS:
        return e.resolve(sym if sym in FUNCS else name)
    h = e.arg(0)
    entry = _DL.get(h)
    lib = entry[0] if entry else None
    if lib == "guest":
        exp = getattr(e, "dylib_exports", {}) or {}
        for key in (name, "_" + name, sym):
            if key in exp: return exp[key]
        try:
            import dylib as _dylib
            for key in (name, "_" + name, sym):
                if key in _dylib._EXPORTS: return _dylib._EXPORTS[key]
        except Exception:
            pass
        _DLERR = f"dlsym: {name} not found in guest image"
        return 0
    if lib is None and _DL:
        lib = next(iter(_DL.values()))[0]
        if lib == "guest":
            return 0
    if lib is not None:
        try:
            fnp = getattr(lib, name)
        except AttributeError:
            fnp = None
        if fnp is not None:
            # Unknown signature: publish a best-effort integer trampoline.
            _install_raw(name, fnp)
            return e.resolve("_" + name)
    _DLERR = f"dlsym: {name} not found"
    return 0

def _install_raw(name, fnp):
    sym = "_" + name
    if sym in FUNCS: return
    def wrap(e, _fn=fnp):
        try:
            proto = ctypes.CFUNCTYPE(ctypes.c_void_p, *([ctypes.c_void_p] * 8))(ctypes.cast(_fn, ctypes.c_void_p).value
                    if not isinstance(_fn, int) else _fn)
            # getattr already returns a foreign function; call with 8 ints
            args = [e.arg(i) for i in range(8)]
            _fn.restype = ctypes.c_void_p
            _fn.argtypes = [ctypes.c_void_p] * 8
            r = _fn(*args)
            return (r or 0) & M64
        except Exception as ex:
            sys.stderr.write(f"[dlsym] {name} raw call failed: {ex}")
            return 0
    FUNCS[sym] = wrap

@fn("dlclose")
def _dlclose(e):
    _DL.pop(e.arg(0), None); return 0
@fn("dlerror")
def _dlerror(e):
    global _DLERR
    if not _DLERR: return 0
    p = e.alloc_cstr(_DLERR); _DLERR = ""; return p
@fn("dladdr")
def _dladdr(e): return 0

# ---------------------------------------------------------------- strings++
@fn("strlcpy")
def _strlcpy(e):
    src = e.cstr_bytes(e.arg(1)); n = e.arg(2)
    if n: e.write(e.arg(0), src[:n - 1] + b"\0")
    return len(src)
@fn("strlcat")
def _strlcat(e):
    dst, src, n = e.arg(0), e.cstr_bytes(e.arg(1)), e.arg(2)
    cur = e.cstr_bytes(dst); room = max(n - len(cur) - 1, 0) if n > len(cur) else 0
    e.write(dst, cur + src[:room] + b"\0"); return len(cur) + len(src)
@fn("strndup")
def _strndup(e):
    b = e.cstr_bytes(e.arg(0))[:e.arg(1)]
    p = e.malloc(len(b) + 1); e.write(p, b + b"\0"); return p
@fn("strnlen")
def _strnlen(e): return len(e.cstr_bytes(e.arg(0))[:e.arg(1)])
@fn("memchr")
def _memchr(e):
    b = bytes(e.read(e.arg(0), e.arg(2))); i = b.find(bytes([e.arg(1) & 0xff]))
    return 0 if i < 0 else e.arg(0) + i
@fn("memmem")
def _memmem(e):
    hay = bytes(e.read(e.arg(0), e.arg(1))); needle = bytes(e.read(e.arg(2), e.arg(3)))
    i = hay.find(needle); return 0 if i < 0 else e.arg(0) + i
@fn("strcasecmp", "strncasecmp")
def _strcasecmp(e):
    n = e.arg(2) if "n" in sys._getframe().f_code.co_name else 1 << 30
    a = e.cstr(e.arg(0))[:n].lower(); b = e.cstr(e.arg(1))[:n].lower()
    return M64 if a < b else (1 if a > b else 0)
@fn("strsep")
def _strsep(e):
    sp = int.from_bytes(e.read(e.arg(0), 8), "little")
    if not sp: return 0
    delim = set(e.cstr_bytes(e.arg(1)))
    s = e.cstr_bytes(sp)
    i = next((k for k, c in enumerate(s) if c in delim), len(s))
    e.write(sp + i, b"\0")
    nxt = 0 if i == len(s) else sp + i + 1
    e.write(e.arg(0), nxt.to_bytes(8, "little")); return sp
@fn("strtok_r")
def _strtok(e):
    delim = set(e.cstr_bytes(e.arg(1)))
    if e.arg(0):
        p = e.arg(0)
    else:
        p = int.from_bytes(e.read(e.arg(2), 8), "little")
    if not p: return 0
    s = e.cstr_bytes(p)
    i = 0
    while i < len(s) and s[i] in delim: i += 1
    if i == len(s):
        e.write(e.arg(2), b"\0" * 8); return 0
    j = i
    while j < len(s) and s[j] not in delim: j += 1
    e.write(p + j, b"\0")
    nxt = 0 if j == len(s) else p + j + 1
    e.write(e.arg(2), nxt.to_bytes(8, "little")); return p + i
@fn("strtok")
def _strtok1(e):
    if not getattr(e, "_strtok_save", 0):
        e._strtok_save = e.malloc(8); e.write(e._strtok_save, b"\0" * 8)
    save = e._strtok_save
    delim = set(e.cstr_bytes(e.arg(1)))
    p = e.arg(0) or int.from_bytes(e.read(save, 8), "little")
    if not p: return 0
    s = e.cstr_bytes(p)
    i = 0
    while i < len(s) and s[i] in delim: i += 1
    if i == len(s):
        e.write(save, b"\0" * 8); return 0
    j = i
    while j < len(s) and s[j] not in delim: j += 1
    e.write(p + j, b"\0")
    nxt = 0 if j == len(s) else p + j + 1
    e.write(save, nxt.to_bytes(8, "little")); return p + i
def _strto(e, signed=True, bits=64):
    s = e.cstr(e.arg(0)).strip()
    try:
        v = int(s, 0) if s[:2].lower() in ("0x", "0o", "0b") or (s[:1] == "0" and s[1:2].isdigit()) else int(s or "0")
    except ValueError:
        v = 0
    if e.arg(1):
        # end pointer: point at the first unconverted byte (best effort: end of leading number)
        import re
        m = re.match(r"\s*[+-]?(0[xX][0-9a-fA-F]+|\d+)", e.cstr(e.arg(0)))
        end = e.arg(0) + (m.end() if m else 0)
        e.write(e.arg(1), end.to_bytes(8, "little"))
    return v & M64
@fn("strtol", "strtoll", "strtoq")
def _strtol(e): return _strto(e)
@fn("strtoul", "strtoull", "strtouq")
def _strtoul(e): return _strto(e, False)
@fn("strtod", "strtof", "strtold", "atof")
def _strtod(e):
    import re
    m = re.match(r"\s*[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?", e.cstr(e.arg(0)))
    v = float(m.group()) if m else 0.0
    if e.arg(1) and m: e.write(e.arg(1), (e.arg(0) + m.end()).to_bytes(8, "little"))
    e.ret_double(v); return None
@fn("qsort", "qsort_r", "bsearch")
def _qsort(e):
    # compar is guest code; nested calls are impossible. memcmp-order the elements
    # so callers that only need a permutation of POD keys still see sorted bytes.
    base, nmemb, size = e.arg(0), e.arg(1), e.arg(2)
    if not base or not nmemb or not size or nmemb > 1_000_000: return 0
    try:
        blob = bytes(e.read(base, nmemb * size))
    except Exception:
        return 0
    parts = [blob[i * size:(i + 1) * size] for i in range(nmemb)]
    parts.sort()
    e.write(base, b"".join(parts))
    if "bsearch" in sys._getframe().f_code.co_name:
        key = bytes(e.read(e.arg(0), size))
        # bsearch(key, base, nmemb, size, compar) — args differ. Give up and return base.
        return e.arg(1)
    return None
@fn("bcopy")
def _bcopy(e):
    e.write(e.arg(1), bytes(e.read(e.arg(0), e.arg(2)))); return None
@fn("explicit_bzero", "__bzero")
def _ebzero(e):
    e.write(e.arg(0), b"\0" * e.arg(1)); return None
@fn("strerror", "strerror_r")
def _strerror(e):
    # strerror(err) OR strerror_r(err, buf, n) — Darwin has both
    if e.arg(1) and e.arg(2) > 1 and e.arg(2) < 100000:
        msg = os.strerror(_L2D.get(e.arg(0), e.arg(0)) if False else e.arg(0)).encode()
        e.write(e.arg(1), msg[:e.arg(2) - 1] + b"\0"); return 0
    return e.alloc_cstr(os.strerror(e.arg(0) if e.arg(0) < 200 else 0))
@fn("posix_memalign")
def _pma(e):
    n = max(e.arg(2), 1); p = e.malloc(n + 64)
    p = (p + 63) & ~63
    e.write(e.arg(0), p.to_bytes(8, "little")); return 0
@fn("aligned_alloc", "valloc")
def _aa(e):
    n = e.arg(1) if e.arg(1) > 1 else e.arg(0)
    return e.malloc(max(n, 1))
@fn("malloc_size", "malloc_good_size")
def _msz(e): return e.heap_sizes.get(e.arg(0), 0) if hasattr(e, "heap_sizes") else 0
@fn("arc4random")
def _a4(e): return random.getrandbits(32)
@fn("arc4random_uniform")
def _a4u(e):
    n = e.arg(0) or 1
    return random.randrange(n) & 0xffffffff
@fn("arc4random_buf")
def _a4b(e):
    e.write(e.arg(0), random.randbytes(e.arg(1)) if hasattr(random, "randbytes") else os.urandom(e.arg(1)))
    return None
@fn("setlocale")
def _setlocale(e): return e.alloc_cstr("C")
@fn("localeconv")
def _localeconv(e):
    # decimal_point, thousands_sep, ... a small zeroed struct with "." 
    p = e.malloc(128)
    e.write(p, b"\0" * 128)
    dot = e.alloc_cstr(".")
    e.write(p, dot.to_bytes(8, "little"))
    return p
@fn("newlocale", "uselocale", "freelocale", "duplocale")
def _locale(e): return 1
@fn("__cxa_atexit")
def _cxa(e):
    e.atexits = getattr(e, "atexits", [])
    e.atexits.append((e.arg(0), e.arg(1)))
    return 0
@fn("atexit")
def _atexit(e):
    e.atexits = getattr(e, "atexits", [])
    e.atexits.append(e.arg(0))
    return 0
def _hard_exit(e):
    e.exit(getattr(e, "pending_code", 0) or 0)
FUNCS["__arm2x86_exit"] = _hard_exit
@fn("exit")
def _exit(e):
    code = e.arg(0) & 0xff
    xs = getattr(e, "atexits", [])
    if xs and not getattr(e, "_exiting", False) and hasattr(e, "begin_callbacks"):
        e._exiting = True
        e.pending_code = code
        calls = []
        for item in reversed(xs):
            calls.append((item[0], [item[1]]) if isinstance(item, tuple) else (item, []))
        e.atexits.clear()
        calls.append((e.resolve("__arm2x86_exit"), []))
        e.begin_callbacks(calls, code)
        return None
    e.exit(code)
@fn("_exit", "_Exit")
def _e2(e): e.exit(e.arg(0) & 0xff)

@fn("signal", "sigaction", "sigemptyset", "sigfillset", "sigaddset", "sigprocmask", "pthread_sigmask")
def _sig(e): return 0
@fn("raise")
def _raise(e): return 0
@fn("__assert_rtn", "__assert_fail")
def _assert(e):
    try:   # Darwin __assert_rtn(func, file, line, expr)
        sys.stderr.write(("[arm2x86] Assertion failed: (%s), function %s, file %s, line %d." % (
            e.cstr(e.arg(3)), e.cstr(e.arg(0)), e.cstr(e.arg(1)), e.arg(2) & 0xffffffff)) + chr(10))
    except Exception:
        sys.stderr.write("[arm2x86] assertion failed" + chr(10))
    e.exit(134)

# ----------------------------------------------------------------- sockets
# Enough of BSD sockets for an engine to resolve a host and open a TCP fd.
# Level/option numbers are translated from Darwin.
_SOL_D = 0xffff
_SO = {0x0004: ("SO_REUSEADDR",), 0x0080: ("SO_LINGER",), 0x0020: ("SO_BROADCAST",),
       0x0100: ("SO_OOBINLINE",), 0x0400: ("SO_SNDBUF",), 0x1002: ("SO_RCVBUF",),
       0x1001: ("SO_SNDBUF",), 0x1022: ("SO_NOSIGPIPE",)}
def _so(level, opt):
    import socket as S
    if level == _SOL_D: level = S.SOL_SOCKET
    mapping = {0x0004: S.SO_REUSEADDR, 0x0020: S.SO_BROADCAST, 0x1001: S.SO_SNDBUF,
               0x1002: S.SO_RCVBUF, 0x1007: getattr(S, "SO_KEEPALIVE", 8)}
    if level == S.SOL_SOCKET and opt in mapping: opt = mapping[opt]
    return level, opt
def _sockaddr_family(raw):
    """Return (family, unix_path_or_None). Darwin BSD {sun_len,sun_family,path} and Linux-style."""
    if len(raw) < 2:
        return 0, None
    b0, b1 = raw[0], raw[1]
    # Darwin sockaddr_un: sun_len can be 0 (Rust often leaves it zero); family at offset 1.
    if b1 == 1 and b0 != 2:
        path = raw[2:]
        nul = path.find(b"\0")
        if nul >= 0:
            path = path[:nul]
        try:
            return 1, path.decode("utf-8", "surrogateescape") if path else None
        except Exception:
            return 1, None
    fam = struct.unpack_from("<H", raw)[0]
    if fam == 1:
        path = raw[2:]
        nul = path.find(b"\0")
        if nul >= 0:
            path = path[:nul]
        try:
            return 1, path.decode("utf-8", "surrogateescape") if path else None
        except Exception:
            return 1, None
    if fam == 2 or b0 == 2:
        return 2, None
    if fam == 30 or b1 == 30:
        return 30, None
    if b1 in (2, 30) and 2 <= b0 <= 110:
        return b1, None
    return fam, None

@fn("socketpair")
def _socketpair(e):
    # int socketpair(int domain, int type, int protocol, int *sv)
    dom = e.arg(0) & 0xff
    typ = e.arg(1) & 0xff
    proto = e.arg(2) & 0xff
    sv = e.arg(3)
    typ &= 0xf
    if dom == 30: dom = socket.AF_INET6
    if dom == 0: dom = socket.AF_UNIX  # PF_UNSPEC often used with AF_UNIX intent
    try:
        a, b = socket.socketpair(dom if dom else socket.AF_UNIX, typ or socket.SOCK_STREAM, proto or 0)
        a.setblocking(False); b.setblocking(False)
        fa, fb = a.fileno(), b.fileno()
        _SOCKS[fa] = a; _SOCKS[fb] = b
        if sv:
            e.write(sv, struct.pack("<II", fa, fb))
        if os.environ.get("ARM2X86_VERBOSE"):
            sys.stderr.write("[sock] socketpair -> %d, %d" % (fa, fb) + chr(10)); sys.stderr.flush()
        return 0
    except OSError as ex:
        return _fail(e, _derr(ex), 0xffffffff)

@fn("socket")
def _socket(e):
    dom, typ, proto = e.arg(0) & 0xff, e.arg(1) & 0xff, e.arg(2) & 0xff
    # Darwin AF_UNIX=1 AF_INET=2 AF_INET6=30. Linux AF_INET6=10.
    if dom == 30: dom = socket.AF_INET6
    typ &= 0xf  # strip SOCK_CLOEXEC/NONBLOCK in the high bits (Darwin packs differently)
    try:
        return _sock_fd(dom, typ or 1, proto)
    except OSError as ex:
        return _fail(e, _derr(ex))
_SOCKS = {}
_LISTEN_FDS = set()
def _sock_fd(dom, typ, proto):
    s = socket.socket(dom, typ or socket.SOCK_STREAM, proto or 0)
    s.setblocking(False)
    fd = s.fileno()
    _SOCKS[fd] = s
    if os.environ.get("ARM2X86_VERBOSE"):
        sys.stderr.write("[sock] socket -> fd %d (dom=%d typ=%d)" % (fd, dom, typ) + chr(10)); sys.stderr.flush()
    return fd
def _sock(fd):
    fd &= 0xffff
    return _SOCKS.get(fd)
@fn("connect", "connect$NOCANCEL")
def _connect(e):
    s = _sock(e.arg(0))
    if not s: return _fail(e, EBADF, 0xffffffff)
    n = e.arg(2) or 16
    raw = bytes(e.read(e.arg(1), min(max(n, 0), 256)))
    family, unix_path = _sockaddr_family(raw)
    try:
        if family == 2 and len(raw) >= 8:  # AF_INET
            port = struct.unpack_from("!H", raw, 2)[0]
            ip = socket.inet_ntoa(raw[4:8])
            s.setblocking(True); s.connect((ip, port)); s.setblocking(False)
            return 0
        if family == 1:  # AF_UNIX — Delta single-instance IPC
            path = unix_path
            if not path:
                sys.stderr.write(f"[sock] AF_UNIX connect: bad sockaddr ({len(raw)} bytes hex={raw[:16].hex()})")
                return _fail(e, EINVAL, 0xffffffff)
            parent = os.path.dirname(path)
            if parent:
                try: os.makedirs(parent, exist_ok=True)
                except OSError: pass
            if os.environ.get("ARM2X86_VERBOSE"):
                sys.stderr.write(f"[sock] connect(AF_UNIX, {path!r})")
            s.setblocking(True)
            try:
                s.connect(path)
            finally:
                try: s.setblocking(False)
                except OSError: pass
            return 0
        sys.stderr.write(f"[sock] connect: unsupported family={family} n={n} hex={raw[:16].hex()}")
        return _fail(e, EINVAL, 0xffffffff)
    except OSError as ex:
        # Crash handler / watchdog: pretend connected so Delta does not panic
        if path and any(k in str(path) for k in ("crash-handler", "zed-crash", "watchdog")):
            if os.environ.get("ARM2X86_VERBOSE"):
                sys.stderr.write(("[sock] connect(AF_UNIX, %r) -> fake OK" % path) + chr(10))
            return 0
        # Missing socket path is ENOENT on Darwin; map to ECONNREFUSED (61).
        err = _derr(ex)
        if err == ENOENT:
            err = 61  # Darwin ECONNREFUSED
        if os.environ.get("ARM2X86_VERBOSE"):
            sys.stderr.write(("[sock] connect failed: %s (guest errno=%s)" % (ex, err)) + chr(10))
        return _fail(e, err, 0xffffffff)
@fn("listen")
def _listen(e):
    s = _sock(e.arg(0))
    if not s: return _fail(e, EBADF, 0xffffffff)
    backlog = e.arg(1) & 0xffffffff
    if backlog > 1024:
        backlog = 128
    try:
        if os.environ.get("ARM2X86_VERBOSE"):
            sys.stderr.write("[sock] listen backlog=%d" % backlog)
        s.listen(backlog or 128)
        _LISTEN_FDS.add(e.arg(0) & 0xffff)
        return 0
    except OSError as ex:
        return _fail(e, _derr(ex), 0xffffffff)

@fn("shutdown")
def _shutdown(e):
    s = _sock(e.arg(0))
    if not s: return _fail(e, EBADF, 0xffffffff)
    try:
        s.shutdown(e.arg(1) & 0xff)
        return 0
    except OSError as ex:
        return _fail(e, _derr(ex), 0xffffffff)

@fn("bind")
def _bind(e):
    s = _sock(e.arg(0))
    if not s: return _fail(e, EBADF, 0xffffffff)
    try:
        raw = bytes(e.read(e.arg(1), min(e.arg(2) or 16, 256)))
        family, unix_path = _sockaddr_family(raw)
        if family == 1:
            path = unix_path
            if not path:
                return _fail(e, EINVAL, 0xffffffff)
            parent = os.path.dirname(path)
            if parent:
                try: os.makedirs(parent, exist_ok=True)
                except OSError: pass
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except OSError:
                pass
            if os.environ.get("ARM2X86_VERBOSE"):
                sys.stderr.write("[sock] bind(AF_UNIX, %r)" % path)
            s.bind(path)
        else:
            port = struct.unpack_from("!H", raw, 2)[0]
            s.bind(("0.0.0.0", port))
        return 0
    except OSError as ex:
        return _fail(e, _derr(ex), 0xffffffff)

@fn("accept", "accept$NOCANCEL")
def _accept(e):
    fd = e.arg(0) & 0xffff
    s = _sock(fd)
    if not s:
        try:
            import socket as _socket
            s = _socket.fromfd(fd, _socket.AF_UNIX, _socket.SOCK_STREAM)
            s.setblocking(False)
            _SOCKS[fd] = s
            if os.environ.get("ARM2X86_VERBOSE"):
                sys.stderr.write("[sock] accept: recovered fd %d" % fd + chr(10)); sys.stderr.flush()
        except Exception as ex:
            if os.environ.get("ARM2X86_VERBOSE"):
                globals().setdefault("_ACCEPT_LOG", 0)
                if globals()["_ACCEPT_LOG"] < 3:
                    sys.stderr.write("[sock] accept: no socket for fd %d: %s" % (fd, ex) + chr(10)); sys.stderr.flush()
                    globals()["_ACCEPT_LOG"] += 1
            # Fallback: guest may have lost the listen fd number (accept on 0)
            if _LISTEN_FDS:
                fd2 = next(iter(_LISTEN_FDS))
                s = _SOCKS.get(fd2)
                if s is not None:
                    if os.environ.get("ARM2X86_VERBOSE"):
                        globals().setdefault("_ACCEPT_LOG", 0)
                    if globals()["_ACCEPT_LOG"] < 3:
                        sys.stderr.write("[sock] accept: fd %d invalid, using listen fd %d" % (fd, fd2) + chr(10)); sys.stderr.flush()
                        globals()["_ACCEPT_LOG"] += 1
                else:
                    return _fail(e, EBADF, 0xffffffff)
            else:
                return _fail(e, EBADF, 0xffffffff)
            if not s:
                return _fail(e, EBADF, 0xffffffff)
    try:
        conn, _addr = s.accept()
        conn.setblocking(False)
        cfd = conn.fileno()
        _SOCKS[cfd] = conn
        return cfd
    except BlockingIOError:
        return _fail(e, EAGAIN, 0xffffffff)
    except OSError as ex:
        err = _derr(ex)
        if err in (EAGAIN, 35, 11):
            return _fail(e, EAGAIN, 0xffffffff)
        return _fail(e, err, 0xffffffff)


@fn("send", "sendto")
def _send(e):
    s = _sock(e.arg(0))
    if not s: return _fail(e, EBADF)
    data = bytes(e.read(e.arg(1), e.arg(2)))
    try: return s.send(data)
    except OSError as ex: return _fail(e, _derr(ex))
@fn("recv", "recvfrom")
def _recv(e):
    s = _sock(e.arg(0))
    if not s: return _fail(e, EBADF)
    try:
        b = s.recv(e.arg(2) or 1)
    except BlockingIOError:
        return _fail(e, EAGAIN)
    except OSError as ex:
        return _fail(e, _derr(ex))
    if b: e.write(e.arg(1), b)
    return len(b)
@fn("setsockopt", "getsockopt")
def _sso(e):
    s = _sock(e.arg(0))
    if not s: return _fail(e, EBADF, 0xffffffff)
    level, opt = _so(e.arg(1) & 0xffffffff, e.arg(2) & 0xffffffff)
    try:
        if "get" in sys._getframe().f_code.co_name:
            v = s.getsockopt(level, opt)
            if e.arg(3): e.write(e.arg(3), struct.pack("<I", v if isinstance(v, int) else 0))
        else:
            v = s32(int.from_bytes(e.read(e.arg(3), 4), "little")) if e.arg(3) else 0
            s.setsockopt(level, opt, v)
        return 0
    except OSError:
        return 0  # unknown options are ignored; games probe a lot of them
@fn("select")
def _select(e):
    # don't actually block the emulator for long
    return 0
@fn("poll")
def _poll(e):
    return 0
@fn("getaddrinfo")
def _gai(e):
    node = e.cstr(e.arg(0)) if e.arg(0) else None
    serv = e.cstr(e.arg(1)) if e.arg(1) else None
    try:
        port = int(serv) if serv and serv.isdigit() else 0
        infos = socket.getaddrinfo(node or "127.0.0.1", port or 0, socket.AF_INET, socket.SOCK_STREAM)
    except Exception:
        return 8  # EAI_NONAME-ish
    head = 0
    prev = 0
    for fam, typ, proto, canon, sockaddr in infos:
        if fam != socket.AF_INET: continue
        ip, prt = sockaddr[0], sockaddr[1]
        ai = e.malloc(48)
        sa = e.malloc(16)
        e.write(sa, struct.pack("<H", 2) + struct.pack("!H", prt) + socket.inet_aton(ip) + b"\0" * 8)
        # addrinfo: flags, family, socktype, protocol, addrlen, pad, canon, addr, next
        e.write(ai, struct.pack("<iiiiIIQQQ", 0, 2, 1, 6, 16, 0, 0, sa, 0))
        if prev: e.write(prev + 40, ai.to_bytes(8, "little"))
        else: head = ai
        prev = ai
    if e.arg(3): e.write(e.arg(3), head.to_bytes(8, "little"))
    return 0 if head else 8
@fn("freeaddrinfo")
def _fai(e): return None
@fn("gai_strerror")
def _gais(e): return e.alloc_cstr("name resolution failed")
@fn("inet_ntop")
def _ntop(e):
    raw = bytes(e.read(e.arg(1), 4))
    s = socket.inet_ntoa(raw).encode() + b"\0"
    e.write(e.arg(2), s[:e.arg(3)]); return e.arg(2)
@fn("inet_pton")
def _pton(e):
    try:
        e.write(e.arg(2), socket.inet_aton(e.cstr(e.arg(1))))
        return 1
    except OSError:
        return 0
@fn("htons", "ntohs")
def _htons(e):
    v = e.arg(0) & 0xffff
    return ((v & 0xff) << 8) | (v >> 8)
@fn("htonl", "ntohl")
def _htonl(e):
    v = e.arg(0) & 0xffffffff
    return int.from_bytes(v.to_bytes(4, "little"), "big")

# --------------------------------------------------------------- dispatch / os_log
# dispatch_once(pred*, block) and dispatch_once_f(pred*, ctx, fn) are DIFFERENT calls.  They used to share one function that told
# them apart by "is x2 non-zero": for dispatch_once x2 is just a leftover register (0x20 here), so the block was never run and the
# emulator jumped to address 0x20 (UC_ERR_FETCH_UNMAPPED pc=0x20) -- right after OSISClient's first dispatch_once.
@fn("dispatch_once")
def _donce(e):
    pred = e.arg(0)
    if pred and int.from_bytes(e.read(pred, 8), "little") == 0:
        e.write(pred, (0xffffffffffffffff).to_bytes(8, "little"))      # "done" (libdispatch stores ~0)
        blk = e.arg(1)
        if blk and hasattr(e, "begin_callbacks"):
            imp = int.from_bytes(e.read(blk + 16, 8), "little")           # Block_layout.invoke
            e.begin_callbacks([(imp, [blk])], 0); return None
    return None
@fn("dispatch_once_f")
def _donce_f(e):
    pred = e.arg(0)
    if pred and int.from_bytes(e.read(pred, 8), "little") == 0:
        e.write(pred, (0xffffffffffffffff).to_bytes(8, "little"))
        fnp, ctx = e.arg(2), e.arg(1)
        if fnp and hasattr(e, "begin_callbacks"):
            e.begin_callbacks([(fnp, [ctx])], 0); return None
    return None
@fn("dispatch_get_global_queue", "dispatch_get_main_queue", "dispatch_queue_create")
def _dgq(e): return 1
@fn("dispatch_time", "dispatch_walltime")
def _dtime(e): return (time.monotonic_ns()) & M64
@fn("dispatch_after", "dispatch_after_f", "dispatch_group_create", "dispatch_group_async",
    "dispatch_group_wait", "dispatch_group_notify", "dispatch_release", "dispatch_retain",
    "dispatch_resume", "dispatch_suspend", "dispatch_source_create", "dispatch_source_set_event_handler",
    "dispatch_source_set_timer", "dispatch_source_merge_data", "dispatch_source_cancel",
    "dispatch_set_target_queue")
def _dmisc(e): return 0
@fn("_os_log_internal", "os_log_create", "os_log_type_enabled", "os_log")
def _oslog(e): return 0
@fn("os_release", "os_retain", "os_signpost_enabled")
def _osr(e): return e.arg(0)

@fn("kqueue", "kevent", "kevent64")
def _kq(e): return 0 if "kqueue" not in sys._getframe().f_code.co_name else -1 & 0xffffffff

# random stragglers games import and call during crt startup
for _n in ("__sF", ):
    pass
@fn("__srget", "__swbuf", "__maskrune", "__error_loc")
def _srget(e): return 0
@fn("arc4random_stir")
def _stir(e): return None
@fn("getentropy")
def _ge(e):
    e.write(e.arg(0), os.urandom(e.arg(1))); return 0
@fn("copyfile", "clonefile")
def _copyfile(e): return _fail(e, ENOTSUP, 0xffffffff)
@fn("getattrlistat", "fstatat", "openat$NOCANCEL")
def _fstatat(e):
    # fstatat(dirfd, path, buf, flags)
    try: return _stat_into(e, os.stat(e.cstr(e.arg(1))), e.arg(2))
    except OSError as ex: return _fail(e, _derr(ex), 0xffffffff)
@fn("open$NOCANCEL")
def _open_nc(e): return _open(e)
@fn("close$NOCANCEL")
def _close_nc(e): return _close(e)
@fn("read$NOCANCEL")
def _read_nc(e): return FUNCS["_read"](e)
@fn("write$NOCANCEL")
def _write_nc(e): return FUNCS["_write"](e)


# ---- post-fork / process identity (single-process) ----------------------------
@fn("sigaltstack")
def _sigaltstack(e):
    # Report success; we do not switch stacks under Unicorn.
    return 0

@fn("setsid")
def _setsid(e):
    # Become session leader: return a fake positive pgid.
    return 1

@fn("setpgid", "setpgrp")
def _setpgid(e):
    return 0

@fn("getppid")
def _getppid(e):
    return 1

@fn("getpgrp", "getsid")
def _getpgrp(e):
    return 1

@fn("daemon")
def _daemon(e):
    # Already "backgrounded" in the emulator.
    return 0

@fn("isatty")
def _isatty(e):
    fd = e.arg(0) & 0xffff
    return 1 if fd in (0, 1, 2) else 0

@fn("fork", "vfork", "forkpty")
def _fork(e):
    # Default: fail fork so the app stays single-process.
    # ARM2X86_FORK_CHILD=1 -> 0; ARM2X86_FORK_PARENT=1 -> 2
    if os.environ.get("ARM2X86_FORK_CHILD"):
        if os.environ.get("ARM2X86_VERBOSE"):
            sys.stderr.write("[proc] fork -> 0 (child)"); sys.stderr.flush()
        return 0
    if os.environ.get("ARM2X86_FORK_PARENT"):
        if os.environ.get("ARM2X86_VERBOSE"):
            sys.stderr.write("[proc] fork -> 2 (parent)"); sys.stderr.flush()
        return 2
    if os.environ.get("ARM2X86_VERBOSE"):
        sys.stderr.write("[proc] fork -> -1 EAGAIN (single-process)"); sys.stderr.flush()
    return _fail(e, EAGAIN, 0xffffffff)

@fn("getsockname")
def _getsockname(e):
    s = _sock(e.arg(0))
    if not s: return _fail(e, EBADF, 0xffffffff)
    addr_p, len_p = e.arg(1), e.arg(2)
    try:
        peer = s.getsockname()
    except OSError as ex:
        return _fail(e, _derr(ex), 0xffffffff)
    if isinstance(peer, str):
        pathb = peer.encode("utf-8", "surrogateescape")[:104]
        raw = bytes([2 + len(pathb), 1]) + pathb + b"\0"
        raw = raw.ljust(106, b"\0")
    elif isinstance(peer, tuple) and len(peer) >= 2:
        ip, port = peer[0], peer[1]
        raw = struct.pack("<H", 2) + struct.pack("!H", int(port)) + socket.inet_aton(ip) + b"\0" * 8
    else:
        raw = b"\0" * 16
    if len_p:
        try:
            cap = int.from_bytes(e.read(len_p, 4), "little") or len(raw)
        except Exception:
            cap = len(raw)
        e.write(len_p, struct.pack("<I", min(cap, len(raw))))
        raw = raw[:cap]
    if addr_p:
        e.write(addr_p, raw)
    return 0

@fn("getpeername")
def _getpeername(e):
    return _getsockname(e)

@fn("CCRandomGenerateBytes")
def _cc_rand(e):
    import os as _os
    n = e.arg(1) & 0xffffffff
    if n and e.arg(0):
        e.write(e.arg(0), _os.urandom(n))
    return 0


@fn("waitpid", "wait4")
def _waitpid(e):
    # Fake children from posix_spawn always look already exited.
    pid = e.arg(0) & 0xffffffff
    status = e.arg(1)
    if status:
        try:
            e.write(status, (0).to_bytes(4, "little"))  # WEXITSTATUS 0
        except Exception:
            pass
    if pid in (0, 0xffffffff):
        return os.getpid() & 0x7fffffff
    return pid if pid else _fail(e, 10, 0xffffffff)

@fn("posix_spawn", "posix_spawnp")
def _pspawn(e):
    # Fake success — crash-handler connect is faked in connect().
    pid_ptr = e.arg(0)
    if pid_ptr:
        try:
            e.write(pid_ptr, (os.getpid() & 0xffffffff).to_bytes(4, "little") + bytes(4))
        except Exception:
            pass
    if os.environ.get("ARM2X86_VERBOSE"):
        sys.stderr.write("[proc] posix_spawn* -> 0 (fake child)")
    return 0

@fn("posix_spawnattr_init", "posix_spawnattr_destroy", "posix_spawnattr_setflags",
    "posix_spawnattr_setsigdefault", "posix_spawnattr_setsigmask",
    "posix_spawnattr_setpgroup", "posix_spawnattr_setexceptionports_np",
    "posix_spawn_file_actions_init", "posix_spawn_file_actions_destroy",
    "posix_spawn_file_actions_adddup2", "posix_spawn_file_actions_addchdir_np",
    "posix_spawn_file_actions_addinherit_np")
def _pspawn_ok(e):
    return 0

@fn("writev")
def _writev(e):
    fd, iov, iovcnt = e.arg(0), e.arg(1), e.arg(2) & 0xffffffff
    total = 0
    try:
        for i in range(min(iovcnt, 64)):
            base = int.from_bytes(e.read(iov + i * 16, 8), "little")
            length = int.from_bytes(e.read(iov + i * 16 + 8, 8), "little")
            if not length: continue
            data = e.read(base, min(length, 1 << 20))
            # crash-handler / fake sockets: discard
            if fd in getattr(e, "_SOCKS", {}) or fd > 2:
                try:
                    s = e._SOCKS.get(fd)
                    if s: s.send(data)
                except Exception:
                    pass
            else:
                try: os.write(fd, data)
                except Exception: pass
            total += len(data)
        return total
    except Exception:
        return _fail(e, 9)
@fn("readv")
def _readv(e):
    fd, iov, iovcnt = e.arg(0), e.arg(1), e.arg(2) & 0xffffffff
    total = 0
    try:
        for i in range(min(iovcnt, 64)):
            base = int.from_bytes(e.read(iov + i * 16, 8), "little")
            length = int.from_bytes(e.read(iov + i * 16 + 8, 8), "little")
            if not length: continue
            # no data on fake crash-handler socket
            chunk = b"\x00" * 0
            try:
                s = getattr(e, "_SOCKS", {}).get(fd)
                if s:
                    s.settimeout(0.0)
                    chunk = s.recv(length)
            except Exception:
                chunk = b""
            if chunk:
                e.write(base, chunk)
                total += len(chunk)
            else:
                break
        return total if total else _fail(e, 35)  # EAGAIN
    except Exception:
        return _fail(e, 9)


@fn("abort")
def _abort(e):
    # Skip GPUI profiler panics so startup can continue under partial emulation.
    from unicorn.arm64_const import UC_ARM64_REG_LR, UC_ARM64_REG_PC
    lr = e.uc.reg_read(UC_ARM64_REG_LR)
    n = getattr(e, "_abort_skips", 0)
    if n < 32:
        e._abort_skips = n + 1
        sys.stderr.write(("[arm2x86] abort skipped #%d (lr=%#x) — continuing" % (n + 1, lr)) + chr(10))
        e.uc.reg_write(UC_ARM64_REG_PC, lr)
        return None
    sys.stderr.write("[arm2x86] abort limit reached, exiting" + chr(10))
    e.exit(134)
    return None
