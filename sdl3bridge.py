"""
SDL3 bridge: the guest's SDL_* imports are forwarded to the HOST's real libSDL3 (the app ships a universal
libSDL3.0.dylib; on an Intel Mac ctypes loads its x86_64 slice). Marshalling is driven by sdl3sigs.SIGS
(exact argtypes/restype generated from pysdl3 by gen_sdl3sigs.py).

  ints / floats      : read from x0..x7 / d0..d7 (objc.ArgReader, AAPCS64) and passed natively
  const char*        : guest C string -> host bytes
  POINTER(T)         : guest buffer copied to a host buffer (sizeof(T) * count), copied back after the call
  void*              : opaque (handles, userdata) unless the function needs real bytes (BUF table)
  callbacks          : host trampoline that QUEUES a call into the guest (runs at the next bridged call)
  returned structs the guest reads directly (SDL_Surface, SDL_Texture, keyboard state, id arrays, WAV data)
                     : mirrored into guest memory; guest->host pointer translation via g2h
Host lib search: $ARM2X86_SDL3, then libSDL3*.dylib next to the executable, then the system.
Debug: ARM2X86_SDLTRACE=1 logs every bridged call and SDL_GetError() after a failure.
"""
import os, sys, struct, ctypes, threading
from ctypes import c_void_p
import hle, objc
from hle import FUNCS, M64
from unicorn.arm64_const import *
def _load_sigs():
    try:
        from sdl3sigs import SIGS; return SIGS
    except ImportError: pass
    here = os.path.dirname(os.path.abspath(__file__)); gen = os.path.join(here, "gen_sdl3sigs.py")
    try:                                              # pysdl3 installed? then generate the table now (one-time, ~10 s)
        import importlib.util
        if importlib.util.find_spec("sdl3") and os.path.exists(gen):
            sys.stderr.write("[sdl3] generating sdl3sigs.py from pysdl3 (first run only)...\n")
            import subprocess
            subprocess.run([sys.executable, gen], stdout=sys.stderr, stderr=subprocess.DEVNULL, timeout=300)
            import importlib; importlib.invalidate_caches()
            from sdl3sigs import SIGS; return SIGS
    except Exception as ex: sys.stderr.write(f"[sdl3] could not generate sdl3sigs.py: {ex}\n")
    sys.stderr.write("[sdl3] SDL_* calls are NOT bridged (no sdl3sigs.py). Run once:  pip3 install pysdl3  (then just run the game again)\n")
    return {}
SIGS = _load_sigs()

TRACE = bool(os.environ.get("ARM2X86_SDLTRACE"))
_CT = {("i", 1): ctypes.c_int8, ("i", 2): ctypes.c_int16, ("i", 4): ctypes.c_int32, ("i", 8): ctypes.c_int64,
       ("u", 1): ctypes.c_uint8, ("u", 2): ctypes.c_uint16, ("u", 4): ctypes.c_uint32, ("u", 8): ctypes.c_uint64,
       ("f", 4): ctypes.c_float, ("d", 8): ctypes.c_double}
_ENC = {("i", 1): "c", ("i", 2): "s", ("i", 4): "i", ("i", 8): "q", ("u", 1): "C", ("u", 2): "S", ("u", 4): "I", ("u", 8): "Q",
        ("f", 4): "f", ("d", 8): "d"}
def ctype(k): return _CT.get((k[0], k[1]), c_void_p)

class S:                                    # bridge state
    lib = None; tried = False
    g2h, h2g = {}, {}                       # mirror address maps (guest <-> host)
    live = []                               # (host_ptr, guest_ptr, n): host->guest refresh each PollEvent/PumpEvents
    surfaces = {}                           # guest surf -> (host surf, host_pixels, guest_pixels, nbytes)
    locks = {}                              # guest tex  -> (host_pixels, guest_pixels, nbytes)
    cbs = {}                                # (guest fn, sig repr) -> host callback address
    keep = []
    pending, lock = [], threading.Lock()
    strcache = {}
def take_pending():
    with S.lock: p = S.pending[:]; S.pending.clear()
    return p

def load_lib(e):
    if S.tried: return S.lib
    S.tried = True
    cands = [os.environ.get("ARM2X86_SDL3", "")]
    d = os.path.dirname(e.path)
    for f in ("libSDL3.0.dylib", "libSDL3.dylib", "libSDL3.so.0", "libSDL3.dll"): cands.append(os.path.join(d, f))
    cands += ["libSDL3.0.dylib", "libSDL3.so.0"]
    for c in cands:
        if c:
            try: S.lib = ctypes.CDLL(c); sys.stderr.write(f"[sdl3] bridged to host {c}\n"); return S.lib
            except OSError: pass
    sys.stderr.write("[sdl3] no host libSDL3 found (set ARM2X86_SDL3=/path/to/libSDL3.0.dylib); SDL calls return 0\n")
    return None

# ---- guest memory helpers -----------------------------------------------------------------------------------
def gread(e, a, n): return bytes(e.read(a, n))
def is_guest(e, a): return objc.is_guest(e, a)
def gstr(e, v): return e.cstr_bytes(v)
def _alloc_bytes(e, b): p = e.malloc(len(b)); e.write(p, b); return p
def new_gstr(e, hptr):
    if not hptr: return 0
    s = ctypes.string_at(hptr)
    if s not in S.strcache: S.strcache[s] = _alloc_bytes(e, s + b"\0")
    return S.strcache[s]
def h(e, v): return S.g2h.get(v, v)         # guest value -> host value for opaque pointers

# ---- special per-function knowledge --------------------------------------------------------------------------
def tex_h(e, raw, ti=0):
    """height in rows of the host texture passed as arg ti (SDL_Texture: format@0 w@4 h@8)"""
    ht = S.g2h.get(raw[ti], raw[ti]); return ctypes.c_int.from_address(ht + 8).value if ht else 0
def rect_h(e, raw, ri, ti=0):
    return struct.unpack("<i", gread(e, raw[ri] + 12, 4))[0] if raw[ri] else tex_h(e, raw, ti)
BUF = {   # name -> (ptr index or tuple, size fn(e, raw), index of the length arg to shrink, or None)
    "SDL_PutAudioStreamData": (1, lambda e, a: a[2], 2),
    "SDL_GetAudioStreamData": (1, lambda e, a: a[2], 2),
    "SDL_ReadIO": (1, lambda e, a: a[2], 2),
    "SDL_WriteIO": (1, lambda e, a: a[2], 2),
    "SDL_ReadStorageFile": (2, lambda e, a: a[3], 3),
    "SDL_WriteStorageFile": (2, lambda e, a: a[3], 3),
    "SDL_SaveFile": (1, lambda e, a: a[2], 2),
    "SDL_SaveFile_IO": (1, lambda e, a: a[2], 2),
    "SDL_ReadAsyncIO": (1, lambda e, a: a[3], 3),   # (io, ptr, offset, size, ...): shrink size, never the offset
    "SDL_WriteAsyncIO": (1, lambda e, a: a[3], 3),
    "SDL_MixAudio": ((0, 1), lambda e, a: a[3], 3), # dst, src, format, len, volume — both buffers are `len` bytes
    "SDL_ConvertAudioSamples": (1, lambda e, a: a[2], 2),  # src data is arg 1, src_len is arg 2 (NOT arg 3)
    "SDL_IOFromMem": (0, lambda e, a: a[1], 1),
    "SDL_IOFromConstMem": (0, lambda e, a: a[1], 1),
    "SDL_memcpy": ((0, 1), lambda e, a: a[2], 2),
    "SDL_memmove": ((0, 1), lambda e, a: a[2], 2),
    "SDL_memset": (0, lambda e, a: a[2], 2),
    "SDL_UpdateTexture": (2, lambda e, a: a[3] * rect_h(e, a, 1), None),  # pitch * rows; no single length to shrink
}
_MAX_BUF = 64 << 20
def _uclamp(n):
    """Byte count from a guest integer. Reject negatives and sign-extended junk."""
    n = int(n or 0) & M64
    if n >= (1 << 63): return 0
    return n
def _span(e, v):
    v = int(v or 0) & M64
    for b, en in objc.regions(e):
        if b <= v <= en: return max(0, min(en - v + 1, _MAX_BUF))
    return 0
def _note_bounce(name, n, asked):
    if n != asked:
        _say(f"[sdl] {name}: clamped buffer {asked} -> {n} bytes so libSDL3 cannot write past it")
    elif os.environ.get("ARM2X86_VERBOSE") and n >= (1 << 20):
        _say(f"[sdl] {name}: bouncing {n} byte buffer")
def prepare_buffers(e, name, argks, raw):
    """{arg index: bounce size}. Shrinks the length argument to the guest mapping (max 64MB).
    Returns None when the call must be skipped (SDL would write past the mapping and there is no length to shrink)."""
    spec = BUF.get(name)
    if spec:
        idxs, sfn = spec[0], spec[1]
        if isinstance(idxs, int): idxs = (idxs,)
        size_i = spec[2] if len(spec) > 2 else None
        try: asked = _uclamp(sfn(e, raw))
        except Exception: asked = 0
        spans = []
        for i in idxs:
            v = raw[i] if i < len(raw) else 0
            if v and is_guest(e, v): spans.append(_span(e, v))
        if not spans: return {}
        n = min(asked, min(spans), _MAX_BUF)
        if size_i is None and asked > n: return None
        if size_i is not None and size_i < len(raw): raw[size_i] = n & M64
        _note_bounce(name, n, asked)
        return {i: n for i in idxs if i < len(raw) and raw[i] and is_guest(e, raw[i])}
    # Not in the table: a void* / Uint8* followed by exactly one integer is (ptr, bytecount).
    # Do not guess when two integers follow (offset+size, or width+height) — those are listed above.
    if any(a[0] == "cb" for a in argks): return {}
    out = {}; i = 0
    while i < len(argks):
        k, v = argks[i], raw[i]
        bytebuf = k[0] == "v" or (k[0] == "p" and k[1] == 1)
        nxt = argks[i + 1] if i + 1 < len(argks) else None
        after = argks[i + 2] if i + 2 < len(argks) else None
        one_int = nxt and nxt[0] in "iu" and nxt[1] >= 4 and not (after and after[0] in "iu" and after[1] >= 4)
        if bytebuf and v and is_guest(e, v) and one_int:
            asked = _uclamp(raw[i + 1]); n = min(asked, _span(e, v), _MAX_BUF)
            raw[i + 1] = n & M64; out[i] = n; _note_bounce(name, n, asked); i += 2; continue
        i += 1
    return out
def _bounce_buf(e, name, v, n, hold, copyback):
    """Host copy of n guest bytes. IOFrom* / NoCopy keep it (SDL reads it later); everything else is copied back."""
    try: blob = gread(e, v, n) if n else b""
    except Exception as ex: return None, str(ex)
    b = ctypes.create_string_buffer(blob, max(n, 1)); hold.append(b)
    if name.startswith("SDL_IOFrom") or "NoCopy" in name: S.keep.append(b)
    else: copyback.append((v, b, n))
    return ctypes.addressof(b), None
COUNTED = {                                    # POINTER(T) arg i is an array whose length is arg j
    "SDL_RenderFillRects": (1, 2), "SDL_RenderRects": (1, 2), "SDL_RenderPoints": (1, 2), "SDL_RenderLines": (1, 2),
    "SDL_RenderGeometry": (2, 3), "SDL_FillSurfaceRects": (2, 3),
    "SDL_BindAudioStreams": (1, 2), "SDL_UnbindAudioStreams": (0, 1),
}
ARRAY_RET = {"SDL_GetDisplays", "SDL_GetJoysticks", "SDL_GetGamepads", "SDL_GetKeyboards", "SDL_GetMice", "SDL_GetTouchDevices",
             "SDL_GetCameras", "SDL_GetHaptics", "SDL_GetSensors", "SDL_GetWindows"}      # (…, int *count) -> id[count+1]
TEXTURE_RET = {"SDL_CreateTexture", "SDL_CreateTextureFromSurface", "SDL_CreateTextureWithProperties"}
SURFACE_RET = {"SDL_CreateSurface", "SDL_CreateSurfaceFrom", "SDL_DuplicateSurface", "SDL_ConvertSurface", "SDL_ScaleSurface"}

def mirror(e, hptr, n, live=False):
    """give the guest a copy of n host bytes; remember the mapping so the guest can pass it back."""
    if not hptr: return 0
    if hptr in S.h2g: g = S.h2g[hptr]
    else: g = e.malloc(max(n, 8)); S.h2g[hptr] = g; S.g2h[g] = hptr
    e.write(g, ctypes.string_at(hptr, n))
    if live: S.live.append((hptr, g, n))
    return g
def refresh_live(e):
    for hp, g, n in S.live: e.write(g, ctypes.string_at(hp, n))

def surface_mirror(e, hs):
    if not hs: return 0
    if hs in S.h2g: g = S.h2g[hs]
    else: g = e.malloc(48); S.h2g[hs] = g; S.g2h[g] = hs
    raw = bytearray(ctypes.string_at(hs, 48)); pitch, hh = struct.unpack_from("<ii", raw, 16)[0], struct.unpack_from("<i", raw, 12)[0]
    hpix = struct.unpack_from("<Q", raw, 24)[0]; nb = max(pitch * hh, 0)
    gp = S.surfaces[g][2] if g in S.surfaces else e.malloc(max(nb, 8))
    if hpix and nb: e.write(gp, ctypes.string_at(hpix, nb))
    struct.pack_into("<Q", raw, 24, gp); e.write(g, bytes(raw)); S.surfaces[g] = (hs, hpix, gp, nb); return g
def surfaces_to_host(e, touched):
    for g in touched:
        hs, hp, gp, nb = S.surfaces[g]
        if hp and nb: ctypes.memmove(hp, gread(e, gp, nb), nb)
def surfaces_to_guest(e, touched):
    for g in touched:
        hs, hp, gp, nb = S.surfaces[g]
        if hp and nb: e.write(gp, ctypes.string_at(hp, nb))

# ---- callbacks -------------------------------------------------------------------------------------------------
def make_cb(e, gfn, sig):
    key = (gfn, repr(sig))
    if key in S.cbs: return S.cbs[key]
    args, ret = sig
    T = ctypes.CFUNCTYPE(None if ret[0] == "0" else ctype(ret), *[ctype(a) for a in args])
    def thunk(*a):
        with S.lock: S.pending.append((gfn, [int(x or 0) if not isinstance(x, float) else 0 for x in a]))
        return 0
    cb = T(thunk); S.keep.append(cb); S.cbs[key] = ctypes.cast(cb, c_void_p).value; return S.cbs[key]

# ---- host-pointer sanity (a bad pointer inside libSDL3 is a SIGBUS/SIGSEGV that kills the whole emulator) -----------
_libc = ctypes.CDLL(None); _libc.write.argtypes = [ctypes.c_int, c_void_p, ctypes.c_size_t]; _libc.write.restype = ctypes.c_ssize_t
_devnull = os.open(os.devnull, os.O_WRONLY)
def host_readable(p):
    return _libc.write(_devnull, p, 1) == 1
def region_room(e, v, cap=1 << 18):
    for b, en in objc.regions(e):
        if b <= v <= en: return max(1, min(en - v + 1, cap))
    return 8
OPAQUE_V = ("SDL_SetPointerProperty", "SDL_SetTLS", "SDL_SetPointerPropertyWithCleanup", "SDL_AddEventWatch", "SDL_RemoveEventWatch")
def _say(msg): sys.stderr.write(msg + "\n"); sys.stderr.flush()

# ---- the generic call ----------------------------------------------------------------------------------------------
def call(e, name):
    lib = load_lib(e)
    if lib is None: return 0
    ret, argks = SIGS[name]
    if name == "SDL_free":                           # guest-owned memory (our string copies, mirrors) must never reach host free()
        p = e.arg(0)
        if p in S.g2h: S.h2g.pop(S.g2h[p], None); lib.SDL_free.argtypes = [c_void_p]; lib.SDL_free(S.g2h.pop(p))
        return None
    rd = objc.ArgReader(e, nx=0); raw = []
    for k in argks:                                   # 1) decode guest registers/stack into python values
        raw.append(rd.read(_ENC[(k[0], k[1])]) if (k[0], k[1]) in _ENC else rd.read("Q"))
    surf_touched = [v for v in raw if v in S.surfaces]
    if surf_touched: surfaces_to_host(e, surf_touched)
    sized = prepare_buffers(e, name, argks, raw)
    if sized is None:
        _say(f"[sdl] {name}: buffer is larger than the guest mapping and the length cannot be shrunk; call skipped")
        e.uc.reg_write(UC_ARM64_REG_X0, 0); return None
    conv, copyback, hold = [], [], []
    cnt = COUNTED.get(name)
    for i, (k, v) in enumerate(zip(argks, raw)):      # 2) translate each arg
        kk = k[0]
        if kk == "s":
            v = None if v == 0 else ctypes.create_string_buffer(gstr(e, v)); hold.append(v); conv.append(ctypes.addressof(v) if v is not None else None)
        elif kk == "p":
            if v == 0: conv.append(None); continue
            if v in S.g2h: conv.append(S.g2h[v]); continue
            if i in sized and is_guest(e, v):
                addr, err = _bounce_buf(e, name, v, sized[i], hold, copyback)
                if err:
                    _say(f"[sdl] {name}: cannot read {sized[i]} bytes at {v:#x} ({err}); call skipped")
                    e.uc.reg_write(UC_ARM64_REG_X0, 0); return None
                conv.append(addr); continue
            if is_guest(e, v) and k[1] == 1:
                # Uint8* whose length is not in the table. A 1-byte copy is a lie: SDL reads/writes the real
                # length and SIGBUS. The guest mapping is this process's memory — hand that pointer over.
                if not host_readable(v):
                    _say(f"[sdl] {name}: byte pointer {i} = {v:#x} is not host-readable; call skipped")
                    e.uc.reg_write(UC_ARM64_REG_X0, 0); return None
                conv.append(v); continue
            n = k[1] * (raw[cnt[1]] if cnt and cnt[0] == i else 1)
            if is_guest(e, v):
                b = ctypes.create_string_buffer(gread(e, v, n), max(n, 1)); hold.append(b); copyback.append((v, b, n)); conv.append(ctypes.addressof(b))
            else:
                if v and not host_readable(v):
                    _say(f"[sdl] {name}: pointer argument {i} = {v:#x} is neither guest nor host memory; call skipped")
                    e.uc.reg_write(UC_ARM64_REG_X0, 0); return None
                conv.append(v)
        elif kk == "pp":
            if v and is_guest(e, v):                 # pointer-to-pointer: arrays of handles (in) or out-parameters (out)
                n = 8 * (raw[cnt[1]] if cnt and cnt[0] == i else 1)
                b = ctypes.create_string_buffer(gread(e, v, n), max(n, 8)); hold.append(b); copyback.append((v, b, n)); conv.append(ctypes.addressof(b))
            else: conv.append(v or None)
        elif kk == "v":
            if v == 0: conv.append(None); continue
            if v in S.g2h: conv.append(S.g2h[v]); continue
            if i in sized and is_guest(e, v):
                addr, err = _bounce_buf(e, name, v, sized[i], hold, copyback)
                if err:
                    _say(f"[sdl] {name}: cannot read {sized[i]} bytes at {v:#x} ({err}); call skipped")
                    e.uc.reg_write(UC_ARM64_REG_X0, 0); return None
                conv.append(addr); continue
            if (is_guest(e, v) and not any(a[0] == "cb" for a in argks)
                    and not name.startswith(OPAQUE_V) and "Property" not in name):
                # Length unknown. Do NOT bounce region_room (256KB): SDL still writes the real size and the
                # host dies with SIGBUS inside f(*conv), which Python cannot catch. Unicorn identity-maps, so
                # the guest address IS the buffer.
                if not host_readable(v):
                    _say(f"[sdl] {name}: argument {i} = {v:#x} is neither guest nor host memory; call skipped (would crash the host)")
                    e.uc.reg_write(UC_ARM64_REG_X0, 0); return None
                conv.append(v); continue
            if not is_guest(e, v) and not host_readable(v):
                _say(f"[sdl] {name}: argument {i} = {v:#x} is neither guest nor host memory; call skipped (would crash the host)")
                e.uc.reg_write(UC_ARM64_REG_X0, 0); return None
            conv.append(h(e, v))
        elif kk == "cb": conv.append(make_cb(e, v, k[2]) if v else None)
        else: conv.append(v)
    f = getattr(lib, name); f.argtypes = [ctype(k) for k in argks]
    f.restype = None if ret[0] == "0" else ctype(ret) if ret[0] in "iufd" else c_void_p
    if name == "SDL_UnlockTexture" and raw[0] in S.locks:           # push the guest's texture pixels to the host
        hp, gp, nb = S.locks.pop(raw[0]); ctypes.memmove(hp, gread(e, gp, nb), nb)
    for i, (k, c) in enumerate(zip(argks, conv)):     # last line: a raw int pointer libSDL3 cannot read is a SIGBUS
        if k[0] in ("v", "p", "pp", "s") and isinstance(c, int) and c and not host_readable(c):
            _say(f"[sdl] {name}: pointer arg {i} = {c:#x} is not readable in this process; call skipped")
            e.uc.reg_write(UC_ARM64_REG_X0, 0); return None
    if TRACE: _say(f"[sdl] > {name}({', '.join(hex(x) if isinstance(x, int) else str(x) for x in raw)})")
    r = f(*conv)
    if TRACE:
        sys.stderr.write(f"[sdl] {name}({', '.join(hex(x) if isinstance(x, int) else str(x) for x in raw)}) -> {r}\n")
        if ret[0] in "iuv" and not r and name != "SDL_GetError":
            g = lib.SDL_GetError; g.restype = c_void_p; g.argtypes = []; m = g()
            if m and ctypes.string_at(m): sys.stderr.write(f"[sdl]    error: {ctypes.string_at(m).decode('utf8', 'replace')}\n")
    for gaddr, b, n in copyback: e.write(gaddr, b.raw[:n])        # 3) copy-back of out-parameters
    if surf_touched: surfaces_to_guest(e, surf_touched)
    if name == "SDL_LockTexture" and r:                           # (tex, rect*, void **pixels, int *pitch)
        hp = struct.unpack("<Q", gread(e, raw[2], 8))[0]; pitch = struct.unpack("<i", gread(e, raw[3], 4))[0]
        nb = pitch * rect_h(e, raw, 1); gp = e.malloc(max(nb, 8)); e.write(gp, ctypes.string_at(hp, nb))
        e.write(raw[2], struct.pack("<Q", gp)); S.locks[raw[0]] = (hp, gp, nb)
    if name in ("SDL_LoadWAV", "SDL_LoadWAV_IO") and r:           # (…, SDL_AudioSpec*, Uint8 **buf, Uint32 *len)
        bi, li = len(argks) - 2, len(argks) - 1
        hp = struct.unpack("<Q", gread(e, raw[bi], 8))[0]; n = struct.unpack("<I", gread(e, raw[li], 4))[0]
        e.write(raw[bi], struct.pack("<Q", mirror(e, hp, n)))
    out = r
    if ret[0] == "0": out = None
    elif ret[0] == "s": out = new_gstr(e, r)
    elif ret[0] in ("v", "p", "pp"):
        out = r or 0
        if out:
            if name in ARRAY_RET:
                n = (struct.unpack("<i", gread(e, raw[0], 4))[0] if raw[0] else 0) + 1; out = mirror(e, out, 4 * n)
            elif name in SURFACE_RET: out = surface_mirror(e, out)
            elif name in TEXTURE_RET: out = mirror(e, out, 16)
            elif name in ("SDL_LoadFile", "SDL_LoadFile_IO"):
                # SDL malloc'd the bytes. A raw host pointer is not guest memory: mirror it (SDL_free still works via g2h).
                n = 0
                try:
                    if len(raw) > 1 and raw[1]: n = _uclamp(struct.unpack("<Q", gread(e, raw[1], 8))[0])
                except Exception: n = 0
                if n > _MAX_BUF:
                    _say(f"[sdl] {name}: file is {n} bytes; mirroring the first {_MAX_BUF}"); n = _MAX_BUF
                out = mirror(e, out, n)
            elif name == "SDL_GetKeyboardState": out = mirror(e, out, 512, live=True)
            elif name == "SDL_GlobDirectory":                      # char** (NULL terminated) -> guest array of guest strings
                items = []
                while True:
                    ptr = ctypes.c_void_p.from_address(out + 8 * len(items)).value
                    if not ptr: break
                    items.append(new_gstr(e, ptr))
                arr = _alloc_bytes(e, b"".join(struct.pack("<Q", x) for x in items) + b"\0" * 8); S.h2g[out] = arr; S.g2h[arr] = out; out = arr
    if name in ("SDL_PollEvent", "SDL_PumpEvents", "SDL_WaitEvent", "SDL_WaitEventTimeout"): refresh_live(e)
    if name == "SDL_DestroySurface" and raw[0] in S.surfaces: S.surfaces.pop(raw[0])
    if ret[0] in "iu": objc.write_ret(e, _ENC[(ret[0], ret[1])], int(out or 0))
    elif ret[0] in "fd": objc.write_ret(e, _ENC[(ret[0], ret[1])], float(out))
    elif ret[0] != "0": e.uc.reg_write(UC_ARM64_REG_X0, int(out or 0) & M64)
    p = take_pending()
    if p and ret[0] not in "fd": e.begin_callbacks(p, e.uc.reg_read(UC_ARM64_REG_X0))
    return None

def _mk(name): return lambda e: call(e, name)
for _n in SIGS:
    if _n.startswith("SDL_") and ("_" + _n) not in FUNCS: FUNCS["_" + _n] = _mk(_n)
