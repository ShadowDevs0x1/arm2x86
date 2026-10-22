"""
Graphics bridge: the guest's GLFW + OpenGL calls are executed on the HOST's real
GLFW and OpenGL driver (OpenGL.framework on macOS), so rendering is hardware
accelerated even though the game's CPU code runs under Unicorn.

  * scalar-only GL functions are marshalled generically from a signature table
    (int args come from x0-x7, float/double args from d0-d7)
  * functions that take pointers (buffers, shader source, textures, ...) copy
    the data between guest memory and host buffers explicitly
  * GLFW callbacks (key, mouse, resize...) re-enter the guest through the
    continuation mechanism in loader.py (begin_callbacks)

Needs:  pip3 install glfw
"""
import ctypes, struct, os, sys
from unicorn.arm64_const import *
import hle
from hle import fn, FUNCS, M64, s32, s64

def _glfw():
    try:
        import glfw
    except ImportError:
        sys.exit("[arm2x86] this program needs GLFW on the host:  pip3 install glfw")
    return glfw

class State:
    def __init__(self):
        self.windows, self.handles, self.cbs, self.events = {}, {}, {}, []
        self.next = 0x10000; self.userptr = {}
        self.unpack_align = self.pack_align = 4
        self.strings, self.gl = {}, {}
        self.fake_done = False
def st(e):
    if not hasattr(e, "gfx"): e.gfx = State()
    return e.gfx

def iarg(e, i):
    return e.arg(i) if i < 8 else int.from_bytes(e.read(e.sp() + 8 * (i - 8), 8), "little")
def u32(v): return v & 0xffffffff
def f32_of(bits): return struct.unpack("<f", struct.pack("<I", bits & 0xffffffff))[0]
def d_reg(e, i): return e.uc.reg_read(UC_ARM64_REG_D0 + i) & M64
def read_f32s(e, p, n): return list(struct.unpack(f"<{n}f", bytes(e.read(p, 4 * n)))) if n else []
def wr_i32(e, p, *v): e.write(p, struct.pack(f"<{len(v)}i", *v))

# ------------------------------------------------------------ host GL access --
_GLLIB = None
_GLLIB_TRIED = False
def _gl_lib():
    """OpenGL.framework / libGL, so NSOpenGLView can draw without GLFW owning the context."""
    global _GLLIB, _GLLIB_TRIED
    if _GLLIB_TRIED: return _GLLIB
    _GLLIB_TRIED = True
    for c in ("/System/Library/Frameworks/OpenGL.framework/OpenGL",
              "/System/Library/Frameworks/OpenGL.framework/Versions/A/OpenGL",
              "libGL.so.1", "libGL.so", "/usr/lib/x86_64-linux-gnu/libGL.so.1"):
        try:
            _GLLIB = ctypes.CDLL(c); return _GLLIB
        except OSError:
            continue
    return None
def host(e, name, res, args):
    s = st(e)
    key = (name, res, tuple(args))
    if key not in s.gl:
        fn = None
        lib = _gl_lib()
        if lib is not None:
            try:
                raw = getattr(lib, name)
                addr = ctypes.cast(raw, ctypes.c_void_p).value
                if addr: fn = ctypes.CFUNCTYPE(res, *args)(addr)
            except AttributeError:
                fn = None
        if fn is None:
            try:
                import glfw
                fp = glfw.get_proc_address(name)
                addr = ctypes.cast(fp, ctypes.c_void_p).value if fp else None
                if addr: fn = ctypes.CFUNCTYPE(res, *args)(addr)
            except Exception:
                fn = None
        if fn is None: sys.exit(f"[arm2x86] host OpenGL driver has no {name}")
        s.gl[key] = fn
    return s.gl[key]

T = dict(i=ctypes.c_int, u=ctypes.c_uint, b=ctypes.c_ubyte, f=ctypes.c_float, d=ctypes.c_double,
         l=ctypes.c_ssize_t, P=ctypes.c_void_p)
CONV = dict(i=lambda v: s32(v), u=u32, b=lambda v: v & 0xff, l=s64, P=lambda v: v & M64)

def make_scalar(name, sig):
    ret, argsig = sig[0], sig[1:]
    rtype = None if ret == "v" else T[ret]
    atypes = [T[c] for c in argsig]
    def f(e):
        xi = fi = 0; vals = []
        for c in argsig:
            if c == "f":   vals.append(f32_of(d_reg(e, fi))); fi += 1
            elif c == "d": vals.append(struct.unpack("<d", struct.pack("<Q", d_reg(e, fi)))[0]); fi += 1
            else:          vals.append(CONV[c](iarg(e, xi))); xi += 1
        r = host(e, name, rtype, atypes)(*vals)
        return None if ret == "v" else (r or 0)
    return f

SCALAR = """
glClearColor vffff|glClear vu|glViewport viiii|glScissor viiii|glEnable vu|glDisable vu|glBlendFunc vuu
glBlendFuncSeparate vuuuu|glBlendEquation vu|glDepthFunc vu|glDepthMask vb|glCullFace vu|glFrontFace vu
glLineWidth vf|glPointSize vf|glClearDepth vd|glClearStencil vi|glColorMask vbbbb|glPolygonMode vuu
glUseProgram vu|glBindTexture vuu|glActiveTexture vu|glBindBuffer vuu|glBindVertexArray vu
glBindFramebuffer vuu|glBindRenderbuffer vuu|glEnableVertexAttribArray vu|glDisableVertexAttribArray vu
glVertexAttribPointer vuiubiP|glDrawArrays vuii|glDrawElements vuiuP|glCreateShader uu|glCompileShader vu
glCreateProgram u|glAttachShader vuu|glLinkProgram vu|glDeleteShader vu|glDeleteProgram vu|glValidateProgram vu
glGenerateMipmap vu|glTexParameteri vuui|glTexParameterf vuuf|glFlush v|glFinish v|glGetError u
glUniform1i vii|glUniform2i viii|glUniform3i viiii|glUniform1f vif|glUniform2f viff|glUniform3f vifff|glUniform4f viffff
glFramebufferTexture2D vuuuui|glFramebufferRenderbuffer vuuuu|glRenderbufferStorage vuuii|glCheckFramebufferStatus uu
glStencilFunc vuiu|glStencilOp vuuu|glStencilMask vu|glDepthRange vdd|glPolygonOffset vff|glHint vuu|glSampleCoverage vfb
glIsEnabled bu|glIsTexture bu|glIsBuffer bu|glIsProgram bu|glIsShader bu|glBlendColor vffff|glReadBuffer vu|glDrawBuffer vu
glMatrixMode vu|glLoadIdentity v|glPushMatrix v|glPopMatrix v|glOrtho vdddddd|glFrustum vdddddd|glTranslatef vfff
glRotatef vffff|glScalef vfff|glTranslated vddd|glRotated vdddd|glScaled vddd|glBegin vu|glEnd v|glVertex2f vff
glVertex3f vfff|glVertex4f vffff|glVertex2i vii|glColor3f vfff|glColor4f vffff|glColor3ub vbbb|glColor4ub vbbbb
glTexCoord2f vff|glTexCoord3f vfff|glNormal3f vfff|glLineStipple vib|glShadeModel vu|glLightModeli vui|glColorMaterial vuu
glAlphaFunc vuf|glClientActiveTexture vu|glEnableClientState vu|glDisableClientState vu|glBindBufferBase vuuu
glDrawArraysInstanced vuiii|glDrawElementsInstanced vuiuPi|glVertexAttribDivisor vuu|glRasterPos2f vff|glPointParameterf vuf
glCopyTexSubImage2D vuiiiiiii|glFramebufferTexture vuuui|glBlitFramebuffer viiiiiiiiiuu
""".replace("\n", "|").split("|")
for ent in SCALAR:
    ent = ent.strip()
    if not ent: continue
    nm, sig = ent.split()
    FUNCS["_" + nm] = make_scalar(nm, sig)

# ------------------------------------------------- pointer-taking GL calls ----
def _gen(name):
    def f(e):
        n, p = s32(e.arg(0)), e.arg(1)
        arr = (ctypes.c_uint * max(n, 1))()
        host(e, name, None, [ctypes.c_int, ctypes.c_void_p])(n, ctypes.addressof(arr))
        e.write(p, struct.pack(f"<{n}I", *arr[:n]))
    return f
def _delete(name):
    def f(e):
        n = s32(e.arg(0)); ids = struct.unpack(f"<{n}I", bytes(e.read(e.arg(1), 4 * n))) if n > 0 else ()
        arr = (ctypes.c_uint * max(n, 1))(*ids)
        host(e, name, None, [ctypes.c_int, ctypes.c_void_p])(n, ctypes.addressof(arr))
    return f
for g in ("Buffers", "Textures", "VertexArrays", "Framebuffers", "Renderbuffers"):
    FUNCS["_glGen" + g] = _gen("glGen" + g); FUNCS["_glDelete" + g] = _delete("glDelete" + g)

@fn("glBufferData")
def _bufdata(e):
    target, size, ptr, usage = u32(e.arg(0)), e.arg(1), e.arg(2), u32(e.arg(3))
    buf = ctypes.create_string_buffer(bytes(e.read(ptr, size)), size) if ptr else None
    host(e, "glBufferData", None, [ctypes.c_uint, ctypes.c_ssize_t, ctypes.c_void_p, ctypes.c_uint])(
        target, size, ctypes.addressof(buf) if buf else None, usage)
@fn("glBufferSubData")
def _bufsub(e):
    target, off, size, ptr = u32(e.arg(0)), e.arg(1), e.arg(2), e.arg(3)
    buf = ctypes.create_string_buffer(bytes(e.read(ptr, size)), size)
    host(e, "glBufferSubData", None, [ctypes.c_uint, ctypes.c_ssize_t, ctypes.c_ssize_t, ctypes.c_void_p])(
        target, off, size, ctypes.addressof(buf))

@fn("glShaderSource")
def _shsrc(e):
    sh, cnt, strs, lens = u32(e.arg(0)), s32(e.arg(1)), e.arg(2), e.arg(3)
    out = []
    for i in range(cnt):
        p = int.from_bytes(e.read(strs + 8 * i, 8), "little")
        n = s32(int.from_bytes(e.read(lens + 4 * i, 4), "little")) if lens else -1
        out.append(bytes(e.read(p, n)) if n >= 0 else e.cstr_bytes(p))
    arr = (ctypes.c_char_p * max(cnt, 1))(*out)
    host(e, "glShaderSource", None, [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p])(
        sh, cnt, ctypes.addressof(arr), None)
def _iv(name):
    def f(e):
        out = ctypes.c_int(0)
        host(e, name, None, [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p])(u32(e.arg(0)), u32(e.arg(1)), ctypes.addressof(out))
        wr_i32(e, e.arg(2), out.value)
    return f
FUNCS["_glGetShaderiv"] = _iv("glGetShaderiv"); FUNCS["_glGetProgramiv"] = _iv("glGetProgramiv")
def _infolog(name):
    def f(e):
        obj, size, lenp, logp = u32(e.arg(0)), s32(e.arg(1)), e.arg(2), e.arg(3)
        buf = ctypes.create_string_buffer(max(size, 1)); n = ctypes.c_int(0)
        host(e, name, None, [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p])(
            obj, size, ctypes.addressof(n), ctypes.addressof(buf))
        if size > 0: e.write(logp, buf.raw[: n.value] + b"\0")
        if lenp: wr_i32(e, lenp, n.value)
    return f
FUNCS["_glGetShaderInfoLog"] = _infolog("glGetShaderInfoLog"); FUNCS["_glGetProgramInfoLog"] = _infolog("glGetProgramInfoLog")
@fn("glGetUniformLocation")
def _guloc(e): return host(e, "glGetUniformLocation", ctypes.c_int, [ctypes.c_uint, ctypes.c_char_p])(u32(e.arg(0)), e.cstr_bytes(e.arg(1)))
@fn("glGetAttribLocation")
def _galoc(e): return host(e, "glGetAttribLocation", ctypes.c_int, [ctypes.c_uint, ctypes.c_char_p])(u32(e.arg(0)), e.cstr_bytes(e.arg(1)))
@fn("glBindAttribLocation")
def _baloc(e): host(e, "glBindAttribLocation", None, [ctypes.c_uint, ctypes.c_uint, ctypes.c_char_p])(u32(e.arg(0)), u32(e.arg(1)), e.cstr_bytes(e.arg(2)))

def _uniform_v(name, per, kind):
    def f(e):
        loc, cnt = s32(e.arg(0)), s32(e.arg(1)); p = e.arg(2)
        n = cnt * per
        c = ctypes.c_float if kind == "f" else ctypes.c_int
        vals = struct.unpack(f"<{n}{kind}", bytes(e.read(p, 4 * n)))
        arr = (c * max(n, 1))(*vals)
        host(e, name, None, [ctypes.c_int, ctypes.c_int, ctypes.c_void_p])(loc, cnt, ctypes.addressof(arr))
    return f
for nm, per, kind in [("glUniform1fv", 1, "f"), ("glUniform2fv", 2, "f"), ("glUniform3fv", 3, "f"), ("glUniform4fv", 4, "f"),
                      ("glUniform1iv", 1, "i"), ("glUniform2iv", 2, "i"), ("glUniform3iv", 3, "i"), ("glUniform4iv", 4, "i")]:
    FUNCS["_" + nm] = _uniform_v(nm, per, kind)
def _uniform_m(name, per):
    def f(e):
        loc, cnt, tr, p = s32(e.arg(0)), s32(e.arg(1)), e.arg(2) & 0xff, e.arg(3)
        n = cnt * per; arr = (ctypes.c_float * max(n, 1))(*read_f32s(e, p, n))
        host(e, name, None, [ctypes.c_int, ctypes.c_int, ctypes.c_ubyte, ctypes.c_void_p])(loc, cnt, tr, ctypes.addressof(arr))
    return f
FUNCS["_glUniformMatrix2fv"] = _uniform_m("glUniformMatrix2fv", 4)
FUNCS["_glUniformMatrix3fv"] = _uniform_m("glUniformMatrix3fv", 9)
FUNCS["_glUniformMatrix4fv"] = _uniform_m("glUniformMatrix4fv", 16)

def _fvec(name, n):
    def f(e):
        arr = (ctypes.c_float * n)(*read_f32s(e, e.arg(0), n))
        host(e, name, None, [ctypes.c_void_p])(ctypes.addressof(arr))
    return f
for nm, n in [("glVertex2fv", 2), ("glVertex3fv", 3), ("glVertex4fv", 4), ("glColor3fv", 3), ("glColor4fv", 4),
              ("glNormal3fv", 3), ("glTexCoord2fv", 2), ("glLoadMatrixf", 16), ("glMultMatrixf", 16)]:
    FUNCS["_" + nm] = _fvec(nm, n)
def _paramfv(name, count_fn):
    def f(e):
        a, b, p = u32(e.arg(0)), u32(e.arg(1)), e.arg(2); n = count_fn(b)
        arr = (ctypes.c_float * n)(*read_f32s(e, p, n))
        host(e, name, None, [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p])(a, b, ctypes.addressof(arr))
    return f
_light_n = lambda pn: 3 if pn == 0x1204 else (1 if 0x1205 <= pn <= 0x1209 else 4)
_mat_n   = lambda pn: 1 if pn == 0x1601 else (3 if pn == 0x1603 else 4)
FUNCS["_glLightfv"] = _paramfv("glLightfv", _light_n); FUNCS["_glMaterialfv"] = _paramfv("glMaterialfv", _mat_n)
FUNCS["_glLightModelfv"] = _paramfv("glLightModelfv", lambda pn: 4)
FUNCS["_glTexParameterfv"] = _paramfv("glTexParameterfv", lambda pn: 4 if pn == 0x1004 else 1)
@fn("glTexParameteriv")
def _tpiv(e):
    pn = u32(e.arg(1)); n = 4 if pn == 0x1004 else 1
    arr = (ctypes.c_int * n)(*struct.unpack(f"<{n}i", bytes(e.read(e.arg(2), 4 * n))))
    host(e, "glTexParameteriv", None, [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p])(u32(e.arg(0)), pn, ctypes.addressof(arr))
@fn("glDrawBuffers")
def _drawbufs(e):
    n = s32(e.arg(0)); arr = (ctypes.c_uint * max(n, 1))(*struct.unpack(f"<{n}I", bytes(e.read(e.arg(1), 4 * n))))
    host(e, "glDrawBuffers", None, [ctypes.c_int, ctypes.c_void_p])(n, ctypes.addressof(arr))
@fn("glPixelStorei")
def _pixstore(e):
    pn, v = u32(e.arg(0)), s32(e.arg(1)); s = st(e)
    if pn == 0x0CF5: s.unpack_align = v
    if pn == 0x0D05: s.pack_align = v
    host(e, "glPixelStorei", None, [ctypes.c_uint, ctypes.c_int])(pn, v)

CHANNELS = {0x1903: 1, 0x8227: 2, 0x1907: 3, 0x1908: 4, 0x80E1: 4, 0x80E0: 3, 0x1909: 1, 0x190A: 2, 0x1906: 1,
            0x1902: 1, 0x84F9: 1, 0x8D94: 1, 0x8228: 2, 0x8D98: 3, 0x8D99: 4}
TYPEBYTES = {0x1400: 1, 0x1401: 1, 0x1402: 2, 0x1403: 2, 0x1404: 4, 0x1405: 4, 0x1406: 4, 0x140B: 2}
PACKED = {0x8363: 2, 0x8033: 2, 0x8034: 2, 0x8035: 4, 0x8367: 4, 0x8368: 4, 0x84FA: 4, 0x8365: 2, 0x8366: 2}
def image_size(w, h, fmt, typ, align):
    bpp = PACKED.get(typ) or CHANNELS.get(fmt, 4) * TYPEBYTES.get(typ, 1)
    row = (w * bpp + align - 1) // align * align
    return row * h
@fn("glTexImage2D")
def _teximg(e):
    t, lvl, ifmt, w, h, border, fmt, typ, ptr = u32(e.arg(0)), s32(e.arg(1)), s32(e.arg(2)), s32(e.arg(3)), s32(e.arg(4)), \
        s32(e.arg(5)), u32(e.arg(6)), u32(e.arg(7)), iarg(e, 8)
    buf = None
    if ptr: n = image_size(w, h, fmt, typ, st(e).unpack_align); buf = ctypes.create_string_buffer(bytes(e.read(ptr, n)), n)
    host(e, "glTexImage2D", None, [ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p])(t, lvl, ifmt, w, h, border, fmt, typ,
                                   ctypes.addressof(buf) if buf else None)
@fn("glTexSubImage2D")
def _texsub(e):
    t, lvl, x, y, w, h, fmt, typ, ptr = u32(e.arg(0)), s32(e.arg(1)), s32(e.arg(2)), s32(e.arg(3)), s32(e.arg(4)), \
        s32(e.arg(5)), u32(e.arg(6)), u32(e.arg(7)), iarg(e, 8)
    n = image_size(w, h, fmt, typ, st(e).unpack_align); buf = ctypes.create_string_buffer(bytes(e.read(ptr, n)), n)
    host(e, "glTexSubImage2D", None, [ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                      ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p])(t, lvl, x, y, w, h, fmt, typ, ctypes.addressof(buf))
@fn("glReadPixels")
def _readpix(e):
    x, y, w, h, fmt, typ, ptr = s32(e.arg(0)), s32(e.arg(1)), s32(e.arg(2)), s32(e.arg(3)), u32(e.arg(4)), u32(e.arg(5)), e.arg(6)
    n = image_size(w, h, fmt, typ, st(e).pack_align); buf = ctypes.create_string_buffer(n)
    host(e, "glReadPixels", None, [ctypes.c_int] * 4 + [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p])(x, y, w, h, fmt, typ, ctypes.addressof(buf))
    e.write(ptr, buf.raw)

_INT_COUNT = {0x0BA2: 4, 0x0C10: 4, 0x0D3A: 2}
@fn("glGetIntegerv")
def _geti(e):
    pn = u32(e.arg(0)); n = _INT_COUNT.get(pn, 1); arr = (ctypes.c_int * 16)()
    host(e, "glGetIntegerv", None, [ctypes.c_uint, ctypes.c_void_p])(pn, ctypes.addressof(arr)); wr_i32(e, e.arg(1), *arr[:n])
_FLT_COUNT = {0x0BA2: 4, 0x0C22: 4, 0x0BA6: 16, 0x0BA7: 16, 0x0BA8: 16, 0x0B53: 4}
@fn("glGetFloatv")
def _getf(e):
    pn = u32(e.arg(0)); n = _FLT_COUNT.get(pn, 1); arr = (ctypes.c_float * 16)()
    host(e, "glGetFloatv", None, [ctypes.c_uint, ctypes.c_void_p])(pn, ctypes.addressof(arr)); e.write(e.arg(1), struct.pack(f"<{n}f", *arr[:n]))
@fn("glGetBooleanv")
def _getb(e):
    arr = (ctypes.c_ubyte * 16)(); host(e, "glGetBooleanv", None, [ctypes.c_uint, ctypes.c_void_p])(u32(e.arg(0)), ctypes.addressof(arr))
    e.write(e.arg(1), bytes([arr[0]]))
@fn("glGetString")
def _getstr(e):
    n = u32(e.arg(0)); s = st(e)
    if n not in s.strings:
        r = host(e, "glGetString", ctypes.c_char_p, [ctypes.c_uint])(n)
        s.strings[n] = e.alloc_cstr(r.decode("latin-1")) if r else 0
    return s.strings[n]

# ----------------------------------------------------------------- GLFW -------
def win(e, handle): return st(e).windows.get(handle)
def _p(name):
    def deco(f): FUNCS["_" + name] = f; return f
    return deco

@_p("glfwInit")
def _init(e): return int(bool(_glfw().init()))
@_p("glfwTerminate")
def _term(e): _glfw().terminate()
@_p("glfwWindowHint")
def _hint(e): _glfw().window_hint(s32(e.arg(0)), s32(e.arg(1)))
@_p("glfwDefaultWindowHints")
def _dhint(e): _glfw().default_window_hints()
@_p("glfwWindowHintString")
def _hints(e): pass
@_p("glfwCreateWindow")
def _create(e):
    g, s = _glfw(), st(e)
    w = g.create_window(s32(e.arg(0)), s32(e.arg(1)), e.cstr(e.arg(2)), None, None)
    if not w: return 0
    h = s.next; s.next += 16; s.windows[h] = w; s.handles[id(w)] = h
    for kind, setter, mk in (
        ("key", g.set_key_callback, lambda w_, k, sc, a, m: [h, k, sc, a, m]),
        ("mouse", g.set_mouse_button_callback, lambda w_, b, a, m: [h, b, a, m]),
        ("cursor", g.set_cursor_pos_callback, lambda w_, x, y: [h, float(x), float(y)]),
        ("scroll", g.set_scroll_callback, lambda w_, x, y: [h, float(x), float(y)]),
        ("char", g.set_char_callback, lambda w_, c: [h, c]),
        ("fbsize", g.set_framebuffer_size_callback, lambda w_, a, b: [h, a, b]),
        ("wsize", g.set_window_size_callback, lambda w_, a, b: [h, a, b]),
        ("close", g.set_window_close_callback, lambda w_: [h])):
        def make(kind=kind, mk=mk):
            def cb(*args):
                guest = s.cbs.get((h, kind))
                if guest: s.events.append((guest, mk(*args)))
            return cb
        setter(w, make())
    return h
@_p("glfwDestroyWindow")
def _destroy(e):
    w = win(e, e.arg(0))
    if w: _glfw().destroy_window(w)
@_p("glfwMakeContextCurrent")
def _mcc(e): _glfw().make_context_current(win(e, e.arg(0)))
@_p("glfwGetCurrentContext")
def _gcc(e):
    cur = _glfw().get_current_context(); s = st(e)
    return s.handles.get(id(cur), 0) if cur else 0
@_p("glfwSwapInterval")
def _swapint(e): _glfw().swap_interval(s32(e.arg(0)))
def _shot(e, path):
    """test hook: save the current framebuffer as PNG and exit"""
    import zlib
    w, h = _glfw().get_framebuffer_size(next(iter(st(e).windows.values())))
    buf = ctypes.create_string_buffer(w * h * 4)
    host(e, "glPixelStorei", None, [ctypes.c_uint, ctypes.c_int])(0x0D05, 1)
    host(e, "glReadPixels", None, [ctypes.c_int] * 4 + [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p])(0, 0, w, h, 0x1908, 0x1401, ctypes.addressof(buf))
    rows = b"".join(b"\0" + buf.raw[y * w * 4:(y + 1) * w * 4] for y in range(h - 1, -1, -1))
    def chunk(t, d): c = struct.pack(">I", len(d)) + t + d; return c + struct.pack(">I", zlib.crc32(t + d))
    open(path, "wb").write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)) +
                          chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))
@_p("glfwSwapBuffers")
def _swap(e):
    s = st(e); s.frames = getattr(s, "frames", 0) + 1
    shot = os.environ.get("ARM2X86_SHOT")             # "frame,path.png"
    if shot and s.frames == int(shot.split(",")[0]):
        _shot(e, shot.split(",", 1)[1]); print(f"[arm2x86] screenshot saved after {s.frames} frames", file=sys.stderr); e.exit(0)
    _glfw().swap_buffers(win(e, e.arg(0)))
@_p("glfwWindowShouldClose")
def _wsc(e):
    w = win(e, e.arg(0)); return int(_glfw().window_should_close(w)) if w else 1
@_p("glfwSetWindowShouldClose")
def _swsc(e): _glfw().set_window_should_close(win(e, e.arg(0)), bool(s32(e.arg(1))))
@_p("glfwSetWindowTitle")
def _swt(e):
    t = e.cstr(e.arg(1))
    if os.environ.get("ARM2X86_VERBOSE"): print(f"[title] {t}", file=sys.stderr)
    _glfw().set_window_title(win(e, e.arg(0)), t)
@_p("glfwSetWindowSize")
def _sws(e): _glfw().set_window_size(win(e, e.arg(0)), s32(e.arg(1)), s32(e.arg(2)))
@_p("glfwGetTime")
def _gt(e): e.ret_double(_glfw().get_time())
@_p("glfwSetTime")
def _st(e): _glfw().set_time(struct.unpack("<d", struct.pack("<Q", d_reg(e, 0)))[0])
@_p("glfwGetFramebufferSize")
def _gfs(e):
    w, h = _glfw().get_framebuffer_size(win(e, e.arg(0)))
    if e.arg(1): wr_i32(e, e.arg(1), w)
    if e.arg(2): wr_i32(e, e.arg(2), h)
@_p("glfwGetWindowSize")
def _gws(e):
    w, h = _glfw().get_window_size(win(e, e.arg(0)))
    if e.arg(1): wr_i32(e, e.arg(1), w)
    if e.arg(2): wr_i32(e, e.arg(2), h)
@_p("glfwGetWindowContentScale")
def _gwcs(e):
    x, y = _glfw().get_window_content_scale(win(e, e.arg(0)))
    if e.arg(1): e.write(e.arg(1), struct.pack("<f", x))
    if e.arg(2): e.write(e.arg(2), struct.pack("<f", y))
@_p("glfwGetCursorPos")
def _gcp(e):
    x, y = _glfw().get_cursor_pos(win(e, e.arg(0)))
    if e.arg(1): e.write(e.arg(1), struct.pack("<d", x))
    if e.arg(2): e.write(e.arg(2), struct.pack("<d", y))
@_p("glfwSetCursorPos")
def _scp(e):
    _glfw().set_cursor_pos(win(e, e.arg(0)), struct.unpack("<d", struct.pack("<Q", d_reg(e, 0)))[0],
                           struct.unpack("<d", struct.pack("<Q", d_reg(e, 1)))[0])
@_p("glfwGetKey")
def _gk(e): return _glfw().get_key(win(e, e.arg(0)), s32(e.arg(1)))
@_p("glfwGetMouseButton")
def _gmb(e): return _glfw().get_mouse_button(win(e, e.arg(0)), s32(e.arg(1)))
@_p("glfwSetInputMode")
def _sim(e): _glfw().set_input_mode(win(e, e.arg(0)), s32(e.arg(1)), s32(e.arg(2)))
@_p("glfwGetPrimaryMonitor")
def _gpm(e): return 0x1
@_p("glfwGetVideoMode")
def _gvm(e):
    m = _glfw().get_video_mode(_glfw().get_primary_monitor())
    p = e.malloc(24); wr_i32(e, p, m.size.width, m.size.height, m.bits.red, m.bits.green, m.bits.blue, m.refresh_rate); return p
@_p("glfwGetVersionString")
def _gvs(e): return e.alloc_cstr(_glfw().get_version_string())
@_p("glfwExtensionSupported")
def _ext(e): return int(bool(_glfw().extension_supported(e.cstr(e.arg(0)))))
@_p("glfwGetProcAddress")
def _gpa(e):
    name = "_" + e.cstr(e.arg(0))
    return e.resolve(name) if name in FUNCS else 0
@_p("glfwSetWindowUserPointer")
def _swup(e): st(e).userptr[e.arg(0)] = e.arg(1)
@_p("glfwGetWindowUserPointer")
def _gwup(e): return st(e).userptr.get(e.arg(0), 0)
@_p("glfwSetErrorCallback")
def _serr(e): return 0

def _setcb(kind):
    def f(e):
        s = st(e); key = (e.arg(0), kind); old = s.cbs.get(key, 0); s.cbs[key] = e.arg(1); return old
    return f
for kind, nm in [("key", "Key"), ("mouse", "MouseButton"), ("cursor", "CursorPos"), ("scroll", "Scroll"),
                 ("char", "Char"), ("fbsize", "FramebufferSize"), ("wsize", "WindowSize"), ("close", "WindowClose")]:
    FUNCS[f"_glfwSet{nm}Callback"] = _setcb(kind)

def _poll(e, wait=False):
    g, s = _glfw(), st(e)
    if wait: g.wait_events_timeout(0.05)
    else: g.poll_events()
    fake = os.environ.get("ARM2X86_FAKE_KEY")
    if fake and not s.fake_done:
        s.fake_done = True; k, a = (int(x) for x in fake.split(","))
        cb = next((v for (h, kind), v in s.cbs.items() if kind == "key"), 0)
        if cb: s.events.append((cb, [next(iter(s.windows)), k, 0, a, 0]))
    import objc
    calls, s.events = objc.take_pending() + s.events, []
    e.begin_callbacks(calls, 0)
@_p("glfwPollEvents")
def _pe(e): return _poll(e)
@_p("glfwWaitEvents")
def _we(e): return _poll(e, True)
@_p("glfwPostEmptyEvent")
def _pee(e): pass
