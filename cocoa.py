"""
AppKit / Foundation / CoreGraphics / CoreVideo / Metal C entry points, plus
NSApplicationMain.

objc_msgSend already forwards every ObjC method to the host runtime (objc.py).
What kills a Cocoa guest before that is the C symbol `_NSApplicationMain` and
friends. On a Mac those C functions run on the host frameworks. The run loop
is ours: AppKit's -[NSApplication run] would block inside a Unicorn hook and
the guest would never execute again, so `run` / CFRunLoopRun jump into a tiny
arm64 loop that calls back into Python between frames.
"""
import os, sys, struct, time, plistlib, ctypes
from unicorn.arm64_const import *
from hle import fn, FUNCS, M64, s32
import objc

DARWIN = sys.platform == "darwin"
RUNLOOP = 0x320000000
_LIBS = {}

def _lib(framework):
    if not DARWIN: return None
    if framework not in _LIBS:
        path = f"/System/Library/Frameworks/{framework}.framework/{framework}"
        try: _LIBS[framework] = ctypes.CDLL(path)
        except OSError: _LIBS[framework] = None
    return _LIBS[framework]

def _dreg(e, i):
    return e.uc.reg_read(UC_ARM64_REG_D0 + i) & M64
def _f32(bits):
    return struct.unpack("<f", struct.pack("<I", bits & 0xffffffff))[0]
def _f64(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & M64))[0]
def _iarg(e, i):
    if i < 8: return e.arg(i)
    return int.from_bytes(e.read(e.sp() + 8 * (i - 8), 8), "little")

_T = dict(i=ctypes.c_int, u=ctypes.c_uint, l=ctypes.c_int64, L=ctypes.c_uint64,
          p=ctypes.c_void_p, f=ctypes.c_float, d=ctypes.c_double, c=ctypes.c_int8,
          b=ctypes.c_uint8, v=None, q=ctypes.c_int64, Q=ctypes.c_uint64)

def _bind(framework, name, sig):
    """sig is 'return arg arg ...' using i,u,l,p,f,d,c,v. NSRect is four d's."""
    ret, args = sig[0], sig[1:]
    def f(e, framework=framework, name=name, ret=ret, args=args):
        lib = _lib(framework)
        if lib is None: return 0
        try:
            cfn = getattr(lib, name)
        except AttributeError:
            return 0
        rtype = None if ret == "v" else _T[ret]
        atypes = [_T[c] for c in args]
        cfn.restype, cfn.argtypes = rtype, atypes
        xi = fi = 0; vals = []
        for c in args:
            if c == "f": vals.append(_f32(_dreg(e, fi))); fi += 1
            elif c == "d": vals.append(_f64(_dreg(e, fi))); fi += 1
            elif c in "iu":
                vals.append(s32(_iarg(e, xi)) if c == "i" else (_iarg(e, xi) & 0xffffffff)); xi += 1
            elif c == "c":
                vals.append(s32(_iarg(e, xi)) & 0xff); xi += 1
            else:
                # pointer: guest Unicorn addresses are NOT valid host pointers
                p = _iarg(e, xi) & M64; xi += 1
                # guest image ~0x100000000+, stubs 0x300000000, heap 0x400000000+, threads 0x7f0000000000
                if p and (0x100000000 <= p < 0x600000000 or p >= 0x7f0000000000):
                    p = 0  # null out pure guest ptrs so host libc/CF does not SIGSEGV
                vals.append(p)
        try:
            r = cfn(*vals)
        except Exception as ex:
            sys.stderr.write("[cocoa] %s failed: %s" % (name, ex) + chr(10)); return 0
        if ret == "v" or r is None: return None
        if ret == "d":
            e.ret_double(float(r)); return None
        if ret == "f":
            e.uc.reg_write(UC_ARM64_REG_D0, struct.unpack("<I", struct.pack("<f", float(r)))[0]); return None
        return int(r) & M64
    FUNCS["_" + name] = f

def _bind_rect(framework, name, nd_in):
    """Host function returns NSRect/CGRect (4 doubles) and takes `nd_in` doubles."""
    class R(ctypes.Structure):
        _fields_ = [(f"f{i}", ctypes.c_double) for i in range(4)]
    def f(e, framework=framework, name=name, nd_in=nd_in):
        lib = _lib(framework)
        if lib is None: return 0
        try: cfn = getattr(lib, name)
        except AttributeError: return 0
        cfn.restype = R
        cfn.argtypes = [ctypes.c_double] * nd_in
        vals = [_f64(_dreg(e, i)) for i in range(nd_in)]
        try: r = cfn(*vals)
        except Exception: return 0
        for i in range(4):
            e.uc.reg_write(UC_ARM64_REG_D0 + i, struct.unpack("<Q", struct.pack("<d", getattr(r, f"f{i}")))[0])
        return None
    FUNCS["_" + name] = f

# --- AppKit C API (geometry in d-regs, the arm64 AAPCS HFA convention) ------
for _n, _nd in [("NSUnionRect", 8), ("NSIntersectionRect", 8), ("NSInsetRect", 6),
                ("NSOffsetRect", 6), ("NSIntegralRect", 4), ("NSIntegralRectWithOptions", 5)]:
    pass
_bind_rect("AppKit", "NSUnionRect", 8)
_bind_rect("AppKit", "NSIntersectionRect", 8)
_bind_rect("AppKit", "NSInsetRect", 6)
_bind_rect("AppKit", "NSOffsetRect", 6)
_bind_rect("AppKit", "NSIntegralRect", 4)
_bind("AppKit", "NSPointInRect", "idddddd")
_bind("AppKit", "NSMouseInRect", "iddddddc")
_bind("AppKit", "NSIntersectsRect", "idddddddd")
_bind("AppKit", "NSContainsRect", "idddddddd")
_bind("AppKit", "NSEqualRects", "idddddddd")
_bind("AppKit", "NSEqualPoints", "idddd")
_bind("AppKit", "NSEqualSizes", "idddd")
_bind("AppKit", "NSIsEmptyRect", "idddd")
_bind("AppKit", "NSRectFill", "vdddd")
_bind("AppKit", "NSRectFillUsingOperation", "vddddu")
_bind("AppKit", "NSFrameRect", "vdddd")
_bind("AppKit", "NSFrameRectWithWidth", "vddddd")
_bind("AppKit", "NSEraseRect", "vdddd")
_bind("AppKit", "NSDrawWhiteBezel", "vdddddddd")
_bind("AppKit", "NSDrawGrayBezel", "vdddddddd")
_bind("AppKit", "NSDrawGroove", "vdddddddd")
_bind("AppKit", "NSDrawButton", "vdddddddd")
_bind("AppKit", "NSRectClip", "vdddd")
_bind("AppKit", "NSBezierPath", ) if False else None
_bind("AppKit", "NSBeep", "v")
_bind("AppKit", "NSApplicationLoad", "c")
_bind("AppKit", "NSBestDepth", "upiiiic")
_bind("AppKit", "NSPlanarFromDepth", "ii")
_bind("AppKit", "NSBitsPerPixelFromDepth", "ii")
_bind("AppKit", "NSBitsPerSampleFromDepth", "ii")
_bind("AppKit", "NSNumberOfColorComponents", "ip")
_bind("AppKit", "NSAvailableWindowDepths", "p")
_bind("AppKit", "NSCountWindows", "vp")
_bind("AppKit", "NSWindowList", "vip")
_bind("AppKit", "NSPerformService", "cpp")
_bind("Foundation", "NSHomeDirectory", "p")
_bind("Foundation", "NSTemporaryDirectory", "p")
_bind("Foundation", "NSUserName", "p")
_bind("Foundation", "NSFullUserName", "p")
_bind("Foundation", "NSHomeDirectoryForUser", "pp")
_bind("Foundation", "NSOpenStepRootDirectory", "p")
_bind("Foundation", "NSSearchPathForDirectoriesInDomains", "puuc")
_bind("Foundation", "NSStringFromSelector", "pp")
_bind("Foundation", "NSStringFromProtocol", "pp")
_bind("Foundation", "NSZoneMalloc", "ppl")
_bind("Foundation", "NSZoneCalloc", "ppll")
_bind("Foundation", "NSZoneFree", "vpp")
_bind("Foundation", "NSDefaultMallocZone", "p")
_bind("Foundation", "NSAllocateMemoryPages", "pl")
_bind("Foundation", "NSDeallocateMemoryPages", "vpl")
_bind("Foundation", "NSCopyMemoryPages", "vppl")
_bind("Foundation", "NSRoundUpToMultipleOfPageSize", "ll")
_bind("Foundation", "NSRoundDownToMultipleOfPageSize", "ll")
_bind("Foundation", "NSPageSize", "l")
_bind("Foundation", "NSRealMemoryAvailable", "l")
_bind("Foundation", "NSAllocateObject", "ppl")
_bind("Foundation", "NSDeallocateObject", "vp")
_bind("Foundation", "NSCopyObject", "ppl")

# CoreGraphics. Rect-returning helpers follow the same 4-double convention.
_bind_rect("CoreGraphics", "CGRectInset", 6)
_bind_rect("CoreGraphics", "CGRectOffset", 6)
_bind_rect("CoreGraphics", "CGRectIntegral", 4)
_bind_rect("CoreGraphics", "CGRectUnion", 8)
_bind_rect("CoreGraphics", "CGRectIntersection", 8)
_bind_rect("CoreGraphics", "CGRectStandardize", 4)
_bind("CoreGraphics", "CGRectContainsPoint", "idddddd")
_bind("CoreGraphics", "CGRectContainsRect", "idddddddd")
_bind("CoreGraphics", "CGRectIntersectsRect", "idddddddd")
_bind("CoreGraphics", "CGRectEqualToRect", "idddddddd")
_bind("CoreGraphics", "CGRectIsEmpty", "idddd")
_bind("CoreGraphics", "CGRectIsNull", "idddd")
_bind("CoreGraphics", "CGPointEqualToPoint", "idddd")
_bind("CoreGraphics", "CGMainDisplayID", "u")
_bind("CoreGraphics", "CGDisplayPixelsWide", "uu")
_bind("CoreGraphics", "CGDisplayPixelsHigh", "uu")
_bind("CoreGraphics", "CGDisplayBounds", "Ru") if False else _bind("CoreGraphics", "CGDisplayBounds", "uu")
_bind("CoreGraphics", "CGDisplayIDToOpenGLDisplayMask", "uu")
_bind("CoreGraphics", "CGWarpMouseCursorPosition", "idd")
_bind("CoreGraphics", "CGAssociateMouseAndMouseCursorPosition", "ii")
_bind("CoreGraphics", "CGCursorIsVisible", "c")
_bind("CoreGraphics", "CGColorSpaceCreateDeviceRGB", "p")
_bind("CoreGraphics", "CGColorSpaceCreateDeviceGray", "p")
_bind("CoreGraphics", "CGColorSpaceCreateWithName", "pp")
_bind("CoreGraphics", "CGColorSpaceRelease", "vp")
_bind("CoreGraphics", "CGColorSpaceRetain", "pp")
_bind("CoreGraphics", "CGColorCreate", "ppp")
_bind("CoreGraphics", "CGColorCreateGenericRGB", "pdddd")
_bind("CoreGraphics", "CGColorRelease", "vp")
_bind("CoreGraphics", "CGColorRetain", "pp")
_bind("CoreGraphics", "CGColorGetComponents", "pp")
_bind("CoreGraphics", "CGImageRelease", "vp")
_bind("CoreGraphics", "CGImageRetain", "pp")
_bind("CoreGraphics", "CGImageGetWidth", "lp")
_bind("CoreGraphics", "CGImageGetHeight", "lp")
_bind("CoreGraphics", "CGImageGetBytesPerRow", "lp")
_bind("CoreGraphics", "CGImageGetBitsPerPixel", "lp")
_bind("CoreGraphics", "CGDataProviderCreateWithData", "ppplp")
_bind("CoreGraphics", "CGDataProviderCreateWithFilename", "pp")
_bind("CoreGraphics", "CGDataProviderRelease", "vp")
_bind("CoreGraphics", "CGBitmapContextCreate", "pplluupp")
_bind("CoreGraphics", "CGBitmapContextCreateImage", "pp")
_bind("CoreGraphics", "CGBitmapContextGetData", "pp")
_bind("CoreGraphics", "CGContextRelease", "vp")
_bind("CoreGraphics", "CGContextRetain", "pp")
_bind("CoreGraphics", "CGContextSetRGBFillColor", "vpdddd")
_bind("CoreGraphics", "CGContextSetRGBStrokeColor", "vpdddd")
_bind("CoreGraphics", "CGContextFillRect", "vpdddd")
_bind("CoreGraphics", "CGContextStrokeRect", "vpdddd")
_bind("CoreGraphics", "CGContextClearRect", "vpdddd")
_bind("CoreGraphics", "CGContextDrawImage", "vpddddp")
_bind("CoreGraphics", "CGContextSaveGState", "vp")
_bind("CoreGraphics", "CGContextRestoreGState", "vp")
_bind("CoreGraphics", "CGContextTranslateCTM", "vpdd")
_bind("CoreGraphics", "CGContextScaleCTM", "vpdd")
_bind("CoreGraphics", "CGContextRotateCTM", "vpd")
_bind("CoreGraphics", "CGContextSetLineWidth", "vpd")
_bind("CoreGraphics", "CGContextAddRect", "vpdddd")
_bind("CoreGraphics", "CGContextAddLineToPoint", "vpdd")
_bind("CoreGraphics", "CGContextMoveToPoint", "vpdd")
_bind("CoreGraphics", "CGContextStrokePath", "vp")
_bind("CoreGraphics", "CGContextFillPath", "vp")
_bind("CoreGraphics", "CGContextBeginPath", "vp")
_bind("CoreGraphics", "CGContextClosePath", "vp")
_bind("CoreGraphics", "CGContextClip", "vp")
_bind("CoreGraphics", "CGPathCreateMutable", "p")
_bind("CoreGraphics", "CGPathRelease", "vp")
_bind("CoreGraphics", "CGPathRetain", "pp")
_bind("CoreGraphics", "CGPathAddLineToPoint", "vppdddd")
_bind("CoreGraphics", "CGPathMoveToPoint", "vppdddd")
_bind("CoreGraphics", "CGPathCloseSubpath", "vpp")
_bind("CoreGraphics", "CGGetActiveDisplayList", "uppp")
_bind("CoreGraphics", "CGDisplayModeGetWidth", "lp")
_bind("CoreGraphics", "CGDisplayModeGetHeight", "lp")
_bind("CoreGraphics", "CGDisplayCopyDisplayMode", "pp")
_bind("CoreGraphics", "CGDisplayModeRelease", "vp")

# Metal C entry points. Almost all of Metal is objc_msgSend; these two are not.
_bind("Metal", "MTLCreateSystemDefaultDevice", "p")
_bind("Metal", "MTLCopyAllDevices", "p")

# QuartzCore
_bind("QuartzCore", "CACurrentMediaTime", "d")
_bind("QuartzCore", "CATransaction", ) if False else None

# CoreVideo display link: games drive their frame loop from this, not from NSApp.
_DL = {"cb": 0, "user": 0, "link": 0, "on": False}

@fn("CVDisplayLinkCreateWithActiveCGDisplays", "CVDisplayLinkCreateWithCGDisplay")
def _dlcreate(e):
    # (allocator-less) CVDisplayLinkRef *out
    link = e.malloc(16)
    e.write(link, b"CVDL" + b"\0" * 12)
    out = e.arg(0) if "Active" in "" else e.arg(1) if False else e.arg(0)
    # CreateWithActiveCGDisplays(CVDisplayLinkRef*)
    if e.arg(0): e.write(e.arg(0), link.to_bytes(8, "little"))
    _DL["link"] = link
    return 0
@fn("CVDisplayLinkSetOutputCallback")
def _dlset(e):
    _DL["link"] = e.arg(0) or _DL["link"]
    _DL["cb"] = e.arg(1)
    _DL["user"] = e.arg(2)
    return 0
@fn("CVDisplayLinkSetCurrentCGDisplayFromOpenGLContext")
def _dlgl(e): return 0
@fn("CVDisplayLinkStart")
def _dlstart(e):
    _DL["on"] = True; _DL["link"] = e.arg(0) or _DL["link"]; return 0
@fn("CVDisplayLinkStop")
def _dlstop(e):
    _DL["on"] = False; return 0
@fn("CVDisplayLinkRelease", "CVDisplayLinkRetain")
def _dlrel(e): return e.arg(0)
@fn("CVDisplayLinkIsRunning")
def _dlrun(e): return int(_DL["on"])
@fn("CVDisplayLinkGetNominalOutputVideoRefreshPeriod")
def _dlperiod(e): return 0

# CoreFoundation: toll-free objects are host pointers, so retain/release go to the host.
def _cf():
    return _lib("CoreFoundation")
@fn("CFRetain")
def _cfr(e):
    v = e.arg(0)
    lib = _cf()
    if lib and v and not objc.is_guest(e, v):
        lib.CFRetain.restype = ctypes.c_void_p
        lib.CFRetain.argtypes = [ctypes.c_void_p]
        return lib.CFRetain(v) or v
    return v
@fn("CFRelease")
def _cfrel(e):
    v = e.arg(0)
    lib = _cf()
    if lib and v and not objc.is_guest(e, v):
        lib.CFRelease.argtypes = [ctypes.c_void_p]
        lib.CFRelease(v)
    return None
@fn("CFAutorelease")
def _cfar(e): return e.arg(0)
@fn("CFGetRetainCount")
def _cfgr(e): return 1
@fn("CFRunLoopGetMain", "CFRunLoopGetCurrent")
def _cfrl(e): return 0xCF000001
@fn("CFRunLoopRun")
def _cfrun(e):
    enter_runloop(e)
@fn("CFRunLoopRunInMode")
def _cfrunm(e):
    # (mode, seconds, returnAfterSourceHandled) — one turn of our poll is enough
    _poll(e)
    return 1
@fn("CFRunLoopStop", "CFRunLoopWakeUp")
def _cfstop(e):
    e.stop_app = True; return None
@fn("CFStringCreateWithCString", "CFStringCreateWithBytes")
def _cfstr(e):
    if not DARWIN: return e.alloc_cstr(e.cstr(e.arg(1)) if e.arg(1) else "")
    s = e.cstr(e.arg(1)) if "CString" in sys._getframe().f_code.co_name else e.cstr(e.arg(1))
    lib = _cf()
    if not lib: return 0
    lib.CFStringCreateWithCString.restype = ctypes.c_void_p
    lib.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
    return lib.CFStringCreateWithCString(None, s.encode() + b"\0", 0x08000100) or 0
@fn("CFStringGetCStringPtr", "CFStringGetCString")
def _cfgcs(e):
    return e.arg(0)
@fn("CFBundleGetMainBundle")
def _cfb(e): return 0xCF000002
@fn("CFBundleCopyBundleURL", "CFBundleGetIdentifier")
def _cfbid(e): return 0
@fn("CFPreferencesCopyAppValue", "CFPreferencesSetAppValue")
def _cfp(e): return 0
@fn("CFAbsoluteTimeGetCurrent")
def _cfat(e):
    e.ret_double(time.time() + 978307200)  # CF absolute time is seconds since 2001
    return None
@fn("CFUUIDCreate", "CFUUIDCreateString")
def _cfu(e): return 0

def _bundle_plist(path):
    # .../Foo.app/Contents/MacOS/Foo -> .../Foo.app/Contents/Info.plist
    parts = os.path.abspath(path).split(os.sep)
    if "Contents" in parts:
        i = parts.index("Contents")
        plist = os.sep.join(parts[:i + 1] + ["Info.plist"])
        if os.path.isfile(plist):
            try:
                with open(plist, "rb") as f: return plistlib.load(f)
            except Exception as ex:
                sys.stderr.write(f"[cocoa] Info.plist: {ex}\n")
    return {}

def _app_paths(exe):
    exe = os.path.abspath(exe or "")
    parts = exe.split(os.sep)
    if "Contents" not in parts: return None, None
    i = parts.index("Contents")
    app = os.sep.join(parts[:i])
    res = os.sep.join(parts[:i + 1] + ["Resources"])
    return app, res if os.path.isdir(res) else None

def _nib_window(exe, info):
    """Title and content size from NSMainNibFile, else the executable name and 640x480."""
    title = str(info.get("CFBundleName") or info.get("CFBundleExecutable") or os.path.basename(exe or "App"))
    w, h = 640, 480
    nib = info.get("NSMainNibFile")
    res = _app_paths(exe)[1]
    if not nib or not res: return title, w, h
    path = os.path.join(res, nib + ".nib")
    if not os.path.isfile(path): return title, w, h
    try:
        objs = plistlib.load(open(path, "rb")).get("$objects") or []
    except Exception:
        return title, w, h
    import re
    for o in objs:
        if not isinstance(o, dict) or "NSWindowTitle" not in o or "NSWindowRect" not in o: continue
        t = o["NSWindowTitle"]
        if isinstance(t, plistlib.UID) and isinstance(objs[t.data], str) and objs[t.data] not in ("$null", ""):
            title = objs[t.data]
        rect = o["NSWindowRect"]
        if isinstance(rect, plistlib.UID): rect = objs[rect.data]
        if isinstance(rect, str):
            m = re.search(r"\{\s*[\d.]+\s*,\s*[\d.]+\s*\}\s*,\s*\{\s*([\d.]+)\s*,\s*([\d.]+)\s*\}", rect)
            if m:
                w, h = int(float(m.group(1))), int(float(m.group(2)))
        break
    return title, max(w, 64), max(h, 64)

# Host IMPs for a guest NSView/NSOpenGLView subclass. Struct-returning methods
# (drawRect:, initWithFrame:) are NOT overridden — their host ABI is painful and
# the guest runs them later, outside the AppKit callback.
_HOST_CBS = []
_KEYS = {}
def _retain(p):
    if not p: return 0
    p = int(p) & M64
    objc.note_host(p)
    try: objc.host()["objc"].objc_retain(p)
    except Exception: pass
    return p

def _sel(name):
    return objc.host()["objc"].sel_registerName(name.encode() if isinstance(name, str) else name)

def _method_imp(cls, name):
    o = objc.host()["objc"]
    m = o.class_getInstanceMethod(cls, _sel(name))
    if not m: return None, _sel(name)
    return o.method_getImplementation(m), _sel(name)

def _guest_view():
    best = None
    for addr, c in objc.CLASSES.items():
        if c["is_meta"]: continue
        if "initWithFrame:" in c["methods"] or "drawRect:" in c["methods"]:
            best = c
    return best

def _key_code(self, _sel):
    return _KEYS.get(self, 0) & 0xffff

def _repaint(self, _sel, _timer):
    e = _UI.get("e")
    if e is not None: e.need_draw = self

def _yes(self, _sel):
    return 1

def _on_key(self, sel, event):
    e = _UI.get("e")
    if e is None or not event: return
    try:
        code = int(objc.hmsg(event, "keyCode", restype=ctypes.c_ushort, argtypes=[]) or 0)
    except Exception:
        code = 0
    try:
        name = objc.host()["objc"].sel_getName(sel).decode()
    except Exception:
        name = "keyUp:"
    e._keyq = getattr(e, "_keyq", [])
    e._keyq.append((name, code))

def _on_sound(self, _sel, _sound, _done):
    return

def _register_host_view(e, guest):
    """Publish `MyOpenGLView` (or whatever the nib names) as a real host subclass."""
    o = objc.host()["objc"]
    if not hasattr(o, "_arm_bound"):
        o.objc_allocateClassPair.restype = ctypes.c_void_p
        o.objc_allocateClassPair.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
        o.objc_registerClassPair.argtypes = [ctypes.c_void_p]
        o._arm_bound = True
    sup = guest["super"] if objc.host_ok(e, guest["super"]) else 0
    if not sup:
        for n in (b"NSOpenGLView", b"NSView"):
            sup = o.objc_getClass(n)
            if sup: break
    if not sup:
        sys.stderr.write("[cocoa] no host superclass for %s\n" % guest["name"]); return 0
    name = guest["name"].encode()
    cls = o.objc_getClass(name)
    if not cls:
        cls = o.objc_allocateClassPair(sup, name, 0)
        if not cls:
            sys.stderr.write("[cocoa] objc_allocateClassPair %s failed\n" % guest["name"]); return 0
        def add(sel, types, cb):
            _HOST_CBS.append(cb)
            o.class_addMethod.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p]
            o.class_addMethod.restype = ctypes.c_bool
            ok = o.class_addMethod(cls, _sel(sel), ctypes.cast(cb, ctypes.c_void_p), types)
            if not ok: sys.stderr.write("[cocoa] class_addMethod %s failed\n" % sel)
        add("repaintGame:", b"v@:@", ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(_repaint))
        add("acceptsFirstResponder", b"B@:", ctypes.CFUNCTYPE(ctypes.c_uint8, ctypes.c_void_p, ctypes.c_void_p)(_yes))
        add("keyDown:", b"v@:@", ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(_on_key))
        add("keyUp:", b"v@:@", ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(_on_key))
        add("sound:didFinishPlaying:", b"v@:@B",
            ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint8)(_on_sound))
        add("awakeFromNib", b"v@:", ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)(lambda s, sel: None))
        o.objc_registerClassPair(cls)
    # keyCode stand-in so the guest's -keyUp: can message a real object.
    evcls = o.objc_getClass(b"ARM2X86Event")
    if not evcls:
        nsobj = o.objc_getClass(b"NSObject")
        evcls = o.objc_allocateClassPair(nsobj, b"ARM2X86Event", 0)
        if evcls:
            kcb = ctypes.CFUNCTYPE(ctypes.c_ushort, ctypes.c_void_p, ctypes.c_void_p)(_key_code)
            _HOST_CBS.append(kcb)
            o.class_addMethod.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p]
            o.class_addMethod(evcls, _sel("keyCode"), ctypes.cast(kcb, ctypes.c_void_p), b"S@:")
            o.objc_registerClassPair(evcls)
    e._evt = _retain(objc.hmsg(evcls, "new")) if evcls else 0
    return cls

class _NSRect(ctypes.Structure):
    _fields_ = [("x", ctypes.c_double), ("y", ctypes.c_double), ("w", ctypes.c_double), ("h", ctypes.c_double)]

def _present_opengl_app(e, guest):
    """Build the host window the nib would have built, then let the guest init it."""
    _UI["e"] = e
    o = objc.host()["objc"]
    app = getattr(e, "nsapp", None)
    if app:
        try:
            objc.hmsg(app, "setActivationPolicy:", 0, restype=ctypes.c_bool, argtypes=[ctypes.c_long])
        except Exception as ex:
            sys.stderr.write(f"[cocoa] setActivationPolicy: {ex}\n")
        try: objc.hmsg(app, "finishLaunching", restype=None, argtypes=[])
        except Exception as ex:
            sys.stderr.write(f"[cocoa] finishLaunching: {ex}\n")
    appdir, resdir = _app_paths(getattr(e, "path", ""))
    if resdir and os.path.isdir(resdir):
        try: os.chdir(resdir)
        except OSError: pass
    if appdir:
        try:
            NSString = o.objc_getClass(b"NSString")
            path = objc.hmsg(NSString, "stringWithUTF8String:", appdir.encode() + b"\0",
                             argtypes=[ctypes.c_char_p])
            bundle = objc.hmsg(o.objc_getClass(b"NSBundle"), "bundleWithPath:", path)
            e.app_bundle = _retain(bundle)
        except Exception as ex:
            sys.stderr.write(f"[cocoa] main bundle: {ex}\n")
    cls = _register_host_view(e, guest)
    if not cls: return
    title, w, h = _nib_window(getattr(e, "path", ""), getattr(e, "bundle_info", {}) or {})
    e.gl_size = (w, h)
    # Same attributes MyOpenGLView's initWithFrame: hands to NSOpenGLPixelFormat.
    attrs = (ctypes.c_uint32 * 14)(72, 80, 73, 5, 8, 24, 11, 8, 12, 24, 13, 8, 14, 0)
    try:
        pfcls = o.objc_getClass(b"NSOpenGLPixelFormat")
        pf = objc.hmsg(pfcls, "alloc")
        imp, sel = _method_imp(pfcls, "initWithAttributes:")
        if not imp: raise RuntimeError("no initWithAttributes:")
        PF = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
        pf = PF(imp)(pf, sel, ctypes.addressof(attrs))
        if not pf: raise RuntimeError("pixel format is nil (no OpenGL pixel format)")
        objc.note_host(pf)
        view = objc.hmsg(cls, "alloc")
        imp, sel = _method_imp(cls, "initWithFrame:pixelFormat:")
        if not imp: raise RuntimeError("no initWithFrame:pixelFormat:")
        INIT = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, _NSRect, ctypes.c_void_p)
        view = INIT(imp)(view, sel, _NSRect(0, 0, float(w), float(h)), pf)
        if not view: raise RuntimeError("OpenGL view init returned nil")
        view = _retain(view)
        e.preinited_views = {view & M64}
        e.gl_view = view & M64
        NSWindow = o.objc_getClass(b"NSWindow")
        win = objc.hmsg(NSWindow, "alloc")
        imp, sel = _method_imp(NSWindow, "initWithContentRect:styleMask:backing:defer:")
        WIN = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, _NSRect,
                               ctypes.c_ulong, ctypes.c_ulong, ctypes.c_uint8)
        win = WIN(imp)(win, sel, _NSRect(0, 0, float(w), float(h)), 15, 2, 0)
        win = _retain(win)
        e.nswindow = win
        NSString = o.objc_getClass(b"NSString")
        title_s = objc.hmsg(NSString, "stringWithUTF8String:", title.encode() + b"\0",
                            argtypes=[ctypes.c_char_p])
        objc.hmsg(win, "setTitle:", title_s)
        objc.hmsg(win, "setContentView:", view)
        objc.hmsg(win, "center", restype=None, argtypes=[])
        objc.hmsg(win, "makeKeyAndOrderFront:", None)
        objc.hmsg(win, "makeFirstResponder:", view)
        if app:
            objc.hmsg(app, "activateIgnoringOtherApps:", 1, restype=None, argtypes=[ctypes.c_int])
        try:
            ctx = objc.hmsg(view, "openGLContext")
            if ctx: objc.hmsg(ctx, "makeCurrentContext", restype=None, argtypes=[])
        except Exception:
            pass
        # Let AppKit map the window before the guest spends a long time in init.
        lib = _lib("CoreFoundation")
        if lib:
            mode = ctypes.c_void_p.in_dll(lib, "kCFRunLoopDefaultMode")
            lib.CFRunLoopRunInMode.restype = ctypes.c_int32
            lib.CFRunLoopRunInMode.argtypes = [ctypes.c_void_p, ctypes.c_double, ctypes.c_bool]
            lib.CFRunLoopRunInMode(mode, 0.05, False)
        imp = guest["methods"].get("initWithFrame:")
        if imp:
            e.launch_call = (imp, [e.gl_view, objc.sel_guest(e, "initWithFrame:"), 0.0, 0.0, float(w), float(h)])
        e.draw_imp = guest["methods"].get("drawRect:")
        sys.stderr.write("[cocoa] window '%s' %dx%d is on screen (%s)\n" % (title, w, h, guest["name"]))
    except Exception as ex:
        sys.stderr.write("[cocoa] failed to open the window: %s\n" % ex)
        import traceback; traceback.print_exc()

_UI = {}

def _ns(text):
    NSString = objc.host()["objc"].objc_getClass(b"NSString")
    return objc.hmsg(NSString, "stringWithUTF8String:", str(text).encode() + b"\0",
                     argtypes=[ctypes.c_char_p])

def _arr_count(arr):
    if not arr: return 0
    return int(objc.hmsg(arr, "count", restype=ctypes.c_ulong, argtypes=[]) or 0)

def _host_responds(obj, selname):
    o = objc.host()["objc"]
    cls = o.object_getClass(obj)
    return bool(cls and o.class_getInstanceMethod(cls, _sel(selname)))

_FMT_CBS = []
def _formatter_stubs(o, cls, nsformatter):
    """A guest NSFormatter subclass is published on the host with NO methods; AppKit then calls -stringForObjectValue: on it
    while loading a nib and NSFormatter throws 'only defined for abstract class' (uncatchable from ctypes -> abort).
    Give the host stand-in harmless concrete implementations."""
    c = o.class_getSuperclass; c.restype, c.argtypes = ctypes.c_void_p, [ctypes.c_void_p]
    k = c(cls)
    while k and k != nsformatter: k = c(k)
    if not k: return False
    def s_for(self, sel, obj):
        try:
            if obj and _host_responds(obj, "description"): return _retain(objc.hmsg(obj, "description"))
        except Exception: pass
        return _retain(_ns(""))
    def get_obj(self, sel, outobj, string, outerr):
        if outobj: ctypes.c_void_p.from_address(outobj).value = string
        return 1
    a = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(s_for)
    b = ctypes.CFUNCTYPE(ctypes.c_int8, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(get_obj)
    _FMT_CBS.extend((a, b))
    o.class_addMethod(cls, _sel("stringForObjectValue:"), ctypes.cast(a, ctypes.c_void_p), b"@@:@")
    o.class_addMethod(cls, _sel("getObjectValue:forString:errorDescription:"), ctypes.cast(b, ctypes.c_void_p), b"c@:^@@^@")
    return True

def _publish_guest_classes(e):
    """Host nib unarchiver looks classes up by name. Methods still run in the guest."""
    if not DARWIN: return 0
    o = objc.host()["objc"]
    o.objc_allocateClassPair.restype = ctypes.c_void_p
    o.objc_allocateClassPair.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    o.objc_registerClassPair.argtypes = [ctypes.c_void_p]
    o.class_addMethod.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p]
    o.class_addMethod.restype = ctypes.c_bool
    nsobj = o.objc_getClass(b"NSObject")
    init_cb = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(lambda s, sel: s)
    awake_cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)(lambda s, sel: None)
    _HOST_CBS.extend((init_cb, awake_cb))
    n = 0
    for c in list(objc.CLASSES.values()):
        if c.get("is_meta"): continue
        raw = c["name"].encode()
        if not raw or o.objc_getClass(raw): continue
        sup = c["super"] if objc.host_ok(e, c["super"]) else 0
        if not sup or sup in objc.CLASSES:
            # Walk guest supers until a host class, else NSObject.
            g = objc.CLASSES.get(c["super"])
            sup = nsobj
            seen = set()
            while g and g["addr"] not in seen:
                seen.add(g["addr"])
                if objc.host_ok(e, g["super"]):
                    sup = g["super"]
                    break
                g = objc.CLASSES.get(g["super"])
        cls = o.objc_allocateClassPair(sup or nsobj, raw, 0)
        if not cls: continue
        o.class_addMethod(cls, _sel("init"), ctypes.cast(init_cb, ctypes.c_void_p), b"@@:")
        o.class_addMethod(cls, _sel("awakeFromNib"), ctypes.cast(awake_cb, ctypes.c_void_p), b"v@:")
        try: _formatter_stubs(o, cls, o.objc_getClass(b"NSFormatter"))
        except Exception as ex: sys.stderr.write(f"[cocoa] formatter stubs for {c['name']}: {ex}\n")
        o.objc_registerClassPair(cls)
        objc.note_host(cls)
        n += 1
    return n

def _order_front(app):
    if not app: return 0
    wins = objc.hmsg(app, "windows")
    n = _arr_count(wins)
    for i in range(n):
        w = objc.hmsg(wins, "objectAtIndex:", i, argtypes=[ctypes.c_ulong])
        if w and _host_responds(w, "orderFrontRegardless"):
            objc.hmsg(w, "orderFrontRegardless", restype=None, argtypes=[])
    return n

def _load_named_nib(bundle, app, nib):
    name = _ns(nib)
    if _host_responds(bundle, "loadNibNamed:owner:topLevelObjects:"):
        ok = objc.hmsg(bundle, "loadNibNamed:owner:topLevelObjects:", name, app, None,
                       restype=ctypes.c_bool,
                       argtypes=[ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p])
        if ok: return True
    NSBundle = objc.host()["objc"].objc_getClass(b"NSBundle")
    return bool(objc.hmsg(NSBundle, "loadNibNamed:owner:", name, app,
                          restype=ctypes.c_bool,
                          argtypes=[ctypes.c_void_p, ctypes.c_void_p]))

# ---- app identity: Dock icon / name, and the installer's own windows ---------------------------------------------------------
def _set_identity(e, app, app_path, res, info):
    """Make the process look like the installer: its real icon in the Dock/Cmd-Tab and its name in the menu bar/Dock."""
    o = objc.host()["objc"]
    name = str(info.get("CFBundleDisplayName") or info.get("CFBundleName") or os.path.basename(app_path or "App")[:-4])
    try:
        pi = objc.hmsg(o.objc_getClass(b"NSProcessInfo"), "processInfo")
        objc.hmsg(pi, "setProcessName:", _ns(name), restype=None, argtypes=[ctypes.c_void_p])
    except Exception as ex: sys.stderr.write(f"[cocoa] setProcessName: {ex}\n")
    # Dock label: private LaunchServices call, best effort (the label stays "Python" if this OS refuses it)
    try:
        asv = ctypes.CDLL("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices")
        asv._LSGetCurrentApplicationASN.restype = ctypes.c_void_p
        asv._LSSetApplicationInformationItem.restype = ctypes.c_int32
        asv._LSSetApplicationInformationItem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        key = ctypes.c_void_p.in_dll(asv, "_kLSDisplayNameKey")
        r = asv._LSSetApplicationInformationItem(-2, asv._LSGetCurrentApplicationASN(), key, _ns(name), None)
        sys.stderr.write(f"[cocoa] Dock name '{name}' (LaunchServices status {r})\n")
    except Exception as ex: sys.stderr.write(f"[cocoa] Dock name not changed: {ex}\n")
    img = 0
    try:
        icns = info.get("CFBundleIconFile")
        if icns and res:
            p = os.path.join(res, icns if os.path.splitext(icns)[1] else icns + ".icns")
            if os.path.isfile(p):
                img = objc.hmsg(objc.hmsg(o.objc_getClass(b"NSImage"), "alloc"), "initWithContentsOfFile:", _ns(p),
                                argtypes=[ctypes.c_void_p])
        if not img and app_path:                                  # Assets.car icons (CFBundleIconName): let Finder resolve it
            ws = objc.hmsg(o.objc_getClass(b"NSWorkspace"), "sharedWorkspace")
            img = objc.hmsg(ws, "iconForFile:", _ns(app_path), argtypes=[ctypes.c_void_p])
        if img:
            objc.hmsg(app, "setApplicationIconImage:", img, restype=None, argtypes=[ctypes.c_void_p])
            sys.stderr.write("[cocoa] Dock icon set from the installer bundle\n")
        else: sys.stderr.write("[cocoa] no icon found in the installer bundle\n")
    except Exception as ex: sys.stderr.write(f"[cocoa] icon: {ex}\n")

_UI = {"shown": set()}
# secondary windows: the guest shows them on demand (password prompt, ...); showing them at start-up is wrong
_AUX_WINDOWS = {"IAUserAuthWindowController"}
def _ensure_windows(e):
    """Show every host NSWindowController proxy the guest created (e.g. IASetupController -> IASetupWindow) once, as soon as
    it exists. The guest's classes from IA.bundle are published first so the nib can instantiate its custom views."""
    hp = getattr(objc, "HOST_PROXY", None)
    if not DARWIN or not hp: return
    new = [g for g in list(hp) if g not in _UI["shown"]]
    if not new: return
    app = getattr(e, "nsapp", None)
    try: _publish_guest_classes(e)
    except Exception as ex: sys.stderr.write(f"[cocoa] publish classes: {ex}\n")
    for g in new:
        _UI["shown"].add(g); wc = hp[g]
        try:
            w = objc.hmsg(wc, "window")
            if not w: sys.stderr.write(f"[cocoa] proxy {wc:#x}: its nib has no window\n"); continue
            # the nib is loaded: its outlets now sit in the guest controller's ivars -> run the guest's own setup code
            try:
                gcls = objc.CLASSES.get(struct.unpack("<Q", bytes(e.read(g, 8)))[0])
                for nm in ("awakeFromNib", "windowDidLoad"):
                    imp = objc.lookup(gcls, nm, False) if gcls else None
                    if imp:
                        with objc._LOCK: objc.PENDING.append((imp, [g, objc.sel_guest(e, nm)]))
                        sys.stderr.write(f"[cocoa] queued guest -[{gcls['name']} {nm}]\n")
            except Exception as ex: sys.stderr.write(f"[cocoa] guest window setup: {ex}\n")
            gname = ""
            try: gname = objc.CLASSES.get(struct.unpack("<Q", bytes(e.read(g, 8)))[0], {}).get("name", "")
            except Exception: pass
            if gname in _AUX_WINDOWS and not os.environ.get("ARM2X86_SHOW_ALL_WINDOWS"):
                # the nib has "Visible At Launch" set, so merely loading it (the -window call above) already put it on screen
                for sel in ("orderOut:",):
                    try: objc.hmsg(w, sel, 0)
                    except Exception: pass
                sys.stderr.write(f"[cocoa] {gname}: window hidden (the installer opens it itself when it needs it)\n"); continue
            objc.hmsg(w, "center", restype=None, argtypes=[])
            objc.hmsg(wc, "showWindow:", 0)
            objc.hmsg(w, "makeKeyAndOrderFront:", 0)
            objc.hmsg(w, "orderFrontRegardless", restype=None, argtypes=[])
            if app: objc.hmsg(app, "activateIgnoringOtherApps:", 1, restype=None, argtypes=[ctypes.c_int])
            sys.stderr.write(f"[cocoa] installer window shown (proxy {wc:#x}, window {w:#x}); WindowServer windows: {_arr_count(objc.hmsg(app, 'windows')) if app else '?'}\n")
        except Exception as ex:
            sys.stderr.write(f"[cocoa] showing window failed: {ex}\n")

def _show_host_ui(e):
    """Load MainMenu.nib (or whatever Info.plist names) through host AppKit.
    Do not call _CFBundleSetMainBundle: that symbol is a ud2 trap on this OS."""
    exe = getattr(e, "path", "") or ""
    info = getattr(e, "bundle_info", {}) or {}
    app_path, res = _app_paths(exe)
    nib = str(info.get("NSMainNibFile") or "MainMenu")
    sys.stderr.write("[cocoa] host UI v2 %s nib=%s\n" % (app_path or exe or "?", nib))
    app = getattr(e, "nsapp", None)
    if not app or not app_path:
        sys.stderr.write("[cocoa] no host NSApp or .app bundle\n")
        return 0
    if _host_responds(app, "setActivationPolicy:"):
        objc.hmsg(app, "setActivationPolicy:", 0, restype=ctypes.c_bool, argtypes=[ctypes.c_long])
    bundle = objc.hmsg(objc.host()["objc"].objc_getClass(b"NSBundle"), "bundleWithPath:", _ns(app_path))
    if not bundle:
        sys.stderr.write("[cocoa] bundleWithPath failed\n")
        return 0
    e.app_bundle = _retain(bundle)
    try:
        ok = _load_named_nib(bundle, app, nib)
        sys.stderr.write("[cocoa] nib '%s' -> %s\n" % (nib, bool(ok)))
    except Exception as ex:
        sys.stderr.write("[cocoa] nib '%s' failed: %s\n" % (nib, ex))
    try: _set_identity(e, app, app_path, res, info)
    except Exception as ex: sys.stderr.write(f"[cocoa] identity: {ex}\n")
    if _host_responds(app, "activateIgnoringOtherApps:"):
        objc.hmsg(app, "activateIgnoringOtherApps:", 1, restype=None, argtypes=[ctypes.c_int])
    n = _order_front(app)
    sys.stderr.write("[cocoa] WindowServer windows: %d\n" % n)
    return n

def _boot(e):
    info = _bundle_plist(getattr(e, "path", "") or "")
    e.bundle_info = info
    for k, v in (info.get("LSEnvironment") or {}).items():
        os.environ[str(k)] = str(v)
    principal = info.get("NSPrincipalClass") or "NSApplication"
    e.delegate_obj = 0
    e.preinited_views = set()
    for c in objc.CLASSES.values():
        if c.get("is_meta"): continue
        meths = ", ".join(sorted(c["methods"])[:24])
        sys.stderr.write("[cocoa] class %s: %s\n" % (c["name"], meths or "(no methods)"))
    if DARWIN:
        try:
            n = _publish_guest_classes(e)
            if n: sys.stderr.write("[cocoa] published %d guest class(es) on the host\n" % n)
        except Exception as ex:
            sys.stderr.write("[cocoa] publish guest classes: %s\n" % ex)
        try:
            NSApp = objc.host()["objc"].objc_getClass(principal.encode()) or objc.host()["objc"].objc_getClass(b"NSApplication")
            if NSApp:
                happ = objc.hmsg(NSApp, "sharedApplication")
                if happ: _publish(e, happ)
        except Exception as ex:
            sys.stderr.write("[cocoa] sharedApplication: %s\n" % ex)
        try:
            _show_host_ui(e)
        except Exception as ex:
            sys.stderr.write("[cocoa] host UI failed: %s\n" % ex)
            import traceback; traceback.print_exc()
        if os.environ.get("ARM2X86_PYWIN"):
            guest = _guest_view()
            if guest and "initWithFrame:" in guest["methods"]:
                _present_opengl_app(e, guest)
    did = objc.find_delegate(e)
    if not did and principal not in ("NSApplication",) and principal in objc.BY_NAME:
        did = objc.BY_NAME[principal]
    if did:
        inst = objc.alloc_instance(e, objc.CLASSES[did])
        e.delegate_obj = inst
        e.delegate_class = did
        sys.stderr.write("[cocoa] guest delegate %s\n" % objc.CLASSES[did]["name"])
    else:
        sys.stderr.write("[cocoa] no guest controller\n")

def _publish(e, ptr):
    objc._publish_nsapp(e, ptr)

def delegate_calls(e):
    inst = getattr(e, "delegate_obj", 0)
    if not inst: return []
    cls = objc.CLASSES.get(getattr(e, "delegate_class", 0)) or objc.CLASSES.get(
        struct.unpack("<Q", bytes(e.read(inst, 8)))[0])
    if not cls: return []
    calls = []
    init = objc.lookup(cls, "init", False)
    if init:
        calls.append((init, [inst, objc.sel_guest(e, "init")]))
    for sel in ("awakeFromNib", "applicationWillFinishLaunching:", "applicationDidFinishLaunching:",
                "applicationDidBecomeActive:"):
        imp = objc.lookup(cls, sel, False)
        if imp:
            if sel.endswith(":"):
                calls.append((imp, [inst, objc.sel_guest(e, sel), 0]))
            else:
                calls.append((imp, [inst, objc.sel_guest(e, sel)]))
    return calls

def install(e):
    """Map the run-loop trampoline. blr x20; cbnz x0, loop; ret."""
    try:
        e.uc.mem_map(RUNLOOP, 0x1000)
    except Exception:
        pass
    # 0xD63F0280 blr x20
    # 0xB5FFFFE0 cbnz x0, .-4
    # 0xD65F03C0 ret
    e.write(RUNLOOP, struct.pack("<III", 0xD63F0280, 0xB5FFFFE0, 0xD65F03C0))

def enter_runloop(e):
    e.uc.reg_write(UC_ARM64_REG_X20, e.resolve("_arm2x86_poll"))
    e.uc.reg_write(UC_ARM64_REG_PC, RUNLOOP)

def _stamp(e):
    if getattr(e, "_cvstamp", 0): return e._cvstamp
    p = e.malloc(64)
    e.write(p, b"\0" * 64)
    e._cvstamp = p
    # version, videoTimeScale=0, hostTime
    e.write(p, struct.pack("<Ii", 0, 0))
    return p


class _Rect(ctypes.Structure):
    _fields_ = [("x", ctypes.c_double), ("y", ctypes.c_double), ("w", ctypes.c_double), ("h", ctypes.c_double)]
_STRET = {}
def _frame_of(v):
    """-[NSView frame]: a 32-byte NSRect is returned through memory on x86-64, i.e. via objc_msgSend_stret (plain objc_msgSend
    with a struct return type crashed the dump with a bus error)."""
    h = objc.host()["objc"]
    if "f" not in _STRET:
        _STRET["f"] = ctypes.CFUNCTYPE(None, ctypes.POINTER(_Rect), ctypes.c_void_p, ctypes.c_void_p)(
            ctypes.cast(h.objc_msgSend_stret, ctypes.c_void_p).value)
    r = _Rect()
    _STRET["f"](ctypes.byref(r), v, h.sel_registerName(b"frame"))
    return r
def _cname(obj):
    o = objc.host()["objc"]
    o.object_getClass.restype, o.object_getClass.argtypes = ctypes.c_void_p, [ctypes.c_void_p]
    o.class_getName.restype, o.class_getName.argtypes = ctypes.c_char_p, [ctypes.c_void_p]
    return (o.class_getName(o.object_getClass(obj)) or b"?").decode()
def _dump_view(v, depth, out):
    try:
        fr = _frame_of(v)
        hid = objc.hmsg(v, "isHidden", restype=ctypes.c_ubyte, argtypes=[])
        extra = ""
        if _host_responds(v, "image") and _host_responds(v, "setImage:"):
            im = objc.hmsg(v, "image")
            extra = " image=" + ("nil" if not im else _cname(im))
        if _host_responds(v, "title") and _host_responds(v, "setTitle:"):
            t = objc.hmsg(v, "title")
            if t: extra += " title=%r" % ctypes.string_at(objc.hmsg(t, "UTF8String")).decode("utf8", "replace")
        out.append("  " * depth + f"{_cname(v)} frame=({fr.x:.0f},{fr.y:.0f},{fr.w:.0f},{fr.h:.0f}) hidden={bool(hid)}{extra}")
        subs = objc.hmsg(v, "subviews")
        n = _arr_count(subs) if subs else 0
        for i in range(n):
            _dump_view(objc.hmsg(subs, "objectAtIndex:", i, argtypes=[ctypes.c_ulong]), depth + 1, out)
    except Exception as ex:
        out.append("  " * depth + f"(dump failed: {ex})")

def _force_continue(e, root):
    """Fallback: the installer's Continue button stays hidden because its own logic waits for services we do not emulate yet
    (IADiskManager, OSISClient ...). Unhide it and give it the arrow image so the UI can be driven.  ARM2X86_NO_FORCE_CONTINUE=1 disables."""
    out = []
    def walk(v):
        subs = objc.hmsg(v, "subviews"); n = _arr_count(subs) if subs else 0
        for i in range(n):
            sv = objc.hmsg(subs, "objectAtIndex:", i, argtypes=[ctypes.c_ulong])
            if _cname(sv) == "NSButton":
                fr = _frame_of(sv)
                if abs(fr.w - 95) < 3 and abs(fr.h - 60) < 3 and objc.hmsg(sv, "isHidden", restype=ctypes.c_ubyte, argtypes=[]) and not out:
                    out.append(sv)
            walk(sv)
    walk(root)
    if not out: return
    b = out[0]; NSImage = objc.host()["objc"].objc_getClass(b"NSImage")
    img = objc.hmsg(NSImage, "imageNamed:", objc._new_host_string("arrowbutton"))
    alt = objc.hmsg(NSImage, "imageNamed:", objc._new_host_string("arrowbuttonPressed"))
    objc.hmsg(b, "setHidden:", 0, restype=None, argtypes=[ctypes.c_ubyte])
    if img:
        objc.hmsg(b, "setImage:", img, restype=None); objc.hmsg(b, "setImagePosition:", 1, restype=None, argtypes=[ctypes.c_long])
        objc.hmsg(b, "setBordered:", 0, restype=None, argtypes=[ctypes.c_ubyte])
        if alt: objc.hmsg(b, "setAlternateImage:", alt, restype=None)
    objc.hmsg(b, "setEnabled:", 1, restype=None, argtypes=[ctypes.c_ubyte])
    _UI["cont"] = b
    try:
        tgt = objc.hmsg(b, "target"); act = objc.hmsg(b, "action", restype=ctypes.c_void_p, argtypes=[])
        o = objc.host()["objc"]; o.sel_getName.restype, o.sel_getName.argtypes = ctypes.c_char_p, [ctypes.c_void_p]
        an = (o.sel_getName(act) or b"").decode() if act else "(none)"
        sys.stderr.write(f"[cocoa] Continue button: target={_cname(tgt) if tgt else 'nil'} {tgt or 0:#x} action={an}\n")
        w = objc.hmsg(b, "window")
        if w and not os.environ.get("ARM2X86_NO_CLOSABLE"):          # the installer's window has no close box; add one
            sm = objc.hmsg(w, "styleMask", restype=ctypes.c_ulong, argtypes=[])
            objc.hmsg(w, "setStyleMask:", sm | 2, restype=None, argtypes=[ctypes.c_ulong])
    except Exception as ex: sys.stderr.write(f"[cocoa] continue info: {ex}\n")
    sys.stderr.write(f"[cocoa] Continue button forced visible + enabled ({b:#x}, image {'arrowbutton' if img else 'MISSING'})\n")
_DUMPED = []
def _dump_ui_once(e):
    """a few seconds after start-up (the guest's windowDidLoad has run by then): print the setup window's view tree"""
    if _DUMPED or not DARWIN: return
    t0 = _UI.setdefault("t0", time.time())
    if not _UI["shown"] or time.time() - t0 < 4: return
    _DUMPED.append(1)
    app = getattr(e, "nsapp", None)
    ws = objc.hmsg(app, "windows") if app else 0
    out = ["[cocoa] ---- UI dump (ARM2X86_NO_UIDUMP=1 to disable) ----"]
    for i in range(_arr_count(ws) if ws else 0):
        w = objc.hmsg(ws, "objectAtIndex:", i, argtypes=[ctypes.c_ulong])
        vis = objc.hmsg(w, "isVisible", restype=ctypes.c_ubyte, argtypes=[])
        out.append(f"window {w:#x} {_cname(w)} visible={bool(vis)}")
        if vis:
            cv = objc.hmsg(w, "contentView")
            if cv:
                if not os.environ.get("ARM2X86_NO_FORCE_CONTINUE"):
                    try: _force_continue(e, cv)
                    except Exception as ex: sys.stderr.write(f"[cocoa] force continue: {ex}\n")
                _dump_view(cv, 1, out)
    sys.stderr.write("\n".join(out) + "\n")

@fn("arm2x86_poll")
def _poll(e):
    if getattr(e, "stop_app", False) or e.exit_code is not None:
        return 0
    if hasattr(e, "schedule"):
        e.schedule(False)
    _pump_host(e)
    try: _ensure_windows(e)
    except Exception as ex: sys.stderr.write(f"[cocoa] ensure_windows: {ex}\n")
    b = _UI.get("cont")
    if b and time.time() - _UI.get("cont_t", 0) > 0.5:
        _UI["cont_t"] = time.time()
        try:
            if not objc.hmsg(b, "isEnabled", restype=ctypes.c_ubyte, argtypes=[]): objc.hmsg(b, "setEnabled:", 1, restype=None, argtypes=[ctypes.c_ubyte])
            if objc.hmsg(b, "isHidden", restype=ctypes.c_ubyte, argtypes=[]): objc.hmsg(b, "setHidden:", 0, restype=None, argtypes=[ctypes.c_ubyte])
        except Exception: pass
    if not os.environ.get("ARM2X86_NO_UIDUMP"):
        try: _dump_ui_once(e)
        except Exception as ex: sys.stderr.write(f"[cocoa] ui dump: {ex}\n")
    if getattr(e, "stop_app", False) or e.exit_code is not None:
        return 0
    frames = []
    if _DL["on"] and _DL["cb"]:
        st = _stamp(e)
        # CVReturn (*)(link, inNow, inOutput, flagsIn, flagsOut, user)
        frames.append((_DL["cb"], [_DL["link"], st, st, 0, 0, _DL["user"]]))
    try:
        frames.extend(objc.take_pending())
    except Exception:
        pass
    frames.extend(_ui_frames(e))
    if frames:
        e.begin_callbacks(frames, 1)
        return None
    if not getattr(e, "_poll_noted", False):
        e._poll_noted = True
        sys.stderr.write("[cocoa] in NSApp run loop; pumping the host run loop\n")
    return 1

_NSAPP_STATE = {}

def _appkit_pump(e):
    """Drain AppKit's event queue the way [NSApp run] would. CFRunLoopRunInMode alone never
    drains NSApp's events, so LaunchServices never sees the app finish launching (Dock bounces)."""
    app = getattr(e, "nsapp", None)
    if not app:
        try:
            app = objc.hmsg(objc.host()["objc"].objc_getClass(b"NSApplication"), "sharedApplication")
            e.nsapp = app
        except Exception:
            return False
    o = objc.host()["objc"]
    st = _NSAPP_STATE
    if not st.get("launched"):
        st["launched"] = True
        try: objc.hmsg(app, "setActivationPolicy:", 0, restype=ctypes.c_bool, argtypes=[ctypes.c_long])
        except Exception: pass
        try: objc.hmsg(app, "finishLaunching", restype=None, argtypes=[])
        except Exception as ex: sys.stderr.write(f"[cocoa] finishLaunching: {ex}\n")
        try: objc.hmsg(app, "activateIgnoringOtherApps:", 1, restype=None, argtypes=[ctypes.c_int])
        except Exception: pass
    if "date" not in st:
        st["date"] = objc.hmsg(o.objc_getClass(b"NSDate"), "distantPast")
        fnd = _lib("Foundation")
        st["mode"] = ctypes.c_void_p.in_dll(fnd, "NSDefaultRunLoopMode").value
    for _ in range(64):                                   # bounded drain per poll
        ev = objc.hmsg(app, "nextEventMatchingMask:untilDate:inMode:dequeue:",
                       ctypes.c_ulonglong(0xffffffffffffffff), st["date"], st["mode"], True,
                       argtypes=[ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool])
        if not ev: break
        objc.hmsg(app, "sendEvent:", ev, restype=None)
    try: objc.hmsg(app, "updateWindows", restype=None, argtypes=[])
    except Exception: pass
    return True

def _pump_host(e):
    if not DARWIN:
        time.sleep(0.01); return
    try:
        if not _NSAPP_STATE.get("broken") and _appkit_pump(e):
            lib = _lib("CoreFoundation")
            mode = ctypes.c_void_p.in_dll(lib, "kCFRunLoopDefaultMode")
            lib.CFRunLoopRunInMode.restype = ctypes.c_int32
            lib.CFRunLoopRunInMode.argtypes = [ctypes.c_void_p, ctypes.c_double, ctypes.c_bool]
            lib.CFRunLoopRunInMode(mode, 0.005, True)
            return
    except Exception as ex:
        _NSAPP_STATE["broken"] = True
        sys.stderr.write(f"[cocoa] AppKit pump disabled ({ex}); falling back to CFRunLoop only\n")
    try:
        lib = _lib("CoreFoundation")
        mode = ctypes.c_void_p.in_dll(lib, "kCFRunLoopDefaultMode")
        lib.CFRunLoopRunInMode.restype = ctypes.c_int32
        lib.CFRunLoopRunInMode.argtypes = [ctypes.c_void_p, ctypes.c_double, ctypes.c_bool]
        lib.CFRunLoopRunInMode(mode, 0.01, True)
    except Exception:
        time.sleep(0.01)

def _ui_frames(e):
    """Guest drawRect: / keyUp: requested by AppKit while the run loop was pumping."""
    out = []
    view = getattr(e, "need_draw", None)
    if view and getattr(e, "draw_imp", None):
        e.need_draw = None
        w, h = getattr(e, "gl_size", (640, 480))
        out.append((e.draw_imp, [view & M64, objc.sel_guest(e, "drawRect:"), 0.0, 0.0, float(w), float(h)]))
    if getattr(e, "_keyq", None):
        # One thunk per key; it fills the fake event and jumps into the guest IMP.
        n = len(e._keyq)
        thunk = e.resolve("_arm2x86_keydispatch")
        out.extend((thunk, []) for _ in range(n))
    return out

def _keydispatch(e):
    q = getattr(e, "_keyq", [])
    if not q: return 0
    name, code = q.pop(0)
    evt = getattr(e, "_evt", 0) or 0
    _KEYS[evt] = code
    guest = _guest_view()
    imp = guest["methods"].get(name) if guest else None
    if not imp or not getattr(e, "gl_view", 0): return 0
    e.uc.reg_write(UC_ARM64_REG_X0, e.gl_view & M64)
    e.uc.reg_write(UC_ARM64_REG_X1, objc.sel_guest(e, name))
    e.uc.reg_write(UC_ARM64_REG_X2, evt & M64)
    e.uc.reg_write(UC_ARM64_REG_PC, imp)
    return None
FUNCS["_arm2x86_keydispatch"] = _keydispatch

FUNCS["_arm2x86_poll"] = _poll

@fn("NSApplicationMain")
def _nsappmain(e):
    sys.stderr.write("[cocoa] NSApplicationMain v2: host nib, no CFBundleSetMainBundle\n")
    sys.stderr.flush()
    _boot(e)
    calls = []
    if getattr(e, "launch_call", None):
        calls.append(e.launch_call)
    extra = delegate_calls(e)
    sys.stderr.write("[cocoa] NSApplicationMain delegate calls: %d\n" % len(extra))
    calls.extend(extra)
    calls.append((e.resolve("_arm2x86_enter_runloop"), []))
    e.begin_callbacks(calls, 0)
    return None

def _enter_stub(e):
    enter_runloop(e)
FUNCS["_arm2x86_enter_runloop"] = _enter_stub

# A handful of Foundation functions that return NSRect/NSPoint by value.
_bind_rect("Foundation", "NSRectFromString", 0) if False else None
@fn("NSRectFromString", "NSPointFromString", "NSSizeFromString", "NSRangeFromString")
def _fromstr(e):
    # Zero rect/point is a legal answer when the string isn't a rectangle.
    for i in range(4):
        e.uc.reg_write(UC_ARM64_REG_D0 + i, 0)
    return 0
