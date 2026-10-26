#!/usr/bin/env python3
"""Generates sdl3sigs.py (exact SDL3 function signatures) next to this script.   pip3 install pysdl3 && python3 gen_sdl3sigs.py"""
import os, ctypes as C
os.environ["SDL_DOC"] = "0"
# pysdl3 also loads SDL3_ttf/image/mixer/... and dies when one of THEIR dependencies (e.g. Homebrew's freetype) is missing.
# Only core SDL3's signatures are needed here, so a library that fails to load is replaced by an empty stand-in.
_orig_cdll = C.CDLL
class _SafeCDLL(_orig_cdll):                    # a real subclass: pysdl3 uses `ctypes.CDLL | None` in annotations
    def __init__(self, name, *a, **k):
        self._failed = False
        try: super().__init__(name, *a, **k)
        except OSError as ex:
            print(f"(skipping {os.path.basename(str(name))}: {str(ex).splitlines()[0][:90]})")
            self._failed, self._name, self._handle = True, str(name), 0
    def __getattr__(self, n):
        if self.__dict__.get("_failed") or n.startswith("__"): raise AttributeError(n)
        return super().__getattr__(n)
    def __getitem__(self, n):
        if self.__dict__.get("_failed"): raise AttributeError(n)
        return super().__getitem__(n)
C.CDLL = _SafeCDLL
import sdl3
def kind(t, top=True):
    if t is None: return ("0", 0)
    if t is C.c_char_p: return ("s", 8)
    if t is C.c_void_p: return ("v", 8)
    if isinstance(t, type) and issubclass(t, C._CFuncPtr):
        return ("cb", 8, ([kind(a, False) for a in (t._argtypes_ or ())], kind(t._restype_, False)))
    if isinstance(t, type) and issubclass(t, C._Pointer):
        p = t._type_
        if p is C.c_void_p or (isinstance(p, type) and issubclass(p, (C._Pointer, C._CFuncPtr))) or p is C.c_char_p: return ("pp", 8)
        return ("p", C.sizeof(p))
    if isinstance(t, type) and issubclass(t, (C.Structure, C.Union)): return ("st", C.sizeof(t))
    c = getattr(t, "_type_", None)
    if c in "bhilq": return ("i", C.sizeof(t))
    if c in "BHILQ?c": return ("u", C.sizeof(t))
    if c == "f": return ("f", 4)
    if c == "d": return ("d", 8)
    if c in ("P", "z", "Z"): return ("v", 8)
    return ("?", 8)
names = [n for n in dir(sdl3) if n.startswith("SDL_")]
with_sig = [n for n in names if getattr(getattr(sdl3, n), "argtypes", None) is not None]
print(f"[diag] pysdl3 {getattr(sdl3, '__version__', '?')}: {len(names)} SDL_* names, {len(with_sig)} with argtypes")
if len(with_sig) < 200:                      # core binary did not bind: show what pysdl3 did so the cause is visible
    import inspect
    for n in ("SDL_Init", "SDL_GetPrefPath", "SDL_CreateWindow"):
        f = getattr(sdl3, n, None)
        print(f"[diag] {n}: {type(f).__name__} attrs={[a for a in dir(f) if not a.startswith('__')][:8]}")
        try: print("[diag]   source:", inspect.getsource(f).strip().replace(chr(10), ' | ')[:300])
        except Exception as ex: print("[diag]   no source:", ex)
    print("[diag] binaries:", {k: type(v).__name__ for k, v in getattr(sdl3, "binaryMap", {}).items()})
    print("[diag] core binary:", getattr(sdl3, "SDL_BINARY", None))
# Newer pysdl3 wraps every function in a plain Python def that calls `raw.SDL_Xxx(...)`; the ctypes function pointers with
# real argtypes/restype live on that `raw` object. Older pysdl3 put argtypes on the functions themselves.
raw = getattr(sdl3, "raw", None)
if raw is None:
    try: raw = sdl3.SDL_Init.__globals__.get("raw")
    except Exception: raw = None
print("[diag] signature source:", "pysdl3 raw ctypes functions" if raw is not None else "pysdl3 function attributes")
import re
VARIADIC = re.compile(r"^SDL_(Log(Trace|Verbose|Debug|Info|Warn|Error|Critical|Message)?|SetError|RenderDebugTextFormat|a?s?n?printf|sscanf)$")
sigs = {}
for n in names:
    if VARIADIC.match(n): continue
    f = getattr(raw, n, None) if raw is not None else getattr(sdl3, n, None)
    if f is None or getattr(f, "argtypes", None) is None: continue
    if getattr(f, "vararg", False): continue
    try: sigs[n] = (kind(f.restype), [kind(a) for a in f.argtypes])
    except Exception: pass
bad = {n for n, (r, a) in sigs.items() if any(k[0] in ("?", "st") for k in [r] + a)}
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sdl3sigs.py")
open(out, "w").write("# generated from pysdl3 (exact argtypes/restype). kind = (letter, size[, callback sig])\nSIGS = " +
                     repr({n: v for n, v in sigs.items() if n not in bad}) + "\nUNSUPPORTED = " + repr(sorted(bad)) + "\n")
print(f"{len(sigs)} functions; {len(bad)} unsupported (struct by value) -> wrote {out}")
