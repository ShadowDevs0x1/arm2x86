"""
Identity spoofing: what the guest is told about the OS and the machine.

  default      : report the HOST's macOS version (and Darwin release / build) when the host is macOS 26.0 or newer;
                 on an older host report macOS 26.0 (Darwin 25.0.0, build 25A354) so version gates written for 26+ pass.
  --kern26     : report macOS 27.0 (Darwin 27.0.0, xnu-13432.1.9~1) on an Apple M5 (Mac17,2). (env: ARM2X86_KERN26=1)
  always       : hw.memsize is the HOST's RAM; sysctl.proc_translated is 0 (we are not "Rosetta").
  overrides    : ARM2X86_SPOOF_BUILD, ARM2X86_SPOOF_MODEL, ARM2X86_SPOOF_CHIP    ARM2X86_SPOOFTRACE=1 logs every hit.

The guest sees the lie through every route a compatibility check can use:
  sysctl / sysctlbyname (kern.osproductversion, kern.osrelease, kern.osversion, kern.version, hw.model, hw.memsize,
  machdep.cpu.brand_string, ...), uname(), open/fopen of /System/Library/CoreServices/SystemVersion.plist (served from a
  generated copy), the private _CFCopySystemVersionDictionary, and -[NSProcessInfo operatingSystemVersion /
  operatingSystemVersionString / isOperatingSystemAtLeastVersion:] (ObjC calls that would otherwise reach the real host).
Not covered: IOKit registry reads (board-id, model via IORegistry), SystemProfiler, Gestalt, host-side private frameworks that
read the real kernel themselves. Run with ARM2X86_SPOOFTRACE=1 to see which route a given app actually uses.
"""
import os, sys, struct, subprocess, plistlib, ctypes
import hle
from hle import FUNCS, M64
from unicorn.arm64_const import *

TRACE = bool(os.environ.get("ARM2X86_SPOOFTRACE"))
_P = {}
# exact `uname -v` of a real macOS 27 build (from a screenshot supplied by the user)
KVERSION_27 = "Darwin Kernel Version 27.0.0: Tue Aug 11 21:02:16 PDT 2026; root:xnu-13432.1.9~1/RELEASE_ARM64_T8112"
FLOOR = ("26.0", "25A354", "25.0.0")                         # macOS 26.0 release: version, build, Darwin
SYSVER_PATHS = {"/System/Library/CoreServices/SystemVersion.plist",
                "/System/Library/CoreServices/ServerVersion.plist",
                "/System/Library/CoreServices/.SystemVersionPlatform.plist"}

def _vt(s):                                                  # "26.0.1" -> (26, 0, 1)
    p = [int(x) for x in s.split(".") if x.isdigit()][:3]; return tuple(p + [0] * (3 - len(p)))

def host_memsize():
    try:
        v = ctypes.c_uint64(0); n = ctypes.c_size_t(8)
        if ctypes.CDLL(None).sysctlbyname(b"hw.memsize", ctypes.byref(v), ctypes.byref(n), None, 0) == 0 and v.value: return v.value
    except Exception: pass
    try: return os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError, AttributeError): return 8 << 30

def _host_macos():
    if sys.platform != "darwin": return None, None
    env = {**os.environ, "SYSTEM_VERSION_COMPAT": "0"}
    try:
        v = subprocess.check_output(["/usr/bin/sw_vers", "-productVersion"], env=env, text=True, timeout=5).strip()
        b = subprocess.check_output(["/usr/bin/sw_vers", "-buildVersion"], env=env, text=True, timeout=5).strip()
        return v, b
    except Exception: return None, None

def profile():
    """computed lazily (the loader sets ARM2X86_KERN26 from --kern26 before the first use)"""
    if _P: return _P
    k26 = os.environ.get("ARM2X86_KERN26") == "1"
    hv, hb = _host_macos()
    drel = os.uname().release if sys.platform == "darwin" else ""
    if k26:
        ver, build, darwin, model, chip = "27.0", "26A5000a", "27.0.0", "Mac17,2", "Apple M5"
        mode = "--kern26"
    elif hv and _vt(hv) >= (26, 0, 0):
        ver, build, darwin, model, chip = hv, hb or FLOOR[1], drel or "25.0.0", None, None
        mode = "host version (>= 26.0)"
    else:
        ver, build, darwin, model, chip = FLOOR[0], FLOOR[1], FLOOR[2], None, None
        mode = "floor 26.0" + (f" (host is {hv})" if hv else " (host version unknown)")
    build = os.environ.get("ARM2X86_SPOOF_BUILD", build)
    model = os.environ.get("ARM2X86_SPOOF_MODEL", model)
    chip = os.environ.get("ARM2X86_SPOOF_CHIP", chip)
    t = _vt(ver); mem = host_memsize()
    _P.update(ver=ver, vt=t, build=build, darwin=darwin, model=model, chip=chip, mem=mem, kern26=k26, mode=mode,
              kversion=os.environ.get("ARM2X86_SPOOF_KVERSION") or (
                  KVERSION_27 if k26 else f"Darwin Kernel Version {darwin}: Mon Jan  5 00:00:00 PST 2026; root:xnu-spoof/RELEASE_ARM64_T8142"))
    sys.stderr.write(f"[spoof] macOS {ver} (build {build}, Darwin {darwin}) [{mode}]"
                     + (f", {chip} {model}" if chip else "") + f", RAM {mem >> 20} MB\n")
    return _P
def _t(msg):
    if TRACE: sys.stderr.write(f"[spoof] {msg}\n")

# ------------------------------------------------------------------------------------------------ sysctl / uname
def sysctl_override(name):
    p = profile()
    v = {"kern.osproductversion": p["ver"], "kern.osproductversionextra": b"", "kern.osrelease": p["darwin"],
         "kern.osversion": p["build"], "kern.version": p["kversion"].encode(),
         "hw.memsize": p["mem"], "hw.memsize_usable": p["mem"], "sysctl.proc_translated": 0}.get(name)
    if v is None and p["model"]:
        v = {"hw.model": p["model"].encode(), "hw.targettype": b"J700", "machdep.cpu.brand_string": p["chip"].encode()}.get(name)
    if v is not None: _t(f"sysctl {name} -> {v!r}")
    return v

_MIB = {(6, 1): "hw.machine", (6, 2): "hw.model", (6, 3): "hw.ncpu", (6, 7): "hw.pagesize", (6, 24): "hw.memsize",
        (6, 25): "hw.ncpu", (6, 5): "hw.memsize", (6, 6): "hw.memsize",
        (1, 1): "kern.ostype", (1, 2): "kern.osrelease", (1, 4): "kern.version", (1, 10): "kern.hostname", (1, 65): "kern.osversion"}
def mib_name(mib):
    """numeric sysctl() MIB -> name (None if unknown). Darwin: CTL_KERN=1, CTL_HW=6."""
    return _MIB.get(tuple(mib)[:2]) if len(mib) >= 2 else None

def uname_fields():
    p = profile(); return ("Darwin", os.uname().nodename if hasattr(os, "uname") else "localhost", p["darwin"], p["kversion"], "arm64")

# ------------------------------------------------------------------------------------------------ SystemVersion.plist
def version_dict():
    p = profile(); ios = p["ver"] if p["vt"][0] >= 26 else f"{p['vt'][0] + 3}.{p['vt'][1]}"
    return {"ProductBuildVersion": p["build"], "ProductCopyright": "1983-2026 Apple Inc.", "ProductName": "macOS",
            "ProductUserVisibleVersion": p["ver"], "ProductVersion": p["ver"], "iOSSupportVersion": ios}
_PLIST = {}
def map_path(path):
    """open()/fopen() of the OS version plist is served from a generated copy; everything else is untouched."""
    if path not in SYSVER_PATHS: return path
    if "f" not in _PLIST:
        d = os.path.join(os.environ.get("TMPDIR", "/tmp"), "arm2x86-spoof"); os.makedirs(d, exist_ok=True)
        f = os.path.join(d, "SystemVersion.plist")
        with open(f, "wb") as fh: fh.write(plistlib.dumps(version_dict(), fmt=plistlib.FMT_XML))
        _PLIST["f"] = f
    _t(f"open {path} -> {_PLIST['f']}"); return _PLIST["f"]

# ------------------------------------------------------------------------------------------------ ObjC (host) side
SELS = {"operatingSystemVersion", "operatingSystemVersionString", "isOperatingSystemAtLeastVersion:"}
def is_at_least(want):
    return profile()["vt"] >= tuple(want)
def _objc():
    import objc; return objc
def _nsstring(s):
    o = _objc(); h = o.host()["objc"]
    return o.hmsg(h.objc_getClass(b"NSString"), "stringWithUTF8String:", s.encode() + b"\0", argtypes=[ctypes.c_char_p])
_LIB = {}
def _class_name(obj):
    if "o" not in _LIB:
        l = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
        l.object_getClass.restype, l.object_getClass.argtypes = ctypes.c_void_p, [ctypes.c_void_p]
        l.class_getName.restype, l.class_getName.argtypes = ctypes.c_char_p, [ctypes.c_void_p]
        _LIB["o"] = l
    return (_LIB["o"].class_getName(_LIB["o"].object_getClass(obj)) or b"").decode()
def on_msg(e, self_, selname):
    """Hook called by objc.msg_send for SELS; True = handled (result already in registers)."""
    o = _objc()
    if not o.DARWIN or o.is_guest(e, self_) or not _class_name(self_).endswith("ProcessInfo"): return False
    p = profile(); uc = e.uc
    if selname == "operatingSystemVersion":                  # NSOperatingSystemVersion {q,q,q}: 24 bytes -> returned via x8
        e.write(uc.reg_read(UC_ARM64_REG_X8), struct.pack("<qqq", *p["vt"])); _t(f"-[NSProcessInfo {selname}] -> {p['vt']}"); return True
    if selname == "operatingSystemVersionString":
        uc.reg_write(UC_ARM64_REG_X0, _nsstring(f"Version {p['ver']} (Build {p['build']})") & M64); _t(f"-[NSProcessInfo {selname}]"); return True
    if selname == "isOperatingSystemAtLeastVersion:":        # struct by reference in x2
        want = struct.unpack("<qqq", bytes(e.read(e.arg(2), 24))); r = int(is_at_least(want))
        uc.reg_write(UC_ARM64_REG_X0, r); _t(f"-[NSProcessInfo isOperatingSystemAtLeastVersion:{want}] -> {r}"); return True
    return False

def fix_args(selname, arg_ts, conv):
    """NSString path args naming SystemVersion.plist (dictionaryWithContentsOfFile:, fileURLWithPath:, ...) -> generated copy."""
    if not ("File" in selname or "Path" in selname or "URL" in selname): return conv
    o = _objc()
    if not o.DARWIN: return conv
    out = list(conv)
    for i, (t, v) in enumerate(zip(arg_ts, conv)):
        if t != "@" or not v: continue
        try:
            if not o.hmsg(v, "isKindOfClass:", o.host()["objc"].objc_getClass(b"NSString"), restype=ctypes.c_ubyte): continue
            s = ctypes.string_at(o.hmsg(v, "UTF8String"))
        except Exception: continue
        if s.decode("utf8", "replace") in SYSVER_PATHS: out[i] = _nsstring(map_path(s.decode())); _t(f"{selname}: path arg redirected")
    return out

def _cf_copy_system_version_dictionary(e):
    o = _objc()
    if not o.DARWIN: return 0
    h = o.host()["objc"]; d = o.hmsg(o.hmsg(h.objc_getClass(b"NSMutableDictionary"), "alloc"), "init")
    for k, v in version_dict().items(): o.hmsg(d, "setObject:forKey:", _nsstring(v), _nsstring(k))
    _t("_CFCopySystemVersionDictionary -> spoofed dictionary"); return d
FUNCS["__CFCopySystemVersionDictionary"] = _cf_copy_system_version_dictionary


# ------------------------------------------------------------------------------------------------ missing classes / alerts
# A class the guest links but nobody can load (e.g. a private framework class) used to be "nil": every BOOL check on it
# answered NO, which is exactly how an "is this OS supported?" gate fails closed. Now every message is LOGGED and BOOL-looking
# selectors get a permissive answer.  Overrides: ARM2X86_MISSING_YES=sel1,sel2   ARM2X86_MISSING_NO=sel3
_NEG = ("unsupported", "notsupported", "blocked", "fail", "error", "old", "incompatible", "denied", "restricted", "required",
        "needs", "beta", "expired", "invalid", "disabled", "unavailable", "tooold", "tooNew".lower(), "prohibit", "forbid")
_BOOLISH = ("is", "has", "supports", "can", "should", "does", "check", "meets", "allows", "will")
# selectors known to be "is this machine OK?" gates in Apple installers -> always pass (checked before everything else)
_ALWAYS_YES = {"processMeetsHardenedPlatformEnforcement", "meetsHardenedPlatformEnforcement",
               "isPlatformSupported", "isSupportedPlatform", "isCompatible"}
# camelCase fragments that mark a selector as BOOL-looking even when it does not START with a _BOOLISH word
_BOOL_INFIX = ("Meets", "Enforcement", "Supported", "Compatible", "Allowed")
_SEEN = set()
def guess_bool(sel):
    """BOOL answer for a selector sent to a missing class; None = not a BOOL-looking selector (answer nil/0)."""
    base = sel.split(":")[0]; low = base.lower()
    yes = {x for x in os.environ.get("ARM2X86_MISSING_YES", "").split(",") if x}; no = {x for x in os.environ.get("ARM2X86_MISSING_NO", "").split(",") if x}
    if sel in yes or base in yes: return 1
    if sel in no or base in no: return 0
    if base in _ALWAYS_YES: return 1
    boolish = any(low.startswith(b) and (len(low) == len(b) or base[len(b)].isupper()) for b in _BOOLISH) \
              or any(x in base for x in _BOOL_INFIX)
    if not boolish: return None
    if any(n in low for n in _NEG): return 0
    if low.startswith("should"): return 1 if any(k in low for k in ("continue", "allow", "proceed")) else 0
    return 1
def missing_class_msg(e, cls, selname):
    v = guess_bool(selname)
    if (cls, selname) not in _SEEN:
        _SEEN.add((cls, selname))
        sys.stderr.write(f"[spoof] message to missing class: +[{cls} {selname}] -> {'YES' if v else 'NO/nil'}"
                         f"{' (guessed from the name)' if v is not None else ''}\n")
    e.uc.reg_write(UC_ARM64_REG_X0, 1 if v else 0)

_ALERT_PHRASES = ("cannot be used from the version of macos", "cannot be used on this", "is too old to install", "not compatible")
def note_alert(e, selname):
    """-[NSAlert setMessageText:/setInformativeText:] -- when it is a compatibility alert, say so and dump what led to it."""
    o = _objc(); v = e.arg(2)
    try:
        if not v: return
        if o.is_guest(e, v): v = o.to_nsstring(e, v) if o.read_isa_is_cf(e, v) else 0
        if not v: return
        txt = ctypes.string_at(o.hmsg(v, "UTF8String")).decode("utf8", "replace")
    except Exception: return
    if any(p in txt.lower() for p in _ALERT_PHRASES):
        sys.stderr.write(f"[spoof] >>> compatibility alert is being built ({selname}): {txt!r}\n"
                         f"[spoof] >>> guest caller lr={e.uc.reg_read(UC_ARM64_REG_LR):#x}; the messages that led here:\n")
        o.dump_ring(e, "compatibility alert")
