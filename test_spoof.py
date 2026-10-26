"""Spoof layer tests (Linux-runnable): profile modes, sysctl by name and by MIB, uname, SystemVersion.plist, %qu."""
import sys, os, struct, plistlib, importlib; sys.path.insert(0, '.')
from unicorn import *; from unicorn.arm64_const import *
def fresh(env):
    for k in ("ARM2X86_KERN26", "ARM2X86_SPOOF_BUILD", "ARM2X86_SPOOF_MODEL", "ARM2X86_SPOOF_CHIP"): os.environ.pop(k, None)
    os.environ.update(env)
    import spoof; spoof._P.clear(); spoof._PLIST.clear(); return spoof
import hle, hostsys
class E:
    def __init__(s): s.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM); s.uc.mem_map(0x10000, 0x100000); s.errno_addr = 0x10000; s.top = 0x80000
    def read(s, a, n): return bytes(s.uc.mem_read(a, n))
    def write(s, a, b): s.uc.mem_write(a, bytes(b))
    def arg(s, i): return s.uc.reg_read(UC_ARM64_REG_X0 + i)
    def cstr(s, p): return s.cstr_bytes(p).decode()
    def cstr_bytes(s, p):
        o = b""
        while s.read(p + len(o), 1) != b"\0": o += s.read(p + len(o), 1)
        return o
    def alloc_cstr(s, t): p = s.top; s.top += len(t) + 16; s.write(p, t.encode() + b"\0"); return p
e = E()
def regs(*v):
    for i, x in enumerate(v): e.uc.reg_write(UC_ARM64_REG_X0 + i, x)
def sysctlbyname(name, size=256):
    e.write(0x20000, b"\0" * 512); regs(e.alloc_cstr(name), 0x20000, 0x20100, 0, 0); e.write(0x20100, struct.pack("<Q", size))
    r = hle.FUNCS["_sysctlbyname"](e); n = struct.unpack("<Q", e.read(0x20100, 8))[0]; return r, e.read(0x20000, n)
def sysctl_mib(*mib):
    for i, m in enumerate(mib): e.write(0x30000 + 4 * i, struct.pack("<i", m))
    e.write(0x20000, b"\0" * 512); regs(0x30000, len(mib), 0x20000, 0x20100, 0, 0); e.write(0x20100, struct.pack("<Q", 256))
    r = hle.FUNCS["_sysctl"](e); n = struct.unpack("<Q", e.read(0x20100, 8))[0]; return r, e.read(0x20000, n)

# 1) --kern26: macOS 27 / Darwin 26 / Apple M5, RAM = host RAM
sp = fresh({"ARM2X86_KERN26": "1"}); p = sp.profile()
assert p["vt"] == (27, 0, 0) and p["darwin"] == "27.0.0" and p["chip"] == "Apple M5" and p["mem"] == sp.host_memsize() and p["mem"] > (64 << 20)
assert sysctlbyname("kern.osproductversion") == (0, b"27.0\0")
assert sysctlbyname("kern.osrelease") == (0, b"27.0.0\0")
assert sysctlbyname("kern.version", 512)[1] == sp.KVERSION_27.encode() + b"\0" and "xnu-13432.1.9~1/RELEASE_ARM64_T8112" in sp.KVERSION_27
assert sysctlbyname("machdep.cpu.brand_string") == (0, b"Apple M5\0") and sysctlbyname("hw.model")[1] == b"Mac17,2\0"
r, v = sysctlbyname("hw.memsize", 8); assert struct.unpack("<Q", v)[0] == sp.host_memsize()
r, v = sysctlbyname("sysctl.proc_translated", 4); assert r == 0 and struct.unpack("<I", v)[0] == 0
# 2) numeric MIBs: CTL_KERN(1)/KERN_OSRELEASE(2), KERN_OSVERSION(65), CTL_HW(6)/HW_MEMSIZE(24), HW_MODEL(2)
assert sysctl_mib(1, 2) == (0, b"27.0.0\0") and sysctl_mib(1, 65)[1] == sp.profile()["build"].encode() + b"\0"
assert struct.unpack("<Q", sysctl_mib(6, 24)[1][:8])[0] == sp.host_memsize() and sysctl_mib(6, 2)[1] == b"Mac17,2\0"
# 3) uname
regs(0x40000); hle.FUNCS["_uname"](e) if "_uname" in hle.FUNCS else __import__("extras2")
import extras2; regs(0x40000); extras2._uname(e)
rel = e.read(0x40000 + 512, 256).split(b"\0")[0]; mach = e.read(0x40000 + 1024, 256).split(b"\0")[0]
assert rel == b"27.0.0" and mach == b"arm64" and e.read(0x40000 + 768, 256).startswith(b"Darwin Kernel Version 27.0.0: Tue Aug 11")
# 4) SystemVersion.plist is served from a generated copy
f = sp.map_path("/System/Library/CoreServices/SystemVersion.plist"); d = plistlib.load(open(f, "rb"))
assert d["ProductVersion"] == "27.0" and d["ProductName"] == "macOS" and d["ProductBuildVersion"] == "26A5000a"
assert sp.map_path("/etc/hosts") == "/etc/hosts"
# 5) version-gate arithmetic (what -[NSProcessInfo isOperatingSystemAtLeastVersion:] answers)
assert sp.is_at_least((27, 0, 0)) and sp.is_at_least((26, 4, 1)) and not sp.is_at_least((27, 0, 1)) and not sp.is_at_least((28, 0, 0))
# 6) default mode: Linux host has no macOS version -> floor 26.0 / Darwin 25.0.0, no hardware spoof, host RAM still passed
sp = fresh({}); p = sp.profile()
assert p["ver"] == "26.0" and p["darwin"] == "25.0.0" and p["build"] == "25A354" and p["chip"] is None and p["mem"] == sp.host_memsize()
assert sysctlbyname("kern.osproductversion")[1] == b"26.0\0" and sp.is_at_least((26, 0, 0)) and not sp.is_at_least((27, 0, 0))
# 7) host >= 26 is reported as-is (simulate a macOS 26.1 host)
sp = fresh({}); sp._P.clear(); sp._host_macos = lambda: ("26.1.2", "25B77"); p = sp.profile()
assert p["ver"] == "26.1.2" and p["build"] == "25B77" and p["vt"] == (26, 1, 2)
# 8) host < 26 (macOS 15.4) is raised to the 26.0 floor
sp._P.clear(); sp._host_macos = lambda: ("15.4", "24E248"); p = sp.profile(); assert p["ver"] == "26.0" and "15.4" in p["mode"]
# 9) env overrides
sp = fresh({"ARM2X86_KERN26": "1", "ARM2X86_SPOOF_CHIP": "Apple M5 Pro", "ARM2X86_SPOOF_BUILD": "26A1234"}); p = sp.profile()
assert p["chip"] == "Apple M5 Pro" and p["build"] == "26A1234"
# 10) printf %qu (the "RAM: %qu MB" line)
import struct as S
class F:
    def __init__(s, vals): s.v = list(vals)
args = iter([8192]); out = hle.format_c(None, "%qu MB RAM, %qd, %llu", lambda: next(args), lambda: 0.0) if False else None
vals = iter([16384, (-5) & ((1 << 64) - 1), 7]); assert hle.format_c(None, "%qu MB RAM, %qd, %llu", lambda: next(vals), lambda: 0.0) == "16384 MB RAM, -5, 7"
# 11) missing-class BOOL heuristics
g = sp.guess_bool
assert g("isCompatible") == 1 and g("isSupportedOS") == 1 and g("supportsThisHardware:") == 1 and g("canInstall") == 1
assert g("isUnsupportedOS") == 0 and g("isBlocked") == 0 and g("hasFailed") == 0 and g("shouldBlock") == 0 and g("shouldContinue") == 1
assert g("sharedInstance") is None and g("island") is None and g("hashValue") is None
os.environ["ARM2X86_MISSING_NO"] = "isCompatible"; assert g("isCompatible") == 0; os.environ["ARM2X86_MISSING_YES"] = "isBlocked"; assert g("isBlocked") == 1
os.environ.pop("ARM2X86_MISSING_NO"); os.environ.pop("ARM2X86_MISSING_YES")
print("spoof ALL OK")
