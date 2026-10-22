"""Linux-runnable tests for the marshalling logic (no host ObjC needed)."""
import sys, struct, ctypes; sys.path.insert(0, '.')
import objc
from unicorn import *; from unicorn.arm64_const import *
class FakeEmu:                       # real Unicorn memory + registers, so ArgReader/write_ret run for real
    def __init__(s):
        s.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM); s.uc.mem_map(0x10000, 0x10000); s.uc.mem_map(0x7000000, 0x10000)
        s.uc.reg_write(UC_ARM64_REG_SP, 0x7008000)
    def read(s, a, n): return s.uc.mem_read(a, n)
    def write(s, a, b): s.uc.mem_write(a, bytes(b))
    def sp(s): return s.uc.reg_read(UC_ARM64_REG_SP)
e = FakeEmu(); X = lambda i, v: e.uc.reg_write(UC_ARM64_REG_X0 + i, v); D = lambda i, v: e.uc.reg_write(UC_ARM64_REG_D0 + i, v)
d = lambda v: struct.unpack("<Q", struct.pack("<d", v))[0]

# 1) encoding parser: real Metal-style encodings
sig = objc.parse_sig("v48@0:8{MTLSize=QQQ}16{MTLSize=QQQ}40")
assert sig[0] == "v" and sig[1:3] == ["@", ":"] and sig[3][0] == "{" and len(sig[3][2]) == 3, sig
sig = objc.parse_sig("{CGRect={CGPoint=dd}{CGSize=dd}}16@0:8")
assert objc.hfa(sig[0]) == "d" and len(objc.leaves(sig[0])) == 4
assert objc.parse_sig("@40@0:8^{_NSZone=}16r*24^@32")[3:] == ["^", "*", "^@"]
assert objc.parse_sig("v24@0:8@?16") == ["v", "@", ":", "@?"]
print("parse ok")

# 2) scalar args: ints in x2.., double in d0, int past x7 goes on the stack
X(2, 0xdeadbeef); X(3, 7); D(0, d(2.5))
rd = objc.ArgReader(e); assert rd.read("Q") == 0xdeadbeef and rd.read("i") == 7 and rd.read("d") == 2.5
# 3) HFA struct (MTLClearColor-like: 4 doubles) comes from d0..d3
for i, v in enumerate((0.1, 0.2, 0.3, 1.0)): D(i, d(v))
t = objc.parse_sig("v@:{MTLClearColor=dddd}")[3]; c = objc.ArgReader(e).read(t)
assert (c.f0, c.f1, c.f2, c.f3) == (0.1, 0.2, 0.3, 1.0)
# 4) 16-byte struct (NSRange) from x2,x3; 24-byte struct (MTLSize) by pointer
X(2, 5); X(3, 9); r = objc.ArgReader(e).read(objc.parse_sig("v@:{_NSRange=QQ}")[3]); assert (r.f0, r.f1) == (5, 9)
e.write(0x10100, struct.pack("<QQQ", 64, 32, 1)); X(2, 0x10100)
m = objc.ArgReader(e).read(objc.parse_sig("v@:{MTLSize=QQQ}")[3]); assert (m.f0, m.f1, m.f2) == (64, 32, 1)
# 5) stack spill: 9th integer lands at [sp]
e.write(e.sp(), struct.pack("<Q", 1234))
for i in range(2, 8): X(i, i)
rd = objc.ArgReader(e)
for _ in range(6): rd.read("Q")
assert rd.read("Q") == 1234
# 6) return values: HFA -> d0..d3, 16B -> x0/x1, >16B -> memory at x8, float -> d0, int masked
cg = objc.parse_sig("{CGRect={CGPoint=dd}{CGSize=dd}}16@0:8")[0]; S = objc.ctype_of(cg)
objc.write_ret(e, cg, S.from_buffer_copy(struct.pack("<4d", 1, 2, 3, 4))); assert [struct.unpack("<d", struct.pack("<Q", e.uc.reg_read(UC_ARM64_REG_D0 + i)))[0] for i in range(4)] == [1, 2, 3, 4]
objc.write_ret(e, objc.parse_sig("{_NSRange=QQ}")[0], objc.ctype_of(objc.parse_sig("{_NSRange=QQ}")[0])(3, 4))
assert (e.uc.reg_read(UC_ARM64_REG_X0), e.uc.reg_read(UC_ARM64_REG_X1)) == (3, 4)
e.uc.reg_write(UC_ARM64_REG_X8, 0x10200); sz = objc.parse_sig("{MTLSize=QQQ}")[0]
objc.write_ret(e, sz, objc.ctype_of(sz)(7, 8, 9)); assert struct.unpack("<QQQ", bytes(e.read(0x10200, 24))) == (7, 8, 9)
objc.write_ret(e, "f", 1.5); assert e.uc.reg_read(UC_ARM64_REG_D0) == struct.unpack("<I", struct.pack("<f", 1.5))[0]
objc.write_ret(e, "i", -1); assert e.uc.reg_read(UC_ARM64_REG_X0) == 0xffffffff
print("marshalling ok")
# 7) sized-pointer rule for replaceRegion (MTLRegion = origin{3Q} size{3Q})
reg = objc.ctype_of(objc.parse_sig("{MTLRegion={MTLOrigin=QQQ}{MTLSize=QQQ}}")[0])
rr = reg(); rr.f1.f0, rr.f1.f1, rr.f1.f2 = 16, 8, 1
assert objc.SIZED["replaceRegion:mipmapLevel:withBytes:bytesPerRow:"][1]([rr, 0, 0, 64]) == 512
print("ALL OK")
