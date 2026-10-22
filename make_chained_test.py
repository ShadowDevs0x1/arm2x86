#!/usr/bin/env python3
"""
Builds a synthetic arm64/arm64e Mach-O that uses LC_DYLD_CHAINED_FIXUPS (what
Xcode emits) to exercise the loader's fixup code. Usage:
    make_chained_test.py <fmt> <out>      fmt: 2 (PTR_64) | 6 (PTR_64_OFFSET) | 9 (ARM64E_USERLAND, uses PAC insns)
"""
import struct, sys

fmt, out = int(sys.argv[1]), sys.argv[2]
arm64e = fmt == 9
BASE, DATA_VM, CODE_OFF = 0x100000000, 0x100004000, 0x400
M1, M2 = b"chained fixup bind ok\0", b"chained fixup rebase ok\0"

def adr(rd, pc, target):
    imm = target - pc
    assert -(1 << 20) <= imm < (1 << 20)
    imm &= (1 << 21) - 1
    return 0x10000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | rd

if arm64e: PRO, BLR, RET = 0xd503237f, 0xd63f0920, 0xd65f0fff   # pacibsp / blraaz x9 / retab
else:      PRO, BLR, RET = 0xd503201f, 0xd63f0120, 0xd65f03c0   # nop / blr x9 / ret
NINS = 14
msg1_off = CODE_OFF + NINS * 4
def at(i): return BASE + CODE_OFF + 4 * i                     # address of instruction i
words = [
    PRO, 0xa9bf7bfd,                                          # [pacibsp] stp x29,x30,[sp,#-16]!
    adr(0, at(2), BASE + msg1_off),                           # x0 = msg1
    adr(9, at(3), DATA_VM), 0xf9400129,                       # x9 = *(slot0)  (bound puts)
    BLR,                                                      # puts(msg1)
    adr(10, at(6), DATA_VM + 8), 0xf9400140,                  # x0 = *(slot1) (rebased ptr to msg2)
    adr(9, at(8), DATA_VM), 0xf9400129,
    BLR,                                                      # puts(msg2)
    0xd2800120, 0xa8c17bfd, RET,                              # mov x0,#9 ; ldp ; [retab] ret
]
assert len(words) == NINS
code = b"".join(struct.pack("<I", w) for w in words)
M1 = M1; msg2_off = msg1_off + len(M1)
code += M1 + M2

# ---- chained fixups blob ---------------------------------------------------
stride = 8 if fmt == 9 else 4
nxt = 8 // stride
if fmt in (2, 6):
    bind    = (1 << 63) | (nxt << 51) | 0                       # ordinal 0, addend 0
    rebase  = (BASE + msg2_off) if fmt == 2 else msg2_off       # vmaddr vs offset
else:
    bind    = (1 << 63) | (1 << 62) | (nxt << 51) | 0           # auth + bind, ordinal 0
    rebase  = (1 << 63) | msg2_off                              # auth rebase, 32-bit offset target
starts_in_seg = struct.pack("<IHHQIH", 24, 0x4000, fmt, 0x4000, 0, 1) + struct.pack("<H", 0)
starts_in_img = struct.pack("<IIII", 3, 0, 0, 16)               # 3 segs; only __DATA has fixups
symbols = b"\0_puts\0"
imports = struct.pack("<I", 1 | (1 << 9))                       # lib 1, name offset 1
hdr_len, sii, sis = 28, 16, 24
imports_off = hdr_len + sii + sis
blob = struct.pack("<7I", 0, hdr_len, imports_off, imports_off + 4, 1, 1, 0) + starts_in_img + starts_in_seg + imports + symbols
blob = blob.ljust((len(blob) + 7) & ~7, b"\0")

# ---- Mach-O ----------------------------------------------------------------
def seg(name, vm, vmsize, fo, fsz, prot):
    return struct.pack("<II16sQQQQiiII", 0x19, 72, name, vm, vmsize, fo, fsz, prot, prot, 0, 0)
cmds  = seg(b"__PAGEZERO", 0, BASE, 0, 0, 0) + seg(b"__TEXT", BASE, 0x4000, 0, 0x4000, 5)
cmds += seg(b"__DATA", DATA_VM, 0x4000, 0x4000, 0x4000, 3)
cmds += struct.pack("<IIQQ", 0x80000028, 24, CODE_OFF, 0)
cmds += struct.pack("<IIII", 0x80000034, 16, 0x8000, len(blob))
hdr = struct.pack("<IiiIIIII", 0xfeedfacf, 0x0100000c, 2 if arm64e else 0, 2, 5, len(cmds), 0, 0)
text = (hdr + cmds).ljust(CODE_OFF, b"\0") + code
data = struct.pack("<QQ", bind, rebase)
open(out, "wb").write(text.ljust(0x4000, b"\0") + data.ljust(0x4000, b"\0") + blob)
print(f"wrote {out} (chained fixup format {fmt}{', arm64e' if arm64e else ''})")
