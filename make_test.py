#!/usr/bin/env python3
"""Builds a tiny static arm64 Mach-O that prints a line and exits 7."""
import struct
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

MSG = b"hello from arm64 on x86_64\n"
asm = f"""
    mov x0, #1
    adr x1, msg
    mov x2, #{len(MSG)}
    mov x16, #4
    svc #0x80
    mov x0, #7
    mov x16, #1
    svc #0x80
msg:
"""
code = bytes(Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN).asm(asm)[0]) + MSG

TEXT_VM, CODE_OFF, FILE_SIZE = 0x100000000, 0x400, 0x4000
pagezero = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__PAGEZERO", 0, 0x100000000, 0, 0, 0, 0, 0, 0)
text     = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__TEXT", TEXT_VM, FILE_SIZE, 0, FILE_SIZE, 5, 5, 0, 0)
main     = struct.pack("<IIQQ", 0x80000028, 24, CODE_OFF, 0)
cmds = pagezero + text + main
hdr = struct.pack("<IiiIIIII", 0xfeedfacf, 0x0100000c, 0, 2, 3, len(cmds), 0, 0)
blob = (hdr + cmds).ljust(CODE_OFF, b"\0") + code
open("hello_arm64", "wb").write(blob.ljust(FILE_SIZE, b"\0"))
print("wrote hello_arm64")
