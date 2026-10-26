#!/usr/bin/env python3
"""
arm2x86 milestone 2: run a simple arm64 / arm64e macOS command-line Mach-O on an
x86_64 host. Pipeline:  parse Mach-O -> map segments -> apply dyld fixups
(chained fixups AND classic rebase/bind opcodes) -> bind every libSystem import
to a Python stub (hle.py) -> build argc/argv -> execute main() under Unicorn.

usage: python3 loader.py <mach-o> [args...]
"""
import struct, sys, os, faulthandler
faulthandler.enable()          # host-side segfaults now print the Python stack
from unicorn import *
from unicorn.arm64_const import *
import hle, spoof, libcxx, hostsys, objc, cocoa, vk, gfx, extras, extras2, cxxio, cxxstr, sdl3bridge, extras3, dylib   # each one registers into hle.FUNCS / RESOLVERS

MH_MAGIC_64, FAT_MAGIC, CPU_ARM64 = 0xfeedfacf, 0xcafebabe, 0x0100000c
LC_SEGMENT_64, LC_UNIXTHREAD, LC_MAIN = 0x19, 0x5, 0x80000028
LC_DYLD_INFO, LC_DYLD_INFO_ONLY, LC_DYLD_CHAINED_FIXUPS = 0x22, 0x80000022, 0x80000034

STUB_BASE, STUB_SIZE, STUB_STRIDE = 0x300000000, 0x100000, 16
DATA_BASE, DATA_SIZE = 0x310000000, 0x100000
HEAP_BASE, HEAP_SIZE = 0x400000000, 0x20000000
STACK_TOP, STACK_SIZE = 0x7ff000000000, 0x800000
THREAD_BASE, THREAD_STACK = 0x7f0000000000, 0x100000
M64 = (1 << 64) - 1

def cstr_at(d, p):
    return d[p:d.index(b"\0", p)].decode("latin-1")
def uleb(d, p):
    r = s = 0
    while True:
        b = d[p]; p += 1; r |= (b & 0x7f) << s; s += 7
        if not b & 0x80: return r, p
def sleb(d, p):
    r = s = 0
    while True:
        b = d[p]; p += 1; r |= (b & 0x7f) << s; s += 7
        if not b & 0x80:
            if b & 0x40: r -= 1 << s
            return r, p

def read_arm64_slice(data):
    if struct.unpack(">I", data[:4])[0] == FAT_MAGIC:
        for i in range(struct.unpack(">I", data[4:8])[0]):
            ct, _, off, size, _ = struct.unpack(">iiIII", data[8 + i*20: 28 + i*20])
            if ct & 0xffffffff == CPU_ARM64: return data[off: off + size]
        sys.exit("no arm64/arm64e slice in this fat binary")
    return data

class Macho:
    def __init__(self, data):
        magic, cputype, subtype, self.filetype, ncmds = struct.unpack("<IiiII", data[:20])
        if magic != MH_MAGIC_64 or cputype & 0xffffffff != CPU_ARM64:
            sys.exit("not an arm64 Mach-O")
        self.data, self.arm64e = data, (subtype & 0xff) == 2
        self.segs, self.sections = [], []
        self.entry_off, self.thread_pc = None, None
        self.chained = self.dyld_info = None
        off = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack("<II", data[off:off+8])
            if cmd == LC_SEGMENT_64:
                name = data[off+8:off+24].split(b"\0")[0].decode()
                vm, vmsz, fo, fsz = struct.unpack("<QQQQ", data[off+24:off+56])
                self.segs.append(dict(name=name, vm=vm, vmsize=vmsz, fileoff=fo, filesize=fsz))
                nsects = struct.unpack_from("<I", data, off + 64)[0]
                so = off + 72
                for _s in range(nsects):
                    sn = data[so:so+16].split(b"\0")[0].decode("latin-1")
                    sgn = data[so+16:so+32].split(b"\0")[0].decode("latin-1")
                    addr, sz = struct.unpack_from("<QQ", data, so + 32)
                    self.sections.append(dict(sect=sn, seg=sgn, addr=addr, size=sz))
                    so += 80
            elif cmd == LC_MAIN:   self.entry_off = struct.unpack("<Q", data[off+8:off+16])[0]
            elif cmd == LC_UNIXTHREAD:
                self.thread_pc = struct.unpack("<33Q", data[off+16: off+16+264])[32]
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                self.chained = struct.unpack("<II", data[off+8:off+16])
            elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
                self.dyld_info = struct.unpack("<10I", data[off+8:off+48])
            off += size
        text = next(s for s in self.segs if s["name"] == "__TEXT")
        self.base = text["vm"]
        self.entry = self.base + self.entry_off if self.entry_off is not None else self.thread_pc

class Emu:
    def __init__(self, path, argv):
        self.mo = Macho(read_arm64_slice(open(path, "rb").read()))
        self.path, self.argv = os.path.abspath(path), [path] + argv
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM64_MAX)   # ARMv8.x extensions Apple compilers emit (SHA3 EOR3, LSE atomics, ...)
        self.exit_code = None
        self.stubs, self.stub_names = {}, []      # name -> addr
        self.cells, self.next_cell = {}, DATA_BASE
        self.heap_ptr, self.heap_sizes = HEAP_BASE, {}
        self.missing = []
        self.cb_frames = []
        self.trace = bool(os.environ.get('ARM2X86_TRACE'))
        self.warned, self.atexits = set(), []
        self.threads = {1: {"state": "run", "ctx": None, "wait": None}}
        self.current_tid = 1
        self._sched = False
        self._blocks = 0
        self._resolved = {}
        self.stop_app = False
        self.n_runnable = self._n_runnable

    # ------------------------------------------------ guest memory helpers --
    def read(self, a, n): return self.uc.mem_read(a, n)
    def write(self, a, b): self.uc.mem_write(a, bytes(b))
    def cstr_bytes(self, a):
        out = bytearray()
        while True:
            c = self.uc.mem_read(a + len(out), 1)[0]
            if c == 0: return bytes(out)
            out.append(c)
    def cstr(self, a): return self.cstr_bytes(a).decode("latin-1")
    def sp(self): return self.uc.reg_read(UC_ARM64_REG_SP)
    def arg(self, i): return self.uc.reg_read(UC_ARM64_REG_X0 + i)
    def darg(self, i):
        return struct.unpack("<d", struct.pack("<Q", self.uc.reg_read(UC_ARM64_REG_D0 + i) & M64))[0]
    def ret_double(self, v):
        self.uc.reg_write(UC_ARM64_REG_D0, struct.unpack("<Q", struct.pack("<d", v))[0])
    def exit(self, code): self.exit_code = code; self.uc.emu_stop()
    def malloc(self, n):
        n = max(n, 1); p = self.heap_ptr; self.heap_ptr = (p + n + 15) & ~15
        if self.heap_ptr > HEAP_BASE + HEAP_SIZE: sys.exit("guest heap exhausted")
        self.heap_sizes[p] = n; return p
    def alloc_cstr(self, s):
        b = s.encode("latin-1", "replace") + b"\0"; p = self.malloc(len(b)); self.write(p, b); return p

    # ------------------------------------------------------ symbol binding --
    def resolve(self, name):
        if name == "__mh_execute_header" or name == "_mh_execute_header": return self.mo.base
        if name in self._resolved: return self._resolved[name]
        for r in hle.RESOLVERS:
            try: a = r(self, name)
            except Exception as ex:
                sys.stderr.write(f"[resolve] {name}: {ex}\n"); a = None
            if a:
                self._resolved[name] = a
                return a
        if name in hle.DATA:
            if name not in self.cells:
                self.cells[name] = self.next_cell
                v = hle.DATA[name]; self.write(self.next_cell, (v if isinstance(v, int) else v(self)).to_bytes(8, "little"))
                self.next_cell += 8
            self._resolved[name] = self.cells[name]
            return self.cells[name]
        if name not in self.stubs:
            idx = len(self.stub_names); self.stub_names.append(name)
            self.stubs[name] = STUB_BASE + idx * STUB_STRIDE
            self.write(self.stubs[name], struct.pack("<I", 0xd65f03c0))   # ret
            if name not in hle.FUNCS: self.missing.append(name)
        self._resolved[name] = self.stubs[name]
        return self.stubs[name]

    # ------------------------------------------------------------- loading --
    def load(self):
        uc, mo = self.uc, self.mo
        for s in mo.segs:
            if s["name"] == "__PAGEZERO" or s["vmsize"] == 0: continue
            base, end = s["vm"] & ~0xfff, (s["vm"] + s["vmsize"] + 0xfff) & ~0xfff
            try: uc.mem_map(base, end - base)
            except UcError: pass
            self.write(s["vm"], mo.data[s["fileoff"]: s["fileoff"] + s["filesize"]])
        for base, size in ((STUB_BASE, STUB_SIZE), (DATA_BASE, DATA_SIZE), (HEAP_BASE, HEAP_SIZE),
                           (STACK_TOP - STACK_SIZE, STACK_SIZE)):
            uc.mem_map(base, size)
        self.errno_addr = self.malloc(8)
        uc.reg_write(UC_ARM64_REG_CPACR_EL1, uc.reg_read(UC_ARM64_REG_CPACR_EL1) | (3 << 20))
        self.dylib_inits = dylib.load_bundled(self)           # the app's own arm64 dylibs (libfreetype) run inside the guest
        if mo.chained: self.apply_chained(*mo.chained)
        elif mo.dyld_info: self.apply_classic(mo.dyld_info)
        self.exit_stub = self.resolve("_exit")
        self.cont_stub = self.resolve("__arm2x86_cont")
        self.init_cont = self.resolve("__arm2x86_init_cont")
        self.thread_exit_stub = self.resolve("__arm2x86_thread_exit")
        objc.scan(self)
        cocoa.install(self)

    # --------------------------------------------- chained fixups (Xcode) ---
    def apply_chained(self, off, size):
        d, mo = self.mo.data, self.mo
        ver, starts_off, imp_off, sym_off, n, ifmt, _ = struct.unpack_from("<7I", d, off)
        imports = []
        for i in range(n):
            if ifmt == 1:   v, ad = struct.unpack_from("<Ii", d, off + imp_off + 4*i)[0], 0; no = v >> 9
            elif ifmt == 2: v, ad = struct.unpack_from("<Ii", d, off + imp_off + 8*i); no = v >> 9
            else:           v, ad = struct.unpack_from("<Qq", d, off + imp_off + 16*i); no = v >> 32
            if ifmt == 1: ad = 0
            imports.append((cstr_at(d, off + sym_off + no), ad))
        sb = off + starts_off
        segcount = struct.unpack_from("<I", d, sb)[0]
        for si in range(segcount):
            so = struct.unpack_from("<I", d, sb + 4 + 4*si)[0]
            if so == 0: continue
            q = sb + so
            _, psize, fmt, segoff, _, pcount = struct.unpack_from("<IHHQIH", d, q)
            pstarts = struct.unpack_from(f"<{pcount}H", d, q + 22)
            for pi, ps in enumerate(pstarts):
                if ps == 0xffff: continue
                if ps & 0x8000: print(f"[fixups] multi-start page unsupported (seg {si})", file=sys.stderr); continue
                a = mo.base + segoff + pi * psize + ps
                while True:
                    raw = int.from_bytes(self.read(a, 8), "little")
                    val, nxt, stride = self.decode_ptr(fmt, raw, imports)
                    self.write(a, (val & M64).to_bytes(8, "little"))
                    if nxt == 0: break
                    a += nxt * stride

    def decode_ptr(self, fmt, raw, imports):
        base = self.mo.base
        sx = lambda v, bits: v - (1 << bits) if v >> (bits - 1) else v
        if fmt in (2, 6):                                   # DYLD_CHAINED_PTR_64 / _64_OFFSET
            nxt = (raw >> 51) & 0xfff
            if raw >> 63:
                name, ad = imports[raw & 0xffffff]
                return self.resolve(name) + ad + ((raw >> 24) & 0xff), nxt, 4
            t = (raw & 0xfffffffff) | (((raw >> 36) & 0xff) << 56)
            return (t + base if fmt == 6 else t), nxt, 4
        if fmt in (1, 9, 12):                               # arm64e: PAC bits are stripped
            nxt, auth, bind = (raw >> 51) & 0x7ff, raw >> 63, (raw >> 62) & 1
            offset_fmt = fmt in (9, 12)
            if bind:
                if fmt == 12: ordi, ad = raw & 0xffffff, (0 if auth else sx((raw >> 32) & 0x7ffff, 19))
                else:         ordi, ad = raw & 0xffff,   (0 if auth else sx((raw >> 32) & 0x7ffff, 19))
                name, iad = imports[ordi]
                return self.resolve(name) + iad + ad, nxt, 8
            if auth: t = raw & 0xffffffff; return t + base, nxt, 8      # auth target is always an offset
            t = (raw & 0x7ffffffffff) | (((raw >> 43) & 0xff) << 56)
            return (t + base if offset_fmt else t), nxt, 8
        sys.exit(f"unsupported chained pointer format {fmt}")

    # ----------------------------------------- classic rebase/bind opcodes --
    def apply_classic(self, info):
        d = self.mo.data
        _, _, bo, bs, _, _, lo, ls, _, _ = info
        # rebases are no-ops: we load at the preferred base address (slide = 0)
        for off, size, lazy in ((bo, bs, False), (lo, ls, True)):
            if size: self.run_bind(d, off, size, lazy)

    def run_bind(self, d, p, size, lazy):
        end, sym, addend, seg, soff = p + size, None, 0, 0, 0
        def do_bind():
            a = self.mo.segs[seg]["vm"] + soff
            self.write(a, ((self.resolve(sym) + addend) & M64).to_bytes(8, "little"))
        while p < end:
            b = d[p]; p += 1; op, imm = b & 0xf0, b & 0x0f
            if op == 0x00:
                if lazy: continue
                break
            elif op == 0x10: pass
            elif op == 0x20: _, p = uleb(d, p)
            elif op == 0x30: pass
            elif op == 0x40: sym = cstr_at(d, p); p += len(sym) + 1
            elif op == 0x50: pass
            elif op == 0x60: addend, p = sleb(d, p)
            elif op == 0x70: seg = imm; soff, p = uleb(d, p)
            elif op == 0x80: v, p = uleb(d, p); soff += v
            elif op == 0x90: do_bind(); soff += 8
            elif op == 0xa0: do_bind(); v, p = uleb(d, p); soff += v + 8
            elif op == 0xb0: do_bind(); soff += imm * 8 + 8
            elif op == 0xc0:
                cnt, p = uleb(d, p); skip, p = uleb(d, p)
                for _ in range(cnt): do_bind(); soff += skip + 8
            else: print(f"[bind] unsupported opcode {op:#x}", file=sys.stderr); break

    # ----------------------------- calling back INTO the guest (GLFW callbacks) --
    def begin_callbacks(self, calls, ret, preserve=False):
        """Run guest functions [(addr, [args]|None)...] then return `ret` to the caller.
        args is None to leave the integer/float registers alone. preserve keeps the
        callee's x0 instead of forcing `ret` (used when the guest return value matters)."""
        if not calls:
            if not preserve: self.uc.reg_write(UC_ARM64_REG_X0, ret & M64)
            return
        self.cb_frames.append(dict(lr=self.uc.reg_read(UC_ARM64_REG_LR), calls=list(calls),
                                   ret=ret & M64, preserve=preserve))
        self._next_cb()
    def tail_into(self, addr):
        """Jump to guest `addr` with the current registers; on return, resume the caller."""
        self.cb_frames.append(dict(lr=self.uc.reg_read(UC_ARM64_REG_LR), calls=[(addr, None)],
                                   ret=0, preserve=True))
        self._next_cb()
    def begin_gen(self, gen):
        """Drive a Python generator that YIELDS (guest_addr, [args]) and is sent each callee's x0.
        Its return value becomes x0 for the original caller. Needed for qsort/bsearch comparators."""
        self.cb_frames.append(dict(lr=self.uc.reg_read(UC_ARM64_REG_LR), calls=[], gen=gen, first=True,
                                   ret=0, preserve=False))
        self._next_cb()
    def _next_cb(self):
        uc, f = self.uc, self.cb_frames[-1]
        if "gen" in f:
            try:
                step = next(f["gen"]) if f.pop("first", False) else f["gen"].send(uc.reg_read(UC_ARM64_REG_X0))
            except StopIteration as si:
                f["ret"] = int(si.value or 0) & M64; del f["gen"]
            else:
                f["calls"] = [step]
        if f["calls"]:
            addr, args = f["calls"].pop(0); xi = fi = 0
            if args is not None:
                for a in args:
                    if isinstance(a, float):
                        uc.reg_write(UC_ARM64_REG_D0 + fi, struct.unpack("<Q", struct.pack("<d", a))[0]); fi += 1
                    else:
                        uc.reg_write(UC_ARM64_REG_X0 + xi, a & M64); xi += 1
            uc.reg_write(UC_ARM64_REG_LR, self.cont_stub); uc.reg_write(UC_ARM64_REG_PC, addr)
        else:
            self.cb_frames.pop()
            if not f.get("preserve"): uc.reg_write(UC_ARM64_REG_X0, f["ret"])
            uc.reg_write(UC_ARM64_REG_LR, f["lr"]); uc.reg_write(UC_ARM64_REG_PC, f["lr"])

    # ------------------------------------------------ arm64e PAC emulation --
    # We never SIGN pointers (pac* are no-ops, fixups are stripped), so every
    # authenticated instruction reduces to its plain-pointer equivalent.
    def pac_shim(self, uc):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        insn = struct.unpack("<I", bytes(uc.mem_read(pc, 4)))[0]
        X = lambda n: uc.reg_read(UC_ARM64_REG_X0 + n) if n < 29 else uc.reg_read(
            {29: UC_ARM64_REG_FP, 30: UC_ARM64_REG_LR, 31: UC_ARM64_REG_SP}[n])
        if insn in (0xd65f0bff, 0xd65f0fff):                       # RETAA / RETAB
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR)); return True
        m = insn & 0xfffffc00; rn = (insn >> 5) & 31
        if m in (0xd61f0800, 0xd61f0c00, 0xd71f0800, 0xd71f0c00):  # BRAA/BRAB (Z and non-Z)
            uc.reg_write(UC_ARM64_REG_PC, X(rn)); return True
        if m in (0xd63f0800, 0xd63f0c00, 0xd73f0800, 0xd73f0c00):  # BLRAA/BLRAB
            tgt = X(rn); uc.reg_write(UC_ARM64_REG_LR, pc + 4); uc.reg_write(UC_ARM64_REG_PC, tgt); return True
        if insn & 0xff200400 == 0xf8200400:                        # LDRAA/LDRAB xt,[xn,#imm]{!}
            imm9 = (insn >> 12) & 0x1ff; imm9 = (imm9 - 512 if imm9 & 0x100 else imm9)
            simm = ((insn >> 22) & 1) << 9 | (insn >> 12) & 0x1ff
            simm = simm - 1024 if simm & 0x200 else simm
            addr = (X(rn) + simm * 8) & M64
            uc.reg_write(UC_ARM64_REG_X0 + (insn & 31), int.from_bytes(uc.mem_read(addr, 8), "little"))
            if insn & 0x800: uc.reg_write(UC_ARM64_REG_X0 + rn, addr)   # pre-index writeback
            uc.reg_write(UC_ARM64_REG_PC, pc + 4); return True
        if insn & 0xffff0000 == 0xdac10000 and ((insn >> 10) & 0x3f) <= 0x11:   # PAC*/AUT*/XPAC* (1-source)
            uc.reg_write(UC_ARM64_REG_PC, pc + 4); return True
        if (insn & 0xfffff01f) == 0xd503201f:
            uc.reg_write(UC_ARM64_REG_PC, pc + 4); return True
        if (insn & 0xffffffc0) == 0xd53bd040:
            rt = insn & 31
            tls = getattr(self, "tpidr", 0)
            if not tls:
                tls = self.malloc(0x1000); self.write(tls, b"\0" * 64); self.tpidr = tls
            if rt < 31: uc.reg_write(UC_ARM64_REG_X0 + rt, tls)
            uc.reg_write(UC_ARM64_REG_PC, pc + 4); return True
        if (insn & 0xfff00000) in (0xd5300000, 0xd5100000):
            if (insn & 0xfff00000) == 0xd5300000 and (insn & 31) < 31:
                uc.reg_write(UC_ARM64_REG_X0 + (insn & 31), 0)
            uc.reg_write(UC_ARM64_REG_PC, pc + 4); return True
        if self.lse_shim(uc, insn, pc): return True
        sys.stderr.write("[intr] undefined insn %#x at pc=%#x\n" % (insn, pc))
        return False

    # ---- ARMv8.1 LSE atomics (LDADD/SWP/CAS/...) and RCpc LDAPR: Unicorn lacks them.
    # Guest is single-threaded here, so a plain read-modify-write is exactly right.
    def lse_shim(self, uc, insn, pc):
        def rr(n, sp=False):
            if n == 31: return uc.reg_read(UC_ARM64_REG_SP) if sp else 0
            if n == 29: return uc.reg_read(UC_ARM64_REG_FP)
            if n == 30: return uc.reg_read(UC_ARM64_REG_LR)
            return uc.reg_read(UC_ARM64_REG_X0 + n)
        def wr(n, v):
            v &= M64
            if n == 31: return
            if n == 29: uc.reg_write(UC_ARM64_REG_FP, v)
            elif n == 30: uc.reg_write(UC_ARM64_REG_LR, v)
            else: uc.reg_write(UC_ARM64_REG_X0 + n, v)
        rt, rn, rs = insn & 31, (insn >> 5) & 31, (insn >> 16) & 31
        size = insn >> 30
        if (insn & 0x3f200c00) == 0x38200000:                       # atomic memory ops
            nb = 1 << size; mask = (1 << (8 * nb)) - 1; sign = 1 << (8 * nb - 1)
            o3, opc = (insn >> 15) & 1, (insn >> 12) & 7
            addr = rr(rn, True)
            old = int.from_bytes(uc.mem_read(addr, nb), "little")
            sv = rr(rs) & mask
            sg = lambda v: v - (mask + 1) if v & sign else v
            if o3 == 0:
                new = [(old + sv), old & ~sv, old ^ sv, old | sv,
                       old if sg(old) > sg(sv) else sv, old if sg(old) < sg(sv) else sv,
                       max(old, sv), min(old, sv)][opc] & mask
            elif opc == 0: new = sv                                  # SWP
            elif opc == 4 and rs == 31:                              # LDAPR (plain load)
                wr(rt, old); uc.reg_write(UC_ARM64_REG_PC, pc + 4); return True
            else: return False
            uc.mem_write(addr, new.to_bytes(nb, "little"))
            wr(rt, old)                                              # Rt=31 -> discarded (ST<op>)
            uc.reg_write(UC_ARM64_REG_PC, pc + 4); return True
        if (insn & 0x3fa07c00) == 0x08a07c00:                       # CAS{A,L,AL}{B,H,}
            nb = 1 << size; mask = (1 << (8 * nb)) - 1
            addr = rr(rn, True); old = int.from_bytes(uc.mem_read(addr, nb), "little")
            if old == rr(rs) & mask: uc.mem_write(addr, (rr(rt) & mask).to_bytes(nb, "little"))
            wr(rs, old); uc.reg_write(UC_ARM64_REG_PC, pc + 4); return True
        if (insn & 0xbfa07c00) == 0x08207c00:                       # CASP
            nb = 4 if (insn >> 30) == 0 else 8; mask = (1 << (8 * nb)) - 1
            addr = rr(rn, True); raw = bytes(uc.mem_read(addr, 2 * nb))
            o0, o1 = int.from_bytes(raw[:nb], "little"), int.from_bytes(raw[nb:], "little")
            if o0 == rr(rs) & mask and o1 == rr(rs + 1) & mask:
                uc.mem_write(addr, (rr(rt) & mask).to_bytes(nb, "little") + (rr(rt + 1) & mask).to_bytes(nb, "little"))
            wr(rs, o0); wr(rs + 1, o1); uc.reg_write(UC_ARM64_REG_PC, pc + 4); return True
        if (insn & 0x3f200c00) == 0x19000000:                       # STLUR / LDAPUR / LDAPURS*
            nb = 1 << size; opc = (insn >> 22) & 3
            imm = (insn >> 12) & 0x1ff; imm = imm - 512 if imm & 0x100 else imm
            addr = (rr(rn, True) + imm) & M64
            if opc == 0:
                uc.mem_write(addr, (rr(rt) & ((1 << (8 * nb)) - 1)).to_bytes(nb, "little"))
            else:
                v = int.from_bytes(uc.mem_read(addr, nb), "little")
                if opc >= 2 and v >> (8 * nb - 1): v -= 1 << (8 * nb)
                wr(rt, v & (M64 if opc == 2 else 0xffffffff))
            uc.reg_write(UC_ARM64_REG_PC, pc + 4); return True
        return False

    # ---------------------------------------------------------- execution ---
    def collect_inits(self):
        out = []
        for s in self.mo.sections:
            try:
                if s["sect"] == "__mod_init_func":
                    for i in range(s["size"] // 8):
                        p = int.from_bytes(self.read(s["addr"] + 8 * i, 8), "little")
                        if p: out.append(p)
                elif s["sect"] == "__init_offsets":
                    for i in range(s["size"] // 4):
                        off = int.from_bytes(self.read(s["addr"] + 4 * i, 4), "little")
                        if off: out.append(self.mo.base + off)
            except Exception:
                continue
        return out
    def _boot_next(self):
        """Next +load / static constructor, then main. Returns the PC to enter."""
        if getattr(self, "_boot", None):
            addr, args = self._boot.pop(0)
            if args is not None:
                xi = fi = 0
                for a in args:
                    if isinstance(a, float):
                        self.uc.reg_write(UC_ARM64_REG_D0 + fi, struct.unpack("<Q", struct.pack("<d", a))[0]); fi += 1
                    else:
                        self.uc.reg_write(UC_ARM64_REG_X0 + xi, a & M64); xi += 1
            else:
                self.uc.reg_write(UC_ARM64_REG_X0, len(self.argv))
                self.uc.reg_write(UC_ARM64_REG_X1, self.argv_p)
                self.uc.reg_write(UC_ARM64_REG_X2, self.envp_p)
                self.uc.reg_write(UC_ARM64_REG_X3, self.apple_p)
            self.uc.reg_write(UC_ARM64_REG_LR, self.init_cont)
            return addr
        self.uc.reg_write(UC_ARM64_REG_X0, len(self.argv))
        self.uc.reg_write(UC_ARM64_REG_X1, self.argv_p)
        self.uc.reg_write(UC_ARM64_REG_X2, self.envp_p)
        self.uc.reg_write(UC_ARM64_REG_X3, self.apple_p)
        self.uc.reg_write(UC_ARM64_REG_LR, self.exit_stub)
        return self.mo.entry
    def _n_runnable(self):
        return sum(1 for t in self.threads.values() if t["state"] == "run")
    def _switch(self, cur_pc):
        """Suspend the current guest thread at cur_pc and resume another runnable one. Rewriting PC after the context
        restore is what makes Unicorn abandon the translation block it is in (a bare context_restore inside a hook let the
        old block finish with the NEW thread's registers, so the other thread never really resumed)."""
        uc = self.uc
        opts = [t for t, i in self.threads.items() if i["state"] == "run" and t != self.current_tid and i.get("ctx") is not None]
        if not opts: return False
        uc.reg_write(UC_ARM64_REG_PC, cur_pc)
        self.threads[self.current_tid]["ctx"] = uc.context_save()
        nxt = opts[self._blocks % len(opts)]
        self.current_tid = nxt
        uc.context_restore(self.threads[nxt]["ctx"])
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_PC))
        return True
    def _on_block(self, uc, address, size, _):
        self._blocks += 1
        pr = getattr(self, "_prof", None)
        if pr is not None: pr[address] = pr.get(address, 0) + 1
        if self._blocks % 40: return
        if self._n_runnable() < 2: return
        self._switch(address)
    def schedule(self, force=False):
        """Called from a stub: yield to another thread as if the stub had already returned to its caller."""
        if self._n_runnable() < 2: return
        self._switch(self.uc.reg_read(UC_ARM64_REG_LR))
    def _bl_note(self, uc, cs, ins):
        """Name the import a bl/b targets, following the binary's own __stubs trampolines (adrp/ldr/br x16)."""
        if ins.mnemonic not in ("bl", "b") or not ins.op_str.startswith("#"): return ""
        try:
            tgt = int(ins.op_str.lstrip("#"), 16)
            def nm(a):
                if STUB_BASE <= a < STUB_BASE + STUB_SIZE: return self.stub_names[(a - STUB_BASE) // STUB_STRIDE]
            if nm(tgt): return "   ; -> " + nm(tgt)
            d = list(cs.disasm(bytes(uc.mem_read(tgt, 12)), tgt))
            if len(d) == 3 and d[0].mnemonic == "adrp" and d[1].mnemonic == "ldr" and d[2].mnemonic == "br":
                page = int(d[0].op_str.split("#")[1], 16); off = int(d[1].op_str.split("#")[-1].rstrip("]"), 16) if "#" in d[1].op_str.split(",", 1)[1] else 0
                p = int.from_bytes(bytes(uc.mem_read(page + off, 8)), "little")
                return f"   ; -> {nm(p) or hex(p)} (via stub)"
        except Exception: pass
        return ""
    def _dump_state(self):
        uc = self.uc; pc = uc.reg_read(UC_ARM64_REG_PC); w = sys.stderr.write
        try:
            code = bytes(uc.mem_read(pc - 32, 80))
        except UcError:
            code = b""
        dis = {}
        try:
            import capstone
            for i in capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM).disasm(code, pc - 32):
                dis[i.address] = f"{i.mnemonic} {i.op_str}"
        except Exception: pass
        w(f"  code around pc ({'capstone' if dis else 'raw words; pip3 install capstone for disassembly'}):\n")
        for k in range(0, len(code) - 3, 4):
            a = pc - 32 + k
            w(f"   {'>' if a == pc else ' '} {a:#x}: {int.from_bytes(code[k:k+4], 'little'):08x}  {dis.get(a, '')}\n")
        w("  regs: " + " ".join(f"x{i}={uc.reg_read(UC_ARM64_REG_X0 + i):#x}" for i in range(16)) + "\n")
        w("  regs: " + " ".join(f"x{i}={uc.reg_read(UC_ARM64_REG_X0 + i):#x}" for i in range(16, 29)) +
          f" fp={uc.reg_read(UC_ARM64_REG_FP):#x} lr={uc.reg_read(UC_ARM64_REG_LR):#x} sp={uc.reg_read(UC_ARM64_REG_SP):#x}\n")
        for i in list(range(0, 8)) + list(range(19, 29)):
            v = uc.reg_read(UC_ARM64_REG_X0 + i)
            try:
                if v > 0x10000: w(f"  [x{i}] {v:#x}: {bytes(uc.mem_read(v, 32)).hex()}\n")
            except UcError: pass
        fp, chain = uc.reg_read(UC_ARM64_REG_FP), []
        for _ in range(10):
            try:
                nfp, ret = struct.unpack("<QQ", bytes(uc.mem_read(fp, 16)))
            except UcError: break
            chain.append(ret)
            if nfp <= fp: break
            fp = nfp
        w("  frame-pointer chain (return addresses, innermost first): " + " ".join(f"{a:#x}" for a in chain) + "\n")
        try:
            import capstone
            cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            for ret in chain:
                base = ret - 32
                try: blob = bytes(uc.mem_read(base, 40))
                except UcError: continue
                w(f"  --- call site, returns to {ret:#x}:\n")
                for ins in cs.disasm(blob, base):
                    note = self._bl_note(uc, cs, ins)
                    w(f"     {ins.address:#x}: {ins.mnemonic:6} {ins.op_str}{note}{'   <== return here' if ins.address + 4 == ret else ''}\n")
        except Exception: pass
        for pk in filter(None, os.environ.get("ARM2X86_PEEK", "").split(",")):      # ARM2X86_PEEK=0x107079a10:24,0x107079d80:64
            try:
                a, n = pk.split(":"); a, n = int(a, 16), int(n)
                w(f"  peek {a:#x}: {bytes(uc.mem_read(a, n)).hex()}\n")
            except Exception as ex: w(f"  peek {pk}: {ex}\n")
        spec = os.environ.get("ARM2X86_DISASM")          # e.g. ARM2X86_DISASM=0x102fb35b0-0x102fb3720,0x102fb3638-0x102fb3700
        if spec:
            try:
                import capstone
                cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
                for rng in spec.split(","):
                    lo, hi = (int(x, 16) for x in rng.split("-"))
                    w(f"  --- disassembly {lo:#x}-{hi:#x}:\n")
                    for ins in cs.disasm(bytes(uc.mem_read(lo, hi - lo)), lo):
                        note = self._bl_note(uc, cs, ins)
                        w(f"     {ins.address:#x}: {ins.mnemonic:7} {ins.op_str}{note}\n")
            except Exception as ex: w(f"  (disasm failed: {ex})\n")
        for tid, info in self.threads.items():
            if tid == self.current_tid or info.get("ctx") is None: continue
            try:
                c = info["ctx"]
                w(f"  thread {tid} ({info['state']}): pc={c.reg_read(UC_ARM64_REG_PC):#x} lr={c.reg_read(UC_ARM64_REG_LR):#x} "
                  f"x19={c.reg_read(UC_ARM64_REG_X19):#x} x20={c.reg_read(UC_ARM64_REG_X20):#x}\n")
            except Exception as ex: w(f"  thread {tid}: (cannot read saved context: {ex})\n")
    def spawn_thread(self, start, arg):
        tid = max(self.threads) + 1
        base = THREAD_BASE + (tid - 2) * (THREAD_STACK + 0x1000)
        try: self.uc.mem_map(base, THREAD_STACK)
        except UcError: pass
        sp = (base + THREAD_STACK - 0x100) & ~0xf
        fp = self.uc.reg_read(UC_ARM64_REG_FP)
        lr = self.uc.reg_read(UC_ARM64_REG_LR)
        sp_caller = self.uc.reg_read(UC_ARM64_REG_SP)
        x0_caller = self.uc.reg_read(UC_ARM64_REG_X0)     # pthread_create's out-pointer: the stub reads it again after we return
        self.uc.reg_write(UC_ARM64_REG_SP, sp)
        self.uc.reg_write(UC_ARM64_REG_FP, 0)
        self.uc.reg_write(UC_ARM64_REG_X0, arg & M64)
        self.uc.reg_write(UC_ARM64_REG_LR, self.thread_exit_stub)
        self.uc.reg_write(UC_ARM64_REG_PC, start)
        ctx = self.uc.context_save()
        self.uc.reg_write(UC_ARM64_REG_SP, sp_caller)
        self.uc.reg_write(UC_ARM64_REG_FP, fp)
        self.uc.reg_write(UC_ARM64_REG_PC, lr)
        self.uc.reg_write(UC_ARM64_REG_X0, x0_caller)
        # GPUI/Rust thread_local profiler breaks when multiple guest threads
        # share one host OS thread. Keep only the main guest thread runnable
        # unless ARM2X86_MULTI_THREAD=1.
        if os.environ.get("ARM2X86_MULTI_THREAD"):
            self.threads[tid] = {"state": "run", "ctx": ctx, "wait": None}
        else:
            self.threads[tid] = {"state": "wait", "ctx": ctx, "wait": ("parked", None)}
        if not self._sched:
            self.uc.hook_add(UC_HOOK_BLOCK, self._on_block)
            self._sched = True
        if os.environ.get("ARM2X86_VERBOSE"):
            sys.stderr.write(f"[thread] spawned {tid} at {start:#x}\n")
        return tid
    def park_thread(self, why, token):
        uc = self.uc
        lr = uc.reg_read(UC_ARM64_REG_LR)
        uc.reg_write(UC_ARM64_REG_PC, lr)
        uc.reg_write(UC_ARM64_REG_X0, 0)
        self.threads[self.current_tid]["ctx"] = uc.context_save()
        self.threads[self.current_tid]["state"] = "wait"
        self.threads[self.current_tid]["wait"] = (why, token)
        self._switch_away()
    def wake_thread(self, tid):
        t = self.threads.get(tid)
        if t and t["state"] == "wait":
            t["state"] = "run"
    def thread_alive(self, tid):
        t = self.threads.get(tid)
        return bool(t and t["state"] != "dead")
    def thread_dead(self, retval):
        me = self.threads.get(self.current_tid)
        if me: me["state"] = "dead"
        for info in self.threads.values():
            w = info.get("wait")
            if info["state"] == "wait" and w and w[0] == "join" and w[1] == self.current_tid:
                info["state"] = "run"
        self._switch_away()
    def _switch_away(self):
        opts = [t for t, i in self.threads.items() if i["state"] == "run" and i.get("ctx") is not None and t != self.current_tid]
        if not opts:
            if self.threads.get(1, {}).get("state") == "run" and self.current_tid != 1 and self.threads[1].get("ctx") is not None:
                opts = [1]
        if not opts:
            if not any(i["state"] == "run" for i in self.threads.values()):
                self.exit(0)
            return
        nxt = opts[0]
        self.current_tid = nxt
        self.uc.context_restore(self.threads[nxt]["ctx"])
        self.uc.reg_write(UC_ARM64_REG_PC, self.uc.reg_read(UC_ARM64_REG_PC))

    def setup_stack(self):
        uc = self.uc; sp = STACK_TOP - 0x1000
        def push_str(s):
            nonlocal sp
            b = s.encode() + b"\0"; sp -= (len(b) + 15) & ~15; self.write(sp, b); return sp
        arg_ptrs = [push_str(a) for a in self.argv]
        env_ptrs = [push_str(f"{k}={v}") for k, v in list(os.environ.items())[:64]]
        apple = [push_str("executable_path=" + self.path)]
        table = arg_ptrs + [0] + env_ptrs + [0] + apple + [0]
        sp -= (len(table) * 8 + 15) & ~15
        self.write(sp, b"".join(p.to_bytes(8, "little") for p in table))
        argv_p = sp
        envp_p = sp + 8 * (len(arg_ptrs) + 1)
        apple_p = envp_p + 8 * (len(env_ptrs) + 1)
        self.argv_p, self.envp_p, self.apple_p = argv_p, envp_p, apple_p
        sp -= 0x100
        uc.reg_write(UC_ARM64_REG_SP, sp & ~0xf)
        uc.reg_write(UC_ARM64_REG_X0, len(self.argv)); uc.reg_write(UC_ARM64_REG_X1, argv_p)
        uc.reg_write(UC_ARM64_REG_X2, envp_p);         uc.reg_write(UC_ARM64_REG_X3, apple_p)
        uc.reg_write(UC_ARM64_REG_LR, self.exit_stub)   # main() returning -> exit(x0)

    def run(self):
        def on_stub(uc, address, size, _):
            name = self.stub_names[(address - STUB_BASE) // STUB_STRIDE]
            if name == "__arm2x86_cont": self._next_cb(); return
            if name == "__arm2x86_init_cont":
                self.uc.reg_write(UC_ARM64_REG_PC, self._boot_next()); return
            if self.trace: sys.stderr.write(f"[call] {name}({', '.join(hex(self.arg(i)) for i in range(4))})\n")
            f = hle.FUNCS.get(name)
            if f is None:
                if os.environ.get("ARM2X86_STRICT") == "1":
                    sys.stderr.write(f"[arm2x86] unimplemented import {name} called\n"); self.exit(127); return
                r = None
                for fb in hle.FALLBACKS:
                    r = fb(self, name)
                    if r is not None: break
                if name not in self.warned:
                    self.warned.add(name)
                    what = "x0 kept (returns this)" if r is hle.KEEP else ("handled" if r is not None else "0")
                    sys.stderr.write(f"[arm2x86] unimplemented {name} -> {what} (set ARM2X86_STRICT=1 to abort)\n")
                if r is hle.KEEP: return
                uc.reg_write(UC_ARM64_REG_X0, (r or 0) & M64); return
            self.last_stubs = (getattr(self, "last_stubs", []) + [name])[-8:]
            try: r = f(self)
            except UcError as ex:
                sys.stderr.write(f"[fault] stub {name} touched bad guest memory: {ex} (x0..x3={self.arg(0):#x},{self.arg(1):#x},{self.arg(2):#x},{self.arg(3):#x} lr={uc.reg_read(UC_ARM64_REG_LR):#x})\n")
                self.exit(139); return
            if r is not None: uc.reg_write(UC_ARM64_REG_X0, r & M64)
        self.uc.hook_add(UC_HOOK_CODE, on_stub, begin=STUB_BASE, end=STUB_BASE + STUB_SIZE)
        objc.install_stub_data_hook(self)
        def on_intr(uc, intno, _):
            if intno == 1 and self.pac_shim(uc): return          # UNDEFINED insn: try PAC emulation
            if intno != 2:
                sys.stderr.write(f"[intr] unhandled {intno} ({'brk/trap' if intno == 7 else 'exception'}) at pc={uc.reg_read(UC_ARM64_REG_PC):#x} lr={uc.reg_read(UC_ARM64_REG_LR):#x} last calls: {getattr(self, 'last_stubs', [])}\n"); self.exit(139); return
            n = uc.reg_read(UC_ARM64_REG_X16)
            sysmap = {1: "_exit", 3: "_read", 4: "_write", 20: "_getpid"}
            if n in sysmap: r = hle.FUNCS[sysmap[n]](self); uc.reg_write(UC_ARM64_REG_X0, (r or 0) & M64)
            else:
                sys.stderr.write(f"[syscall] unimplemented BSD syscall #{n}\n"); uc.reg_write(UC_ARM64_REG_X0, 78)
        self.uc.hook_add(UC_HOOK_INTR, on_intr)
        self.setup_stack()
        loads = objc.guest_load_calls(self)
        inits = [(p, None) for p in getattr(self, 'dylib_inits', []) + self.collect_inits()]
        self._boot = loads + inits
        start = self._boot_next() if self._boot else self.mo.entry
        if self.missing and os.environ.get("ARM2X86_VERBOSE"):
            print("[arm2x86] imports with no emulation yet:", ", ".join(sorted(set(self.missing))), file=sys.stderr)
        import signal
        self._interrupted = False
        self._prof = {}
        def _sigint(signum, frame):
            self._interrupted = True; self.uc.emu_stop()
        signal.signal(signal.SIGINT, _sigint)
        if os.environ.get("ARM2X86_TIMEOUT"):          # auto-interrupt (and print the report) after N seconds
            signal.signal(signal.SIGALRM, _sigint); signal.alarm(int(os.environ["ARM2X86_TIMEOUT"]))
        try:
            self.uc.emu_start(start, 0xffffffffffffffff)
            if self._interrupted:
                uc = self.uc; top = sorted(self._prof.items(), key=lambda kv: -kv[1])[:12]
                sys.stderr.write(f"\n[arm2x86] interrupted. pc={uc.reg_read(UC_ARM64_REG_PC):#x} lr={uc.reg_read(UC_ARM64_REG_LR):#x} "
                                 f"tid={self.current_tid} threads={ {t: (i['state'], i.get('wait')) for t, i in self.threads.items()} }\n"
                                 f"  last calls: {getattr(self, 'last_stubs', [])}\n  hottest blocks: " +
                                 ", ".join(f"{a:#x}x{n}" for a, n in top) + "\n")
                self._dump_state()
                return 130
        except UcError as e:
            pc = self.uc.reg_read(UC_ARM64_REG_PC)
            print(f"[fault] {e} at pc={pc:#x} lr={self.uc.reg_read(UC_ARM64_REG_LR):#x} tid={self.current_tid} last calls: {getattr(self, 'last_stubs', [])}", file=sys.stderr)
            for i in range(0, 8): print(f"  x{i} = {self.uc.reg_read(UC_ARM64_REG_X0+i):#x}", file=sys.stderr)
            return 139
        code = self.exit_code if self.exit_code is not None else 0
        sys.stderr.write(f"[arm2x86] guest stopped: exit code {code}"
                         f"{' (via exit()/_exit)' if self.exit_code is not None else ' (main returned or the run loop stopped)'}; "
                         f"last calls: {getattr(self, 'last_stubs', [])}\n")
        return code

# ---- qsort / qsort_r / bsearch with the GUEST comparator (the old stub sorted by raw bytes -> guest asserts) ----
def _s32(v): v &= 0xffffffff; return v - (1 << 32) if v >> 31 else v
def _qsort_impl(e, reentrant):
    base, n, size = e.arg(0), e.arg(1), e.arg(2)
    thunk, cmp = (e.arg(3), e.arg(4)) if reentrant else (None, e.arg(3))
    def call(a, b): return (cmp, [thunk, a, b] if reentrant else [a, b])
    if not base or n < 2 or not size or not cmp or n > 5_000_000: return None
    blob = bytes(e.read(base, n * size))
    busy = getattr(e, "_qs_busy", 0)
    if busy or getattr(e, "_qs_cap", 0) < len(blob):             # reuse one scratch buffer; fresh one if nested
        tmp = e.malloc(len(blob))
        if not busy: e._qs_tmp, e._qs_cap = tmp, len(blob)
    else: tmp = e._qs_tmp
    e.write(tmp, blob); e._qs_busy = busy + 1
    def msort(idx):
        if len(idx) < 2: return idx
        mid = len(idx) // 2
        L = yield from msort(idx[:mid]); R = yield from msort(idx[mid:])
        out, i, j = [], 0, 0
        while i < len(L) and j < len(R):
            r = yield call(tmp + L[i] * size, tmp + R[j] * size)
            if _s32(r) <= 0: out.append(L[i]); i += 1
            else: out.append(R[j]); j += 1
        return out + L[i:] + R[j:]
    def driver():
        try:
            order = yield from msort(list(range(n)))
            e.write(base, b"".join(blob[k * size:(k + 1) * size] for k in order))
        finally: e._qs_busy -= 1
        return 0
    e.begin_gen(driver()); return None
def _bsearch_impl(e):
    key, base, n, size, cmp = e.arg(0), e.arg(1), e.arg(2), e.arg(3), e.arg(4)
    def driver():
        lo, hi = 0, n
        while lo < hi:
            mid = (lo + hi) // 2
            r = _s32((yield (cmp, [key, base + mid * size])))
            if r == 0: return base + mid * size
            if r < 0: hi = mid
            else: lo = mid + 1
        return 0
    e.begin_gen(driver()); return None
hle.FUNCS["_qsort"] = lambda e: _qsort_impl(e, False)
hle.FUNCS["_qsort_r"] = lambda e: _qsort_impl(e, True)
hle.FUNCS["_bsearch"] = _bsearch_impl

if __name__ == "__main__":
    if "--kern26" in sys.argv:                  # loader option (not passed to the guest): report macOS 27 / Darwin 26 / Apple M5
        sys.argv.remove("--kern26"); os.environ["ARM2X86_KERN26"] = "1"
    if len(sys.argv) < 2: sys.exit(__doc__)
    if os.environ.get("ARM2X86_DEBUG") and not os.environ.get("ARM2X86_CHILD"):
        # supervisor: if the host process dies on a signal (segfault inside a bridged ObjC call), say which call it was
        import subprocess, tempfile
        fd, crumb = tempfile.mkstemp(prefix="a2x_crumb_"); os.close(fd)
        env = {**os.environ, "ARM2X86_CHILD": "1", "ARM2X86_CRUMB": crumb}
        try: rc = subprocess.call([sys.executable, os.path.abspath(__file__)] + sys.argv[1:], env=env)
        except KeyboardInterrupt: rc = 130
        if rc < 0:
            try: last = open(crumb, errors="replace").read()
            except OSError: last = ""
            sys.stderr.write(f"\n[arm2x86] host process died with signal {-rc}. Last bridged ObjC call:\n{last or '(none recorded)'}\n")
        try: os.unlink(crumb)
        except OSError: pass
        sys.exit(rc if rc >= 0 else 128 - rc)
    e = Emu(sys.argv[1], sys.argv[2:]); e.load(); rc = e.run()
    try: sys.stdout.flush(); sys.stderr.flush()
    except Exception: pass
    os._exit(rc & 0xff if rc >= 0 else 1)     # skip interpreter teardown: other host threads (SDL audio) may still call into Python
