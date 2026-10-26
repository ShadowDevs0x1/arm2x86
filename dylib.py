"""
Load the app's OWN arm64 dylibs (e.g. @executable_path/libfreetype.6.dylib) into the guest so their code runs under Unicorn,
and make their exports resolvable by the main binary's imports.

  * libSDL3 is NOT loaded here (it is bridged to the host's real x86_64 copy by sdl3bridge.py)
  * libsteam_api is NOT loaded (no Steam client here): extras3.py provides small SteamAPI stand-ins
  * everything the dylib imports from libSystem/libz/... goes through Emu.resolve(): HLE stubs, or "unimplemented -> 0"
Supports chained fixups (all common formats) and classic rebase/bind opcodes, export tries, __mod_init_func / __init_offsets.
Switch off with ARM2X86_NODYLIBS=1. Debug: ARM2X86_VERBOSE=1.
"""
import os, sys, struct
import hle

DYLIB_BASE, DYLIB_STEP = 0x600000000, 0x10000000
SKIP = ("libSDL3", "libsteam_api", "libSystem", "libc++", "libobjc")
M64 = (1 << 64) - 1
VERBOSE = bool(os.environ.get("ARM2X86_VERBOSE"))

def _uleb(d, p):
    r = s = 0
    while True:
        b = d[p]; p += 1; r |= (b & 0x7f) << s; s += 7
        if not b & 0x80: return r, p
def _sleb(d, p):
    r = s = 0
    while True:
        b = d[p]; p += 1; r |= (b & 0x7f) << s; s += 7
        if not b & 0x80:
            if b & 0x40: r -= 1 << s
            return r, p
def _cstr(d, p): return d[p:d.index(b"\0", p)].decode("latin-1")

def arm64_slice(data):
    magic = struct.unpack(">I", data[:4])[0]
    if magic in (0xcafebabe, 0xcafebabf):
        n = struct.unpack(">I", data[4:8])[0]
        for i in range(n):
            cpu, sub, off, size, al = struct.unpack(">iiIII", data[8 + 20 * i: 28 + 20 * i])
            if cpu & 0xffffffff == 0x0100000c: return data[off: off + size]
        return None
    cpu = struct.unpack("<i", data[4:8])[0]
    return data if struct.unpack("<I", data[:4])[0] == 0xfeedfacf and cpu & 0xffffffff == 0x0100000c else None

class Image:
    """Parsed arm64 Mach-O dylib (no emulator needed: unit-testable on any host)."""
    def __init__(self, data, path=""):
        self.d, self.path = data, path
        magic, cpu, sub, self.filetype, ncmds = struct.unpack("<IiiII", data[:20])
        self.segs, self.sects, self.deps = [], [], []
        self.chained = self.dyld_info = self.exports_trie = None
        off = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack("<II", data[off:off + 8])
            if cmd == 0x19:
                name = data[off + 8:off + 24].split(b"\0")[0].decode()
                vm, vmsz, fo, fsz = struct.unpack("<QQQQ", data[off + 24:off + 56])
                self.segs.append(dict(name=name, vm=vm, vmsize=vmsz, fileoff=fo, filesize=fsz))
                ns = struct.unpack_from("<I", data, off + 64)[0]; so = off + 72
                for _i in range(ns):
                    sn = data[so:so + 16].split(b"\0")[0].decode("latin-1")
                    addr, ssz = struct.unpack_from("<QQ", data, so + 32); flags = struct.unpack_from("<I", data, so + 64)[0]
                    self.sects.append(dict(sect=sn, addr=addr, size=ssz, type=flags & 0xff)); so += 80
            elif cmd in (0xc, 0x80000018, 0x1f, 0x8000001f):
                no = struct.unpack_from("<I", data, off + 8)[0]; self.deps.append(_cstr(data, off + no))
            elif cmd == 0x80000034: self.chained = struct.unpack("<II", data[off + 8:off + 16])
            elif cmd in (0x22, 0x80000022): self.dyld_info = struct.unpack("<10I", data[off + 8:off + 48])
            elif cmd == 0x80000033: self.exports_trie = struct.unpack("<II", data[off + 8:off + 16])
            off += size
        first = next((s for s in self.segs if s["name"] == "__TEXT"), self.segs[0])
        self.vmbase = first["vm"]

    # ---- exports: name -> offset from image base
    def exports(self):
        d = self.d
        if self.exports_trie: base, size = self.exports_trie
        elif self.dyld_info: base, size = self.dyld_info[8], self.dyld_info[9]
        else: return {}
        out = {}
        def walk(prefix, node, depth=0):
            if depth > 64: return
            p = base + node; tl, p = _uleb(d, p)
            if tl:
                flags, q = _uleb(d, p)
                if not (flags & 0x8) and not (flags & 0x10):
                    addr, q = _uleb(d, q); out[prefix] = addr
                elif flags & 0x10:
                    addr, q = _uleb(d, q); out[prefix] = addr          # stub-and-resolver: the stub is good enough
            p += tl; cc = d[p]; p += 1
            for _ in range(cc):
                e = d.index(b"\0", p); label = d[p:e].decode("latin-1"); p = e + 1
                nxt, p = _uleb(d, p); walk(prefix + label, nxt, depth + 1)
        if size: walk("", 0)
        return out

    # ---- fixups: calls rebase(addr, new_value) / bind(addr, name, addend) through callbacks
    def chained_fixups(self, slide, write, resolve):
        d = self.d; off, size = self.chained
        ver, starts_off, imp_off, sym_off, n, ifmt, _ = struct.unpack_from("<7I", d, off)
        imports = []
        for i in range(n):
            if ifmt == 1: v = struct.unpack_from("<I", d, off + imp_off + 4 * i)[0]; ad = 0; no = v >> 9
            elif ifmt == 2: v, ad = struct.unpack_from("<Ii", d, off + imp_off + 8 * i); no = v >> 9
            else: v, ad = struct.unpack_from("<Qq", d, off + imp_off + 16 * i); no = v >> 32
            imports.append((_cstr(d, off + sym_off + no), ad))
        sb = off + starts_off; segcount = struct.unpack_from("<I", d, sb)[0]
        sx = lambda v, bits: v - (1 << bits) if v >> (bits - 1) else v
        for si in range(segcount):
            so = struct.unpack_from("<I", d, sb + 4 + 4 * si)[0]
            if so == 0: continue
            q = sb + so
            _, psize, fmt, segoff, _, pcount = struct.unpack_from("<IHHQIH", d, q)
            pstarts = struct.unpack_from(f"<{pcount}H", d, q + 22)
            for pi, ps in enumerate(pstarts):
                if ps == 0xffff: continue
                if ps & 0x8000:
                    if VERBOSE: print(f"[dylib] multi-start page in {self.path}", file=sys.stderr)
                    continue
                a = slide + segoff + pi * psize + ps
                while True:
                    raw = int.from_bytes(self._rd(a), "little")
                    if fmt in (2, 6):                                      # PTR_64 / PTR_64_OFFSET
                        nxt, stride = (raw >> 51) & 0xfff, 4
                        if raw >> 63:
                            name, ad = imports[raw & 0xffffff]; val = resolve(name) + ad + ((raw >> 24) & 0xff)
                        else:
                            # PTR_64 stores a link-time VMADDR (needs slide - vmbase); PTR_64_OFFSET stores an offset from the header
                            lo, hi = raw & 0xfffffffff, ((raw >> 36) & 0xff) << 56
                            val = ((lo + slide - (self.vmbase if fmt == 2 else 0)) & ((1 << 56) - 1)) | hi
                    elif fmt in (1, 9, 12):                                # arm64e family (PAC stripped)
                        nxt, stride = (raw >> 51) & 0x7ff, 8
                        auth, bind = raw >> 63, (raw >> 62) & 1
                        if bind:
                            ordi = raw & (0xffffff if fmt == 12 else 0xffff); name, iad = imports[ordi]
                            ad = 0 if auth else sx((raw >> 32) & 0x7ffff, 19); val = resolve(name) + iad + ad
                        elif auth: val = (raw & 0xffffffff) + slide
                        else:
                            lo, hi = raw & 0x7ffffffffff, ((raw >> 43) & 0xff) << 56         # fmt 1 = vmaddr, fmt 9/12 = offset
                            val = ((lo + slide - (self.vmbase if fmt == 1 else 0)) & ((1 << 56) - 1)) | hi
                    else:
                        raise RuntimeError(f"unsupported chained pointer format {fmt} in {self.path}")
                    write(a, (val & M64).to_bytes(8, "little"))
                    if nxt == 0: break
                    a += nxt * stride

    def classic_fixups(self, slide, write, resolve):
        d = self.d; _, _, bo, bs, wo, ws, lo, ls, _, _ = self.dyld_info
        # rebases (the dylib is not at its preferred address, so these matter, unlike for the main exe)
        ro, rs = self.dyld_info[0], self.dyld_info[1]
        if rs:
            p, end, seg, soff = ro, ro + rs, 0, 0
            def rebase():
                a = slide + self.segs[seg]["vm"] - self.vmbase + soff
                write(a, ((int.from_bytes(self._rd(a), "little") + slide) & M64).to_bytes(8, "little"))
            while p < end:
                b = d[p]; p += 1; op, imm = b & 0xf0, b & 0x0f
                if op == 0x00: break
                elif op == 0x10: pass
                elif op == 0x20: seg = imm; soff, p = _uleb(d, p)
                elif op == 0x30: v, p = _uleb(d, p); soff += v
                elif op == 0x40: soff += imm * 8
                elif op == 0x50:
                    for _ in range(imm): rebase(); soff += 8
                elif op == 0x60:
                    cnt, p = _uleb(d, p)
                    for _ in range(cnt): rebase(); soff += 8
                elif op == 0x70: rebase(); v, p = _uleb(d, p); soff += v + 8
                elif op == 0x80:
                    cnt, p = _uleb(d, p); skip, p = _uleb(d, p)
                    for _ in range(cnt): rebase(); soff += skip + 8
        for off, size, lazy in ((bo, bs, False), (wo, ws, False), (lo, ls, True)):
            if not size: continue
            p, end, sym, addend, seg, soff = off, off + size, None, 0, 0, 0
            def do_bind():
                a = slide + self.segs[seg]["vm"] - self.vmbase + soff
                write(a, ((resolve(sym) + addend) & M64).to_bytes(8, "little"))
            while p < end:
                b = d[p]; p += 1; op, imm = b & 0xf0, b & 0x0f
                if op == 0x00:
                    if lazy: continue
                    break
                elif op in (0x10, 0x30, 0x50): pass
                elif op == 0x20: _, p = _uleb(d, p)
                elif op == 0x40: sym = _cstr(d, p); p += len(sym) + 1
                elif op == 0x60: addend, p = _sleb(d, p)
                elif op == 0x70: seg = imm; soff, p = _uleb(d, p)
                elif op == 0x80: v, p = _uleb(d, p); soff += v
                elif op == 0x90: do_bind(); soff += 8
                elif op == 0xa0: do_bind(); v, p = _uleb(d, p); soff += v + 8
                elif op == 0xb0: do_bind(); soff += imm * 8 + 8
                elif op == 0xc0:
                    cnt, p = _uleb(d, p); skip, p = _uleb(d, p)
                    for _ in range(cnt): do_bind(); soff += skip + 8
                else: break
    _rd = None   # set by the loader: read 8 bytes of guest memory

def candidates(emu):
    """paths of bundled dylibs the main binary asks for (@executable_path/@loader_path/@rpath)"""
    mo = emu.mo; d = mo.data; exe_dir = os.path.dirname(emu.path); out = []
    off, ncmds = 32, struct.unpack("<I", d[16:20])[0]
    for _ in range(ncmds):
        cmd, size = struct.unpack("<II", d[off:off + 8])
        if cmd in (0xc, 0x80000018):
            no = struct.unpack_from("<I", d, off + 8)[0]; name = _cstr(d, off + no)
            if name.startswith(("@executable_path/", "@loader_path/", "@rpath/")):
                base = os.path.basename(name)
                if any(base.startswith(s) for s in SKIP): off += size; continue
                for dd in (exe_dir, os.path.join(exe_dir, "..", "Frameworks"), os.path.join(exe_dir, "..", "Resources")):
                    p = os.path.join(dd, base)
                    if os.path.exists(p): out.append(os.path.abspath(p)); break
        off += size
    return out

_LOADED = {}          # abspath -> slide
_NEXT_SLIDE = [DYLIB_BASE]
_EXPORTS = {}

def is_arm64_macho(path):
    """True if path is (or contains) an arm64/arm64e Mach-O we can map into the guest."""
    try:
        raw = open(path, "rb").read()
    except OSError:
        return False
    return arm64_slice(raw) is not None

def load_one(emu, path):
    """Map one arm64 Mach-O (dylib or plugin) into the guest. Returns (slide, [init addrs]) or (None, [])."""
    path = os.path.abspath(path)
    if path in _LOADED:
        return _LOADED[path], []
    if os.environ.get("ARM2X86_NODYLIBS"):
        return None, []
    try:
        data = arm64_slice(open(path, "rb").read())
    except OSError:
        return None, []
    if data is None:
        sys.stderr.write(f"[dylib] {os.path.basename(path)} has no arm64 slice; skipped\n")
        return None, []
    img = Image(data, os.path.basename(path)); img._rd = lambda a: bytes(emu.read(a, 8))
    total = max((s["vm"] - img.vmbase + s["vmsize"] for s in img.segs if s["name"] != "__PAGEZERO"), default=0)
    span = (total + 0x3fff) & ~0x3fff
    slide = _NEXT_SLIDE[0]
    try:
        emu.uc.mem_map(slide, span)
    except Exception as ex:
        sys.stderr.write(f"[dylib] mem_map {path}: {ex}\n"); return None, []
    for s in img.segs:
        if s["name"] == "__PAGEZERO" or s["vmsize"] == 0: continue
        emu.write(slide + s["vm"] - img.vmbase, data[s["fileoff"]: s["fileoff"] + s["filesize"]])
    w = lambda a, b: emu.write(a, b)
    try:
        if img.chained: img.chained_fixups(slide, w, emu.resolve)
        elif img.dyld_info: img.classic_fixups(slide, w, emu.resolve)
    except Exception as ex:
        sys.stderr.write(f"[dylib] fixups {os.path.basename(path)}: {ex}\n")
    inits = []
    for name, off in img.exports().items():
        _EXPORTS[name] = slide + off
    for s in img.sects:
        a = slide + s["addr"] - img.vmbase
        if s["sect"] == "__mod_init_func" or s["type"] == 9:
            for i in range(s["size"] // 8):
                p = int.from_bytes(emu.read(a + 8 * i, 8), "little")
                if p: inits.append(p)
        elif s["sect"] == "__init_offsets" or s["type"] == 0x16:
            for i in range(s["size"] // 4):
                o = int.from_bytes(emu.read(a + 4 * i, 4), "little")
                if o: inits.append(slide + o)
        elif s["sect"] == "__objc_classlist":
            try:
                import objc as _objc, traceback
                fresh, errs = [], []
                for i in range(s["size"] // 8):
                    try:
                        addr = int.from_bytes(emu.read(a + 8 * i, 8), "little")
                        if addr not in _objc.CLASSES:
                            info = _objc.parse_class(emu, addr)
                            if info: fresh.append(addr)
                            else: errs.append(f"{addr:#x}: parse_class returned nothing")
                    except Exception as ex:
                        tb = traceback.extract_tb(ex.__traceback__)[-1]
                        errs.append(f"entry {i} addr={addr:#x}: {type(ex).__name__}: {ex} ({os.path.basename(tb.filename)}:{tb.lineno})")
                emu._fresh_classes = getattr(emu, "_fresh_classes", []) + fresh
                names = sorted(_objc.CLASSES[c].get("name") or "?" for c in fresh)
                sys.stderr.write(f"[dylib] {os.path.basename(path)}: __objc_classlist has {s['size'] // 8} entries -> {len(fresh)} classes registered"
                                 f"{', ' + str(len(errs)) + ' FAILED' if errs else ''}; e.g. {names[:6]}\n")
                for er in errs[:5]: sys.stderr.write(f"[dylib]   {er}\n")
            except Exception as ex:
                sys.stderr.write(f"[dylib] objc classlist {os.path.basename(path)}: {ex}\n")
    if not any(x["sect"] == "__objc_classlist" for x in img.sects):
        sys.stderr.write(f"[dylib] {os.path.basename(path)}: NO __objc_classlist section (sections: {sorted({x['sect'] for x in img.sects})[:30]})\n")
    _LOADED[path] = slide
    _NEXT_SLIDE[0] = slide + span + DYLIB_STEP
    sys.stderr.write(f"[dylib] loaded {os.path.basename(path)} at {slide:#x} "
                     f"({len(img.exports())} exports, {len(inits)} initialisers)\n")
    return slide, inits

def load_bundled(emu):
    """Map every candidate dylib, fix it up, register its exports. Returns [init function addresses]."""
    if os.environ.get("ARM2X86_NODYLIBS"): return []
    inits = []
    for path in candidates(emu):
        _, ii = load_one(emu, path)
        inits.extend(ii)
    if _EXPORTS:
        hle.RESOLVERS.append(lambda e, name: _EXPORTS.get(name))
    emu.dylib_exports = dict(_EXPORTS)
    return inits

def load_path(emu, path):
    """Runtime load (NSBundle plugins, dlopen of arm64 code). Returns True on success."""
    try:
        import objc as _objc
        before = set(_objc.CLASSES)
    except Exception:
        before = set()
    slide, inits = load_one(emu, path)
    if slide is None:
        return False
    if _EXPORTS and not getattr(emu, "_dylib_resolver_installed", False):
        hle.RESOLVERS.append(lambda e, name: _EXPORTS.get(name))
        emu._dylib_resolver_installed = True
    emu.dylib_exports = dict(_EXPORTS)
    calls = [(p, None) for p in inits]
    try:
        import objc as _objc
        fresh = [a for a in (getattr(emu, "_fresh_classes", None) or []) if a not in before]
        for addr in fresh:
            c = _objc.CLASSES.get(addr)
            if not c or c.get("is_meta"): continue
            imp = _objc.lookup(c, "load", True)
            if imp:
                calls.append((imp, [addr, _objc.sel_guest(emu, "load")]))
        emu._fresh_classes = [a for a in getattr(emu, "_fresh_classes", []) if a in before]
    except Exception:
        pass
    if calls and hasattr(emu, "begin_callbacks"):
        emu.begin_callbacks(calls, 1)
    return True
