"""Bounce sizes for SDL IO/audio. The host dies (SIGBUS, uncatchable) if libSDL3 is told to write more
bytes than the buffer we handed it. ambiance.ogg is 3006352 bytes; the old path capped the bounce at 256KB."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
import sdl3bridge as sb
from sdl3sigs import SIGS

OGG = 3006352

class E:
    def __init__(self, size):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.uc.mem_map(0x400000000, size)
    def read(self, a, n):
        return self.uc.mem_read(a, n)

def prep(name, raw, size):
    e = E(size)
    argks = SIGS[name][1]
    raw = list(raw)
    sized = sb.prepare_buffers(e, name, argks, raw)
    return sized, raw

def main():
    # 8MB guest buffer, 3MB read: must bounce the whole ogg, NOT region_room's 256KB.
    e = E(8 << 20)
    assert sb.region_room(e, 0x400000000) == (1 << 18), sb.region_room(e, 0x400000000)
    sized, raw = prep("SDL_ReadIO", [0x10, 0x400000000, OGG], 8 << 20)
    assert sized[1] == OGG, sized
    assert raw[2] == OGG, raw
    # Buffer smaller than the request: shrink the size libSDL3 is given, so it cannot write past the bounce.
    sized, raw = prep("SDL_ReadIO", [0x10, 0x400000000, OGG], 64 << 10)
    assert sized[1] == 64 << 10, sized
    assert raw[2] == 64 << 10, raw
    # WriteIO is the same shape.
    sized, raw = prep("SDL_WriteIO", [0x10, 0x400000100, 1000], 8 << 20)
    assert sized[1] == 1000 and raw[2] == 1000
    # Async IO: (io, ptr, offset, size, ...). Clamp size, never the offset.
    sized, raw = prep("SDL_ReadAsyncIO", [0x10, 0x400000000, 0x1000, OGG, 0, 0], 64 << 10)
    assert sized[1] == 64 << 10, sized
    assert raw[2] == 0x1000, raw          # offset untouched
    assert raw[3] == 64 << 10, raw
    # MixAudio: length applies to BOTH byte pointers; the format arg is not a length.
    fmt, ln = 0x8010, 5000
    sized, raw = prep("SDL_MixAudio", [0x400000000, 0x400001000, fmt, ln, 1.0], 8 << 20)
    assert sized[0] == ln and sized[1] == ln, sized
    assert raw[2] == fmt and raw[3] == ln, raw
    sized, raw = prep("SDL_MixAudio", [0x400000000, 0x400001000, fmt, 100000, 1.0], 4096)
    assert sized[0] == 4096 and raw[2] == fmt and raw[3] == 4096, (sized, raw)
    # ConvertAudioSamples: src bytes are arg 1, src_len is arg 2. (The old table used index 2 / a[3].)
    sized, raw = prep("SDL_ConvertAudioSamples", [0x400000000, 0x400010000, OGG, 0x400020000, 0, 0], 8 << 20)
    assert sized == {1: OGG}, sized
    assert raw[2] == OGG and raw[3] == 0x400020000, raw
    # A host (non-guest) pointer is not bounced and its length is left alone.
    sized, raw = prep("SDL_ReadIO", [0x10, 0x2000, OGG], 8 << 20)
    assert sized == {} and raw[2] == OGG, (sized, raw)
    # Negative / sign-extended length becomes 0, not a 2^64 bounce.
    sized, raw = prep("SDL_GetAudioStreamData", [0x10, 0x400000000, -1], 8 << 20)
    assert sized[1] == 0 and raw[2] == 0, (sized, raw)
    print("sdl buffer sizes ok")

if __name__ == "__main__":
    main()
