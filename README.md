# arm2x86 - run simple arm64 / arm64e macOS programs on an Intel Mac

    pip3 install unicorn glfw sdl3
    pip3 install capstone
    pip3 install pysdl3 && python3 gen_sdl3sigs.py
    python3 loader.py --kern26 path/to/arm64-binary [args...]
    python3 run_tests.py            # on Linux: xvfb-run -a python3 run_tests.py

What works: thin/fat Mach-O (arm64 and arm64e slices), classic rebase/bind opcodes,
chained fixups (all common formats), argc/argv/envp, ~100 libSystem functions (hle.py),
raw BSD syscalls, arm64e PAC instructions, and now:

* gfx.py   - GLFW + OpenGL bridge. The guest's glfw*/gl* calls run on the HOST's real GLFW and
             OpenGL driver (hardware accelerated on your Mac). ~200 GL entry points, window/input
             callbacks (key, mouse, cursor, scroll, char, resize, close) re-enter the guest.
* objc.py   - ObjC/Metal bridge: guest objc_msgSend is forwarded to the HOST's real ObjC runtime via ctypes
             (Mac only). Marshals by method type encoding (structs, floats, blocks, CFStrings, buffer.contents).
             Not yet: guest-DEFINED classes (AppDelegate), NSApplicationMain/run loop, threads.
* hostsys.py - env, atexit, single-thread pthread shims. ARM2X86_LENIENT=1 keeps going past unimplemented imports.
* libcxx.py - std::string (Apple arm64 layout), to_string, operator new/delete.

Debug switches (environment variables):
    ARM2X86_VERBOSE=1        list imports with no emulation yet; print window titles
    ARM2X86_TRACE=1          log every emulated call
    ARM2X86_SHOT=N,out.png   save the framebuffer after N frames, then exit
    ARM2X86_FAKE_KEY=k,a     inject one key event (test hook)

Not yet: loading apps that use advanced APIs
