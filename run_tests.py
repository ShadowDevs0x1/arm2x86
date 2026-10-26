#!/usr/bin/env python3
"""Runs every test binary through the loader and checks stdout + exit code."""
import subprocess, sys, os
here = os.path.dirname(os.path.abspath(__file__)); os.chdir(here)
CASES = [  # (binary, args, expected exit code, substrings expected in stdout)
    ("hello_arm64",       [],            7, ["hello from arm64 on x86_64"]),
    ("tests/hello",       [],            3, ["argc=1", "puts works"]),
    ("tests/big",         ["a", "b c"],  0, ["arg 2 = b c", "fib(20)=6765", "buf=id-00042-ff-Z len=13",
                                             "sqrt(2)=1.414214 pow(2,10)=1024.0", "u64=18446744073709551615"]),
    ("tests/chained_2",   [],            9, ["bind ok", "rebase ok"]),
    ("tests/chained_6",   [],            9, ["bind ok", "rebase ok"]),
    ("tests/chained_9",   [],            9, ["bind ok", "rebase ok"]),
    ("tests/cxxtest",     [],            0, ["value=-7 pi=3.14159"]),   # ctor-returns-this + std::cout
]
GL = [  # need a display (Linux: xvfb-run -a python3 run_tests.py; on a Mac the window just opens)
    ("tests/gltest", [], 0, ["fragment shader compiled: 1", "center pixel=(255,0,0)", "key callback received: key=65 action=1"],
     {"ARM2X86_FAKE_KEY": "65,1"}),
]
bad = 0
for binary, args, code, expect in CASES:
    if not os.path.exists(binary): print(f"SKIP {binary}"); continue
    r = subprocess.run([sys.executable, "loader.py", binary] + args, capture_output=True, text=True)
    ok = r.returncode == code and all(x in r.stdout for x in expect)
    print(("PASS " if ok else "FAIL ") + binary + ("" if ok else f"  (exit {r.returncode}, want {code})\n{r.stdout}{r.stderr}"))
    bad += not ok
for binary, args, code, expect, env in GL:
    if not os.path.exists(binary): print(f"SKIP {binary}"); continue
    r = subprocess.run([sys.executable, "loader.py", binary] + args, capture_output=True, text=True, env={**os.environ, **env})
    ok = r.returncode == code and all(x in r.stdout for x in expect)
    print(("PASS " if ok else "FAIL ") + binary + ("" if ok else f"  (exit {r.returncode}, want {code})\n{r.stdout}{r.stderr}"))
    bad += not ok
sys.exit(1 if bad else 0)
