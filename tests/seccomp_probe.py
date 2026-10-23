#!/usr/bin/env python3
"""Benign probe used by the seccomp tests.  It only touches a scratch directory
you pass in, and spawns at most 50 short-lived `sleep 0` children.

  seccomp_probe.py fs    SCRATCH_DIR   try unlink / rmdir / rename on scratch items
  seccomp_probe.py spawn N             try to start N (max 50) `sleep 0` children
"""
import errno
import os
import subprocess
import sys

HARD_CAP = 50


def attempt(label, fn):
    try:
        fn()
        print(f"{label}: OK")
    except OSError as e:
        print(f"{label}: FAILED errno={e.errno} ({errno.errorcode.get(e.errno, '?')}) {e.strerror}")


def probe_fs(scratch):
    f = os.path.join(scratch, "file.txt")
    d = os.path.join(scratch, "subdir")
    with open(f, "w") as fh:          # creating files is never filtered
        fh.write("scratch\n")
    os.makedirs(d, exist_ok=True)
    attempt("rename file", lambda: os.rename(f, f + ".moved"))
    g = f + ".moved" if os.path.exists(f + ".moved") else f
    attempt("unlink file (unlinkat flags=0)", lambda: os.unlink(g))
    attempt("rmdir dir  (unlinkat AT_REMOVEDIR / rmdir)", lambda: os.rmdir(d))


def probe_spawn(n):
    n = max(1, min(int(n), HARD_CAP))
    kids, first_err = [], None
    for _ in range(n):
        try:
            kids.append(subprocess.Popen(["sleep", "0"]))   # zombies count until reaped
        except OSError as e:
            first_err = f"errno={e.errno} ({errno.errorcode.get(e.errno, '?')}) {e.strerror}"
            break
    for k in kids:
        k.wait()
    print(f"spawned={len(kids)} requested={n} first_error={first_err}")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "fs":
        probe_fs(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "spawn":
        probe_spawn(sys.argv[2])
    else:
        sys.exit(__doc__)
