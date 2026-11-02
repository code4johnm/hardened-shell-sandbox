#!/usr/bin/env bash
# Benign tests for cgroup/hss-cgroup. No root needed for the argument checks.
#
# Live tests run only when HSS_CGROUP_PARENT names a cgroup v2 directory you
# may create children in, with pids and memory in its cgroup.subtree_control,
# for example a systemd delegated scope:
#   systemd-run --user --scope -p Delegate=yes -- bash
#   HSS_CGROUP_PARENT=/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/self/cgroup) \
#       bash tests/run_cgroup_tests.sh
# (Inside that scope, move the shell into a leaf first; see docs/LIMITS.md.)
set -u
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CG=${HSS_CGROUP:-$here/../cgroup/hss-cgroup}
PROBE=$here/seccomp_probe.py
[ -x "$CG" ] || { echo "build hss-cgroup first: make -C cgroup" >&2; exit 2; }

pass=0; fail=0
check() { # name, output, regex
  if grep -Eq "$3" <<<"$2"; then echo "PASS  $1"; pass=$((pass+1));
  else echo "FAIL  $1"; echo "----- got:"; echo "$2"; echo "-----"; fail=$((fail+1)); fi
}
check_rc() { # name, got, want
  if [ "$2" -eq "$3" ]; then echo "PASS  $1"; pass=$((pass+1));
  else echo "FAIL  $1 (rc=$2, want $3)"; fail=$((fail+1)); fi
}

# 1. Argument validation. None of these touch a cgroup.
out=$("$CG" --parent /tmp --name ../escape -- true 2>&1); rc=$?
check_rc "name with .. rejected" "$rc" 2
check "name error message" "$out" 'must be 1-64'
out=$("$CG" --parent /tmp --name a/b -- true 2>&1); rc=$?
check_rc "name with slash rejected" "$rc" 2
out=$("$CG" --parent /tmp --name .hidden -- true 2>&1); rc=$?
check_rc "hidden name rejected" "$rc" 2
out=$("$CG" --parent /tmp --name ok --pids-max 0 -- true 2>&1); rc=$?
check_rc "pids-max 0 rejected" "$rc" 2
out=$("$CG" --parent /tmp --name ok --memory-max 12X -- true 2>&1); rc=$?
check_rc "bad memory size rejected" "$rc" 2
out=$("$CG" --parent /tmp --name ok --cpu-max 10 -- true 2>&1); rc=$?
check_rc "cpu quota below 1000us rejected" "$rc" 2
out=$("$CG" --parent /tmp --name ok -- true 2>&1); rc=$?
check_rc "non-cgroup parent rejected" "$rc" 1
check "non-cgroup parent message" "$out" 'not on a cgroup v2 filesystem'
out=$("$CG" --parent /tmp --name ok 2>&1); rc=$?
check_rc "missing command rejected" "$rc" 2

# 2. Live tests against a delegated parent.
P=${HSS_CGROUP_PARENT:-}
if [ -z "$P" ] || [ ! -w "$P" ]; then
  echo "SKIP  live cgroup tests (set HSS_CGROUP_PARENT to a writable cgroup v2 dir)"
else
  name="hss-test-$$"
  out=$("$CG" --parent "$P" --name "$name" --pids-max 8 -- python3 "$PROBE" spawn 50 2>&1)
  check "pids.max=8 stops spawning with EAGAIN" "$out" 'spawned=[0-7] requested=50 first_error=errno=11'
  gone=1; [ -e "$P/$name" ] && gone=0
  check_rc "cgroup removed after supervise run" "$gone" 1

  # shellcheck disable=SC2016  # expanded by the inner sh, on purpose
  out=$("$CG" --parent "$P" --name "$name" --memory-max 64M --pids-max 16 \
        -- sh -c 'cat "/sys/fs/cgroup$(sed -n "s/^0:://p" /proc/self/cgroup)/memory.max"' 2>&1)
  check "memory.max visible inside" "$out" '^67108864$'

  "$CG" --parent "$P" --name "$name" -- sh -c 'exit 7'; rc=$?
  check_rc "child exit status propagated" "$rc" 7

  mkdir "$P/$name" 2>/dev/null
  out=$("$CG" --parent "$P" --name "$name" -- true 2>&1); rc=$?
  check_rc "existing cgroup name refused" "$rc" 1
  rmdir "$P/$name" 2>/dev/null
fi

echo; echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
