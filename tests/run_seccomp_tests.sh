#!/usr/bin/env bash
# Benign seccomp tests.  Needs: built seccomp/sandbox-run, python3.  No root needed.
#   SANDBOX_RUN=/path/to/sandbox-run ./tests/run_seccomp_tests.sh
set -u
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SR=${SANDBOX_RUN:-$here/../seccomp/sandbox-run}
PROBE=$here/seccomp_probe.py
[ -x "$SR" ] || { echo "build sandbox-run first: make -C seccomp" >&2; exit 2; }

pass=0; fail=0
check() { # name, command-output, regex
  if grep -Eq "$3" <<<"$2"; then echo "PASS  $1"; pass=$((pass+1));
  else echo "FAIL  $1"; echo "----- got:"; echo "$2"; echo "-----"; fail=$((fail+1)); fi
}

scratch=$(mktemp -d /tmp/hss-seccomp.XXXXXX)
trap 'rm -rf "$scratch"' EXIT        # cleanup runs OUTSIDE the filter

# 1. strict: unlink / rmdir / rename all return EPERM.
out=$("$SR" --quiet --mode strict -- python3 "$PROBE" fs "$scratch" 2>&1)
check "strict: rename -> EPERM"  "$out" 'rename file: FAILED errno=1 \(EPERM\) Operation not permitted'
check "strict: unlink -> EPERM"  "$out" 'unlink file.*: FAILED errno=1 \(EPERM\) Operation not permitted'
check "strict: rmdir  -> EPERM"  "$out" 'rmdir dir.*: FAILED errno=1 \(EPERM\) Operation not permitted'
[ -e "$scratch/file.txt" ] && echo "INFO  scratch file still present after strict run (expected)"

# 2. workdir-safe: files can be removed, directories cannot.
rm -f "$scratch"/file.txt* ; rmdir "$scratch/subdir" 2>/dev/null
out=$("$SR" --quiet --mode workdir-safe --workdir "$scratch" -- python3 "$PROBE" fs "$scratch" 2>&1)
check "workdir-safe: unlink file allowed" "$out" 'unlink file.*: OK'
check "workdir-safe: rmdir -> EPERM"      "$out" 'rmdir dir.*: FAILED errno=1 \(EPERM\)'

# 3. strict also forbids creating new processes (bounded probe, max 50).
out=$("$SR" --quiet --mode strict -- python3 "$PROBE" spawn 5 2>&1)
check "strict: spawn -> EPERM, 0 children" "$out" 'spawned=0 .*errno=1 \(EPERM\)'

# 4. RLIMIT_NPROC bounds spawning in workdir-safe (limit = current tasks + 10).
base=$(ps -u "$(id -u)" -L --no-headers | wc -l)
out=$("$SR" --quiet --mode workdir-safe --workdir "$scratch" --nproc $((base + 10)) \
        -- python3 "$PROBE" spawn 50 2>&1)
check "nproc cap: fewer than 50 children, EAGAIN" "$out" 'spawned=([0-9]|[1-3][0-9]|4[0-9]) requested=50 first_error=errno=11 \(EAGAIN\)'
echo "INFO  nproc test detail: baseline_tasks=$base limit=$((base+10)) -> $out"

# 5. --log mode: nothing is blocked (observe-only).
rm -f "$scratch"/file.txt* ; rmdir "$scratch/subdir" 2>/dev/null
out=$("$SR" --quiet --mode strict --log -- python3 "$PROBE" fs "$scratch" 2>&1)
check "--log: unlink allowed (logged only)" "$out" 'unlink file.*: OK'

# 5b. Injection and SSH-agent variables do not reach the command.
out=$(LD_PRELOAD=/tmp/hss-not-a-library.so \
	LD_LIBRARY_PATH=/tmp/hss-lib \
	BASH_ENV=/tmp/hss-bashrc \
	SSH_AUTH_SOCK=/tmp/hss-agent.sock \
	SSH_AGENT_PID=1 \
	"$SR" --quiet --mode strict -- python3 -c 'import os
for k in ("LD_PRELOAD","LD_LIBRARY_PATH","BASH_ENV","SSH_AUTH_SOCK","SSH_AGENT_PID"):
    print("%s=%s" % (k, os.environ.get(k, "")))' 2>&1)
check "env scrub: LD_PRELOAD cleared" "$out" '^LD_PRELOAD=$'
check "env scrub: LD_LIBRARY_PATH cleared" "$out" '^LD_LIBRARY_PATH=$'
check "env scrub: BASH_ENV cleared" "$out" '^BASH_ENV=$'
check "env scrub: SSH_AUTH_SOCK cleared" "$out" '^SSH_AUTH_SOCK=$'
check "env scrub: SSH_AGENT_PID cleared" "$out" '^SSH_AGENT_PID=$'

# 6. Raw assembly probes: escape syscalls return EPERM, and capabilities are clear.
make -C "$here/../seccomp" ../tests/escape_probe >/dev/null
out=$("$SR" --quiet --mode strict -- "$here/escape_probe" 2>&1)
for name in ptrace unshare mount umount2 pivot_root setns personality userfaultfd \
	open_by_handle_at process_vm_writev kexec_file_load bpf init_module \
	delete_module perf_event_open; do
	check "escape: $name -> EPERM" "$out" "$name: FAILED errno=1"
done
out=$("$SR" --quiet --mode workdir-safe --workdir "$scratch" -- "$here/escape_probe" 2>&1)
check "workdir-safe: ptrace -> EPERM" "$out" 'ptrace: FAILED errno=1'
caps=$("$SR" --quiet --mode strict -- python3 -c 'print(open("/proc/self/status").read())' 2>&1)
check "CapEff is zero" "$caps" 'CapEff:[[:space:]]+0+$'
check "CapPrm is zero" "$caps" 'CapPrm:[[:space:]]+0+$'

echo; echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
