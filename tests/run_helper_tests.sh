#!/usr/bin/env bash
# Benign tests for the C and assembly helpers behind sandbox-run, and for
# the new launcher options. Needs a built seccomp/ (make -C seccomp). No root.
set -u
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SR=${SANDBOX_RUN:-$here/../seccomp/sandbox-run}
ST=$here/../tools/hss-status
[ -x "$SR" ] || { echo "build sandbox-run first: make -C seccomp" >&2; exit 2; }
make -C "$here/../seccomp" ../tests/helper_selftest ../tools/hss-status >/dev/null || exit 2

pass=0; fail=0
check() { # name, output, regex
  if grep -Eq "$3" <<<"$2"; then echo "PASS  $1"; pass=$((pass+1));
  else echo "FAIL  $1"; echo "----- got:"; echo "$2"; echo "-----"; fail=$((fail+1)); fi
}

# 1. Unit tests of the helpers, unconfined.
out=$("$here/helper_selftest" 2>&1)
check "helper unit tests" "$out" 'passed=[0-9]+ failed=0'

# 2. Under sandbox-run the child is confined and holds only fds 0-2,
#    even when the caller leaks extra descriptors (7 and 9 here).
out=$("$SR" --quiet --mode strict -- "$here/helper_selftest" --confined 2>&1 7</dev/null 9</dev/null)
check "confined self-test (fds closed)" "$out" 'passed=[0-9]+ failed=0'
out=$("$SR" --quiet --mode strict --keep-fds -- "$here/helper_selftest" --confined 2>&1 7</dev/null)
check "--keep-fds keeps inherited fds" "$out" 'FAIL  only fds 0-2 inherited'

# 3. hss-status: confined inside, not confined outside.
out=$("$SR" --quiet --mode strict -- "$ST" --require 2>&1)
check "hss-status: confined yes" "$out" '^confined +yes$'
check "hss-status: no_new_privs 1" "$out" '^no_new_privs +1$'
check "hss-status: seccomp filter" "$out" '^seccomp +2 \(filter\)$'
check "hss-status: core 0" "$out" '^RLIMIT_CORE +soft=0 hard=0$'
if "$ST" --require >/dev/null 2>&1 && [ "$(awk '/^Seccomp:/{print $2}' /proc/self/status)" = 0 ]; then
  echo "FAIL  hss-status --require passed outside the sandbox"; fail=$((fail+1))
else
  echo "PASS  hss-status --require fails or host already confined"; pass=$((pass+1))
fi

# 4. New rlimit options: soft = hard, and they bite.
out=$("$SR" --quiet --mode strict --nofile 64 --fsize 1M --as 1G -- "$ST" 2>&1)
check "--nofile 64" "$out" '^RLIMIT_NOFILE +soft=64 hard=64$'
check "--fsize 1M" "$out" '^RLIMIT_FSIZE +soft=1048576 hard=1048576$'
check "--as 1G" "$out" '^RLIMIT_AS +soft=1073741824 hard=1073741824$'

scratch=$(mktemp -d /tmp/hss-helpers.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
out=$("$SR" --quiet --mode workdir-safe --workdir "$scratch" --fsize 4K -- \
      python3 -c 'open("big","wb").write(b"x"*8192)' 2>&1)
check "--fsize 4K: 8 KiB write fails EFBIG" "$out" 'Errno 27'

# 5. Bad option values are refused before anything runs.
out=$("$SR" --nofile 2 -- true 2>&1)
check "--nofile 2 refused" "$out" 'needs a number >= 4'
out=$("$SR" --fsize 10Q -- true 2>&1)
check "--fsize 10Q refused" "$out" 'bad --fsize'
out=$("$SR" --as 1M -- true 2>&1)
check "--as 1M refused" "$out" 'at least 16M'

echo; echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
