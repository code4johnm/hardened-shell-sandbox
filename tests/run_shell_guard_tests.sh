#!/bin/sh
# Checks for bin/hardened-shell. The metacharacter checks do not need root.
# The /bin/true check needs a built seccomp/sandbox-run.
set -u
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HS=$here/../bin/hardened-shell
pass=0
fail=0

check() {
	name=$1
	got=$2
	want=$3
	code=$4
	if [ "$got" = "$want" ] && [ "$code" -eq "$5" ]; then
		echo "PASS  $name"
		pass=$((pass + 1))
	else
		echo "FAIL  $name"
		echo "----- got ($code): $got"
		echo "----- want ($5): $want"
		fail=$((fail + 1))
	fi
}

out=$("$HS" --check-string 'echo hi'); code=$?
check "plain string allowed" "$out" "OK" "$code" 0

out=$("$HS" --check-string 'echo $(id)'); code=$?
check "command substitution rejected" "$out" "REJECT" "$code" 1

out=$("$HS" --check-string 'a;rm -rf /tmp/x'); code=$?
check "semicolon rejected" "$out" "REJECT" "$code" 1

out=$("$HS" --check-string 'use `id`'); code=$?
check "backtick rejected" "$out" "REJECT" "$code" 1

out=$("$HS" -c 'echo hi' 2>&1); code=$?
check "bare -c refused" "$out" "hardened-shell: refusing -c; this wrapper does not evaluate a shell" "$code" 2

out=$("$HS" bash -c 'echo hi' 2>&1); code=$?
check "bash -c refused" "$out" "hardened-shell: refusing -c; a shell would evaluate the next argument" "$code" 2

if [ -x "$here/../seccomp/sandbox-run" ]; then
	"$HS" /bin/true
	code=$?
	if [ "$code" -eq 0 ]; then
		echo "PASS  /bin/true under strict sandbox"
		pass=$((pass + 1))
	else
		echo "FAIL  /bin/true under strict sandbox (exit $code)"
		fail=$((fail + 1))
	fi
else
	echo "FAIL  /bin/true under strict sandbox (sandbox-run not built)"
	fail=$((fail + 1))
fi

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
