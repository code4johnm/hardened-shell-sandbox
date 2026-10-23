#!/usr/bin/env bash
# shellcheck disable=SC2015
# AppArmor tests.  Needs a host with AppArmor enabled, apparmor-utils and sudo.
# Run in a VM.  Steps 0-1 change system state (load profile); see ROLLBACK.md.
#   ./tests/apparmor_tests.sh            # loads the profile in ENFORCE mode
#   COMPLAIN=1 ./tests/apparmor_tests.sh # loads in complain mode (nothing blocked, denials logged)
# STATUS: written but NOT executed in the authoring sandbox (no AppArmor/root there).
set -u
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROFILE_SRC=$here/../apparmor/usr.local.bin.hardened-shell
PROFILE_DST=/etc/apparmor.d/usr.local.bin.hardened-shell
SHELL_BIN=/usr/local/bin/hardened-shell
WORK=$HOME/sandbox-work
SCRATCH=/tmp/hss-apparmor-test       # benign scratch dir for the "rm -rf /tmp/test" style check

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
hs()  { "$SHELL_BIN" -c "$1" 2>&1; }          # run a command inside the confined shell

# --- 0. install + load ------------------------------------------------------
sudo install -m 0755 /bin/bash "$SHELL_BIN"
sudo apparmor_parser -QT -K "$PROFILE_SRC" && ok "profile syntax check (apparmor_parser)" || bad "syntax check"
sudo cp "$PROFILE_SRC" "$PROFILE_DST"
sudo apparmor_parser -r "$PROFILE_DST" && ok "profile loaded (apparmor_parser -r)" || bad "load"
[ -n "${COMPLAIN:-}" ] && sudo aa-complain "$PROFILE_DST"
sudo aa-status | grep -q 'hardened-shell' && ok "aa-status lists hardened-shell" || bad "aa-status"
mkdir -p "$WORK"

if [ -n "${COMPLAIN:-}" ]; then
  echo "complain mode: expectations below for 'blocked' cases will FAIL by design; check logs instead."
fi

# --- 1. normal work in HOME and /tmp is allowed -------------------------------
out=$(hs "cd \"$HOME\" && mkdir -p hss-home-test && echo hello > hss-home-test/a.txt && touch hss-home-test/b && cat hss-home-test/a.txt")
[ "$out" = "hello" ] && ok "home: mkdir/echo/touch/cat work" || { bad "home work"; echo "$out"; }
out=$(hs "mkdir -p $SCRATCH && echo x > $SCRATCH/f && cat $SCRATCH/f")
[ "$out" = "x" ] && ok "/tmp: create + read work" || { bad "/tmp work"; echo "$out"; }

# --- 2. writes to system paths are denied ---------------------------------------
for p in /etc/hss-probe /usr/hss-probe /boot/hss-probe /hss-probe /var/lib/hss-probe; do
  out=$(hs "touch $p")
  grep -qi 'permission denied' <<<"$out" && ok "write denied: $p" || { bad "write NOT denied: $p"; echo "$out"; }
done
out=$(hs "touch /var/tmp/hss-probe && echo allowed")
grep -q allowed <<<"$out" && ok "/var/tmp writable" || bad "/var/tmp"
sudo rm -f /var/tmp/hss-probe

# --- 3. rm family: blocked outside the sandbox work dir -------------------------
# NOTE: this blocks by PATH (child profile rm_family), not by flags.
out=$(hs "rm -rf $SCRATCH")
grep -qi 'permission denied' <<<"$out" && [ -d "$SCRATCH" ] \
  && ok "rm -rf $SCRATCH denied, directory still exists" || { bad "rm outside work dir"; echo "$out"; }
out=$(hs "rm $HOME/hss-home-test/b")
grep -qi 'permission denied' <<<"$out" && ok "rm in \$HOME (outside sandbox-work) denied" || bad "rm in HOME"

# --- 4. rm family: allowed inside $HOME/sandbox-work ----------------------------
out=$(hs "mkdir -p $WORK/t/sub && touch $WORK/t/sub/f && rm -rf $WORK/t && echo done")
[ "$out" = "done" ] && [ ! -e "$WORK/t" ] && ok "rm -rf inside ~/sandbox-work allowed" || { bad "rm inside work dir"; echo "$out"; }

# --- 5. privileged tools / tracing denied ------------------------------------------
out=$(hs "sudo -n true"); grep -qi 'permission denied' <<<"$out" && ok "sudo exec denied" || bad "sudo exec"
out=$(hs "strace -V");    grep -qi 'permission denied' <<<"$out" && ok "strace exec denied" || bad "strace exec"

# --- 6. bounded process-spawn check under the shell's rlimit ------------------------
if [ -x "$WORK/seccomp_probe.py" ] || cp "$here/seccomp_probe.py" "$WORK/"; then
  out=$(hs "python3 $WORK/seccomp_probe.py spawn 50")
  echo "INFO  spawn probe inside confined shell: $out"
  grep -q 'spawned=' <<<"$out" && ok "bounded spawn probe ran (<=50 children)" || bad "spawn probe"
fi

# --- cleanup (unconfined, scratch only) -------------------------------------------------
rm -rf "$SCRATCH" "$HOME/hss-home-test"
echo; echo "passed=$pass failed=$fail"
echo "Denials: sudo dmesg | grep -i 'apparmor=\"DENIED\"' ; sudo journalctl -k --since '10 min ago' | grep -i apparmor ; sudo ausearch -m AVC -ts recent"
[ "$fail" -eq 0 ]
