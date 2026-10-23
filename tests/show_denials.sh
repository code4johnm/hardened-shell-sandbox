#!/usr/bin/env bash
# Show recent AppArmor and seccomp denials.  Read-only.
since=${1:-"10 min ago"}
echo "== AppArmor (kernel ring buffer) =="
sudo dmesg --ctime 2>/dev/null | grep -i 'apparmor="\(DENIED\|ALLOWED\)"' | tail -n 30
echo "== AppArmor (journal) =="
sudo journalctl -k --since "$since" --no-pager 2>/dev/null | grep -i 'apparmor="' | tail -n 30
echo "== auditd (if installed): AVC + SECCOMP records =="
command -v ausearch >/dev/null && sudo ausearch -m AVC,SECCOMP -ts recent 2>/dev/null | tail -n 40
echo "== profile state =="
sudo aa-status 2>/dev/null | grep -i hardened-shell
