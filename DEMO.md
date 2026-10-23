# Demo

> **Illustrative vs. verified.** Sections marked **[RAN]** were executed on a Debian 13 x86_64 sandbox
> (kernel 6.12, no AppArmor, no root) and the output is real. Sections marked **[ILLUSTRATIVE]** were
> not run; the expected output is what the profile is designed to produce, not captured output.
> Use a VM.

## A. seccomp launcher **[RAN]**

Build and run the benign probe (`tests/seccomp_probe.py` creates a file and directory in a scratch
dir, then tries to remove or rename them):
```sh
make -C seccomp
scratch=$(mktemp -d /tmp/hss-demo.XXXXXX)
seccomp/sandbox-run --mode strict -- python3 tests/seccomp_probe.py fs "$scratch"
```
```
sandbox-run: mode=strict nproc<=256 no-spawn=1 action=ERRNO(EPERM)
rename file: FAILED errno=1 (EPERM) Operation not permitted
unlink file (unlinkat flags=0): FAILED errno=1 (EPERM) Operation not permitted
rmdir dir  (unlinkat AT_REMOVEDIR / rmdir): FAILED errno=1 (EPERM) Operation not permitted
```
Bounded spawn check (at most 5 `sleep 0` children requested; none can start in strict mode):
```sh
seccomp/sandbox-run --quiet --mode strict -- python3 tests/seccomp_probe.py spawn 5
```
```
spawned=0 requested=5 first_error=errno=1 (EPERM) Operation not permitted
```
RLIMIT_NPROC cap (limit = current tasks + 10; at most 50 children requested) - captured from
`tests/run_seccomp_tests.sh`:
```
spawned=9 requested=50 first_error=errno=11 (EAGAIN) Resource temporarily unavailable
```
Full seccomp test run: `SANDBOX_RUN=seccomp/sandbox-run bash tests/run_seccomp_tests.sh` -> `passed=8 failed=0`.

## B. AppArmor confinement **[ILLUSTRATIVE]**
```sh
sudo install -m 0755 /bin/bash /usr/local/bin/hardened-shell
sudo cp apparmor/usr.local.bin.hardened-shell /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.hardened-shell
sudo aa-status | grep hardened-shell
mkdir -p ~/sandbox-work
/usr/local/bin/hardened-shell
```
Inside the confined shell, normal work in your home directory and `/tmp` works:
```
$ cd ~ && mkdir demo && echo hi > demo/a && cat demo/a
hi
```
System paths are not writable:
```
$ touch /etc/probe
touch: cannot touch '/etc/probe': Permission denied
```
The delete tools are restricted to `~/sandbox-work` (by **path**, not by flags):
```
$ mkdir -p /tmp/test && touch /tmp/test/x
$ rm -rf /tmp/test
rm: cannot remove '/tmp/test/x': Permission denied
$ mkdir -p ~/sandbox-work/t && rm -rf ~/sandbox-work/t && echo removed
removed
```
Log line to look for (`tests/show_denials.sh`):
```
audit: type=1400 ... apparmor="DENIED" operation="unlink" class="file" profile="hardened-shell//rm_family" name="/tmp/test/x" requested_mask="d" denied_mask="d" ...
```

## C. cgroup limit **[ILLUSTRATIVE]**
```sh
systemd-run --user --scope -p TasksMax=64 python3 tests/seccomp_probe.py spawn 50
```
Expect the probe to report `first_error=errno=11 (EAGAIN)` once the scope's task limit is hit, if the
limit is below what it needs; with 64 free slots a 50-child probe may succeed completely - lower
`TasksMax` to see the cap bite.
