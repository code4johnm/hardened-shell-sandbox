# hardened-shell-sandbox

Defensive-only Linux shell hardening: an AppArmor profile, a seccomp launcher (`sandbox-run`), cgroup/systemd limits, and benign tests.

> **Use a VM or disposable machine first.** This repository is configuration and benign test code only. It contains no destructive command payloads, exploit code or shellcode, and its tests only touch scratch directories and start at most 50 short-lived `sleep 0` children.

## How to load (under a minute)

Prerequisites (Debian/Ubuntu): `sudo apt install apparmor apparmor-utils libseccomp-dev gcc make python3`

```sh
git clone https://github.com/code4johnm/hardened-shell-sandbox && cd hardened-shell-sandbox

# 1. AppArmor. Profiles attach by resolved path, so install a private copy of bash, then load.
sudo install -m 0755 /bin/bash /usr/local/bin/hardened-shell
sudo cp apparmor/usr.local.bin.hardened-shell /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.hardened-shell
#    (trial first?  sudo aa-complain /etc/apparmor.d/usr.local.bin.hardened-shell)
mkdir -p "$HOME/sandbox-work" && /usr/local/bin/hardened-shell

# 2. seccomp launcher: build once, then run any command under the filter.
make -C seccomp
seccomp/sandbox-run --mode strict --nproc 128 -- /bin/true
seccomp/sandbox-run --mode workdir-safe --workdir "$HOME/sandbox-work" -- bash
```

(Files are uploaded without the executable bit; run scripts with `bash tests/<script>.sh`.)

Unload: see [ROLLBACK.md](ROLLBACK.md). Walkthrough: [DEMO.md](DEMO.md).

## Why this exists

Work for defense-oriented customers means handling sensitive data on shared or semi-trusted hosts. A mistyped or malicious shell command should not be able to damage the system, and a runaway process tree should not exhaust it. This project gives a layered, least-privilege shell: path-based filesystem confinement (AppArmor), syscall restrictions (seccomp), and resource ceilings (rlimit, cgroups, systemd).

## Layout

| Path | What |
|---|---|
| `apparmor/usr.local.bin.hardened-shell` | AppArmor profile for a copy of bash, plus child profile `rm_family` for `rm`, `rmdir`, `unlink`, `shred` |
| `seccomp/sandbox-run.c`, `seccomp/Makefile` | libseccomp launcher: `no_new_privs`, `RLIMIT_NPROC`, seccomp filter, `execvp` |
| `seccomp/oci-seccomp.json`, `seccomp/oci-seccomp-dirs-only.json` | Same filters as OCI/Docker seccomp profiles (`docker run --security-opt seccomp=...`) |
| `systemd/user-slice-limits.conf` | `TasksMax`/`MemoryMax` drop-in for `user-.slice` |
| `systemd/hardened-shell@.service` | Example unit: `TasksMax`, `MemoryMax`, `SystemCallFilter`, `ProtectSystem=strict` |
| `docs/LIMITS.md` | `ulimit -u`, `systemd-run --user --scope -p TasksMax=64`, cgroup `pids.max` |
| `tests/` | Benign test scripts and probes |
| `DEMO.md`, `ROLLBACK.md`, `LICENSE` (MIT) | |

## What it blocks

**AppArmor (`hardened-shell` profile)**
* Writes (create, delete, rename, link, lock) to `/`, `/etc`, `/boot`, `/usr`, `/bin`, `/sbin`, `/lib*`, `/opt`, `/srv`, `/root`, `/sys`, `/proc/sys`, and `/var` except `/var/tmp` (listed subdirs `lib log cache spool backups mail opt www run lock` are denied explicitly; everything unlisted is denied by default).
* Normal work (read, write, delete) under `$HOME` and `/tmp` by the shell and ordinary tools; scratch dirs (`/tmp`, `/var/tmp`, `/dev/shm`) are not executable.
* `rm`, `rmdir`, `unlink`, `shred` run in child profile `rm_family`, which may modify **only** `$HOME/sandbox-work/**`. Elsewhere, including `/tmp` and the rest of `$HOME`, they get `EACCES` ("Permission denied").
* Capabilities (`sys_admin`, `sys_ptrace`, `dac_override`, `setuid`, ...), `ptrace`, mount/umount/pivot_root, raw/packet sockets; execution of `sudo`, `su`, `mount`, `chroot`, `unshare`, `nsenter`, `strace`, `gdb`, and anything in `/sbin`; reading `/etc/shadow`, `~/.ssh`, `~/.gnupg`.
* `RLIMIT_NPROC` ceiling (256 for the shell, 64 for rm), `nofile`, `fsize`, `core`.

**seccomp (`sandbox-run`)**
* `strict`: `unlink`, `unlinkat`, `rmdir`, `rename`, `renameat`, `renameat2` return `EPERM`; new processes are refused (`fork`, `vfork`, `clone` without `CLONE_THREAD` return `EPERM`, `clone3` returns `ENOSYS` so libc falls back to `clone`). Threads still work.
* `workdir-safe`: `chdir` into the work dir; files can be unlinked but directories cannot (`rmdir`, `unlinkat` with `AT_REMOVEDIR`) so a directory tree cannot be removed. Spawning allowed, bounded by `--nproc`; add `--no-spawn` to forbid it.
* `--log`: replace the block with `SCMP_ACT_LOG` (allow, but write an audit record) to observe before enforcing.
* A blocked call fails with `EPERM` and the program keeps running (not killed). Tools print "Operation not permitted".

## What it does NOT block (honest limits)

* **AppArmor cannot inspect argv.** It cannot tell `rm -r` from `rm`, or `-f` from no flag. "Recursive removal against system paths" is stopped by *path-based* write denies, which also stop plain `rm` there. If `rm` is renamed or a different tool is used (`find -delete`, `python`, `mv`, `perl`), the main profile still allows deletion under `$HOME` and `/tmp`, because AppArmor has no separate "unlink" permission: delete is part of `w`. Use the strictest profile variant (shrink the `$HOME/**` and `/tmp/**` write rules to `$HOME/sandbox-work/**`) if you need to protect those too.
* **AppArmor cannot detect recursive shell function definitions** or any other code pattern. Runaway process creation (for example a recursive shell function that keeps spawning copies of itself) is bounded only by resource limits: `RLIMIT_NPROC` (per real UID, not root), cgroup `pids.max`, or systemd `TasksMax` ([docs/LIMITS.md](docs/LIMITS.md)).
* **seccomp is stateless.** It cannot count processes or enforce "at most N forks". The launcher can only forbid process creation outright, and `RLIMIT_NPROC` supplies the count. seccomp also cannot read path arguments, so it cannot permit deletion in one directory and refuse it in another; combine it with AppArmor or a mount namespace.
* The seccomp filter is a deny-list (default allow). Other syscalls that can destroy data (`truncate`, `open` with `O_TRUNC`, `write`) are not filtered. `renameat2` is blocked entirely in `strict` mode, since flag-conditional allow rules are not expressible in a default-allow filter.
* Not a defense against a root-level attacker or a kernel exploit. `RLIMIT_NPROC` is ignored for root.
* The shell must be started as `/usr/local/bin/hardened-shell`; a user who can run plain `/bin/bash` is not confined. Confine login shells/SSH accordingly (`chsh`, `ForceCommand`).
* x86_64 tested only. The `clone` argument filter assumes the x86_64/aarch64 argument order (flags first); verify on other architectures.

## Test overview

| Test | What | Status |
|---|---|---|
| `tests/run_seccomp_tests.sh` | strict: `rename`/`unlink`/`rmdir` -> `EPERM`; workdir-safe: file unlink OK, `rmdir` -> `EPERM`; strict: spawn -> `EPERM`; `--nproc` cap -> `EAGAIN` (<=50 children); `--log` mode | **Verified** on the authoring box (Debian 13, x86_64, kernel 6.12, libseccomp 2.6.0): `passed=8 failed=0` |
| `sandbox-run.c` compile (`gcc -Wall -Wextra -Wpedantic`, static libseccomp 2.6.0) | | **Verified**, no warnings |
| `shellcheck tests/*.sh` | | **Verified** clean (shellcheck 0.11.0) |
| `python3 -m py_compile tests/seccomp_probe.py`; JSON validity of `seccomp/*.json` | | **Verified** |
| AppArmor profile syntax (`apparmor_parser -Q -K -T`, apparmor 4.1.0 parser, kernel load skipped) | | **Verified**: parses without errors |
| `tests/apparmor_tests.sh` (load profile, `aa-status`, `rm` in `/tmp` blocked / in `~/sandbox-work` allowed, system paths not writable, home work OK) | needs AppArmor kernel + sudo | **UNTESTED** (no AppArmor or root on the authoring box); run it in a VM |
| Profile behaviour when loaded into a kernel (rule precedence, `rm_family` transition, `abstractions/bash` completeness) | | **UNTESTED**. Expect to tune using complain mode and `tests/show_denials.sh` |
| `systemd/*` files, `systemd-run` examples | | **UNTESTED** |
| `seccomp/oci-seccomp*.json` loaded by a container runtime | | **UNTESTED** |

Run: `make -C seccomp && bash tests/run_seccomp_tests.sh`, then in a VM `bash tests/apparmor_tests.sh` (set `COMPLAIN=1` for the first run). See denials with `tests/show_denials.sh` (`dmesg`, `journalctl -k`, `ausearch -m AVC,SECCOMP`).

## License

MIT. See [LICENSE](LICENSE).
