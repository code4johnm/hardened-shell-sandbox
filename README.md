# hardened-shell-sandbox

Defensive-only Linux shell hardening: an AppArmor profile, a seccomp launcher, cgroup/systemd limits, and benign tests.

> **Use a VM or disposable machine first.** This repository contains configuration only. It contains no destructive payloads, exploit code or shellcode.

## How to load (under a minute)

Prerequisites (Debian/Ubuntu): `sudo apt install apparmor apparmor-utils libseccomp-dev gcc make`

```sh
git clone https://github.com/code4johnm/hardened-shell-sandbox && cd hardened-shell-sandbox

# 1. AppArmor: install a private copy of bash (profiles attach by resolved path), then load the profile.
sudo install -m 0755 /bin/bash /usr/local/bin/hardened-shell
sudo cp apparmor/usr.local.bin.hardened-shell /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.hardened-shell     # add: sudo aa-complain <profile> first to trial in complain mode
mkdir -p "$HOME/sandbox-work" && /usr/local/bin/hardened-shell

# 2. seccomp launcher: build once, then run any command under the filter.
make -C seccomp
seccomp/sandbox-run --mode strict --nproc 128 -- /bin/true
```

Paths above are the layout of this repository (`apparmor/usr.local.bin.hardened-shell`, `seccomp/sandbox-run`). Unload instructions will be in `ROLLBACK.md`.

## Why this exists

Work for defense-oriented customers means handling sensitive data on shared or semi-trusted hosts. A mistyped or malicious shell command should not be able to damage the system, and a runaway process tree should not exhaust it. This project gives a layered, least-privilege shell environment: path-based filesystem confinement (AppArmor), syscall-level restrictions (seccomp), and resource ceilings (rlimit / cgroups / systemd).

## Coming in subsequent commits

- AppArmor profile (`apparmor/`)
- seccomp filter and `sandbox-run` launcher (`seccomp/`)
- cgroup / systemd limits (`systemd/`, `docs/`)
- Test plan: benign test scripts (`tests/`)
- `DEMO.md` walkthrough
- `ROLLBACK.md`
- Full README with honest limits, LICENSE (MIT)
