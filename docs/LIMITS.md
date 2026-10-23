# Process and resource limits: ulimit, systemd-run, cgroups

Neither AppArmor nor seccomp can count processes. Bound runaway process creation
(for example a recursive shell function that keeps spawning copies of itself)
with kernel resource controls:

| Control | Scope | Notes |
|---|---|---|
| `ulimit -u N` / `RLIMIT_NPROC` | per real UID, **all** that user's tasks (threads included) | Soft limit can be raised up to the hard limit; set the hard limit (`ulimit -H -u N`) or use `sandbox-run --nproc N` (soft = hard). Not enforced for root / `CAP_SYS_RESOURCE`. Too low a value breaks your own session: check `ps -u "$USER" -L --no-headers | wc -l` first. |
| cgroup v2 `pids.max` | per cgroup | Counts only tasks in the cgroup; enforced for everyone including root inside it. Preferred. |
| systemd `TasksMax=` | sets `pids.max` for a unit/slice | `systemd/user-slice-limits.conf`. |
| `/etc/security/limits.d/*.conf` | PAM login sessions | `*  hard  nproc  1024` |

## Quick commands

```sh
# Interactive shell with a hard task cap and memory cap, in its own cgroup (no root needed on a systemd user manager):
systemd-run --user --scope -p TasksMax=64 -p MemoryMax=512M bash

# Run one benign bounded probe inside such a scope:
systemd-run --user --scope -p TasksMax=64 python3 tests/seccomp_probe.py spawn 50

# Inspect the limit that was applied:
systemctl --user status 'run-*.scope' | grep -i tasks
cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/pids.max      # path varies by distro

# Shell-level (per-process-tree) caps; make the hard limit stick:
ulimit -H -u 256 ; ulimit -S -u 256
```

If the user manager does not delegate the `pids` controller you will see
"Failed to set property" - use a system-level slice drop-in instead
(`systemd/user-slice-limits.conf`).

Status: these commands are documented, not executed in the authoring sandbox.

## Environment scrub

`sandbox-run` removes `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_DEBUG`,
`LD_PROFILE`, `BASH_ENV`, `ENV`, `SSH_AUTH_SOCK`, and `SSH_AGENT_PID` before
`exec`. That blocks two publicly described implant classes: code injected
through the dynamic linker or a shell startup file named by the environment,
and collection of keys from an SSH agent socket. The scrub does not delete
files in `~/.ssh`. A program the user names on the command line can still
open a key file if the rest of the profile allows that read.

There is no Vault 7 archive on this machine to unpack. The local PDF folder
was removed. This control is the defensive lesson that applies to a shell
sandbox, not a copy of those documents.

## Capability drop and escape syscalls

`sandbox-run` calls `hss_drop_capabilities` in `seccomp/hss_x86_64.S` after
`PR_SET_NO_NEW_PRIVS` and before the seccomp filter is loaded. That assembly
issues `capset` so effective, permitted, and inheritable capabilities are
zero, clears ambient capabilities, and drops bounding-set bits when the
process is allowed to (`PR_CAPBSET_DROP`). An unprivileged user typically
gets `EPERM` on the bounding-set drop; the launch still proceeds because
`no_new_privs` already blocks gaining privileges through a setuid file.
If `capset` itself fails, `sandbox-run` exits.

Both modes also return `EPERM` for syscalls that a normal shell does not
need and that show up in container escapes: `ptrace`, `process_vm_readv`,
`process_vm_writev`, `mount`, `umount2`, `pivot_root`, `unshare`, `setns`,
`personality`, `userfaultfd`, `open_by_handle_at`, `kexec_load`,
`kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `bpf`,
and `perf_event_open`.

This follows the NSA and CISA Kubernetes Hardening Guidance: drop all
capabilities, set no-new-privileges, and restrict syscalls with seccomp.
The filter is still a deny-list with default allow. It is not a full
allow-list profile.

`bin/hardened-shell` execs `sandbox-run` and does not pass the command
through a shell. It rejects `-c` and, with `--check-string`, rejects shell
metacharacters in an untrusted string.
