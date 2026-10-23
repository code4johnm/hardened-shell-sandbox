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
