# Rollback and recovery

Do this in order of least to most drastic. The confined shell is a *separate copy* of bash at
`/usr/local/bin/hardened-shell`; your normal login shell and `/bin/bash` are never confined, so you
cannot lock yourself out of the machine by loading this profile unless you changed your login shell
to `hardened-shell`.

## 0. Trial first: complain mode
```sh
sudo aa-complain /etc/apparmor.d/usr.local.bin.hardened-shell   # log, do not block
# ... use the shell, then review what would have been denied:
tests/show_denials.sh
sudo aa-enforce  /etc/apparmor.d/usr.local.bin.hardened-shell   # switch to enforcing when happy
```

## 1. Unload the profile (keeps the file)
```sh
sudo apparmor_parser -R /etc/apparmor.d/usr.local.bin.hardened-shell
sudo aa-status | grep hardened-shell || echo "unloaded"
```

## 2. Disable persistently (survives reboot, keeps the file)
```sh
sudo aa-disable /etc/apparmor.d/usr.local.bin.hardened-shell     # symlinks into /etc/apparmor.d/disable/
# manual equivalent:
sudo ln -s /etc/apparmor.d/usr.local.bin.hardened-shell /etc/apparmor.d/disable/
```

## 3. Remove everything
```sh
sudo apparmor_parser -R /etc/apparmor.d/usr.local.bin.hardened-shell 2>/dev/null
sudo rm -f /etc/apparmor.d/usr.local.bin.hardened-shell /etc/apparmor.d/disable/usr.local.bin.hardened-shell
sudo rm -f /usr/local/bin/hardened-shell
sudo rm -f /etc/systemd/system/user-.slice.d/50-hardened-shell.conf /etc/systemd/system/hardened-shell@.service
sudo systemctl daemon-reload
rmdir "$HOME/sandbox-work" 2>/dev/null     # only if empty
make -C seccomp clean                       # removes the built sandbox-run launcher
```
seccomp filters are per-process and are never persistent: they disappear when the launched process
exits. Nothing to unload. A filter, once loaded into a process, cannot be removed from that process.

## 4. Recovery if locked out
* Your login shell was set to `hardened-shell` and it is too restrictive: log in via console/SSH with
  an explicit command (`ssh host /bin/bash`), or from the VM console / recovery mode, then
  `sudo chsh -s /bin/bash <user>` and run step 1.
* AppArmor itself misbehaving: boot with `apparmor=0` on the kernel command line (one-off), or from
  recovery mode run `systemctl stop apparmor` / step 2.
* systemd drop-in made sessions fail (TasksMax too low): remove
  `/etc/systemd/system/user-.slice.d/50-hardened-shell.conf`, `systemctl daemon-reload`, log in again.
* `RLIMIT_NPROC` too low ("Resource temporarily unavailable" on fork): open a new session; limits are
  per-process and not inherited by new logins.
* Always keep a second root/console session open while testing, and snapshot the VM beforehand.
