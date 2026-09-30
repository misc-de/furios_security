# furios_security

Hardening for the FuriPhone FLX1s: fewer routes into the kernel, whatever
kernel it boots.

None of this replaces kernel updates. It is defence in depth - it takes away
the cheap routes an attacker would use first.

## The four parts

Each switches on its own, each goes away again cleanly.

| part | what it does |
|---|---|
| `sysctl` | unprivileged BPF off, JIT hardened, `dmesg` and kernel pointers closed, `ptrace` limited to one's own children |
| `modules` | the kernel stops auto-loading 14 protocol families, line disciplines and filesystems that nothing here uses |
| `firewall` | one nftables input chain with a default of **drop** — what listens on this phone is reachable from the home network, not from the carrier's |
| `lockout` | the phosh lock screen locks itself after 3 wrong PINs: 5 min, then 10, 15, 30, 60, 120, 240 and 480 from then on; a correct PIN starts over |

Not one of them fixes a vulnerability. They make the cheap paths to one
expensive.

### Why `install`, not `blacklist`

`blacklist` only covers alias resolution. The kernel reaches a protocol family
through `socket(AF_TIPC, …)` and a filesystem through `mount()` regardless —
any process on the phone could pull in a driver nobody has audited in years.
`install <module> /bin/true` is what actually stops it.

### How the lockout works, and what it cannot do

`pam_furios_lockout.so` (in `pam/`, built by `install.sh`) goes into
`common-auth` and `common-account` through `pam-auth-update`, not into
`/etc/pam.d/phosh`, which belongs to another package. It acts only for the
service `phosh`; sudo, SSH and polkit pass through untouched. Every attempt is
counted before the PIN is checked and cleared once the account stack runs,
which phosh reaches only after a correct PIN.

It fails open: an unreadable state, another user, anything it does not
understand, and it steps aside. `secctl apply lockout` loads the module first
and refuses if it does not, because a login stack naming a module PAM cannot
load fails every login, sudo included.

phosh does not show PAM messages (`/* TBD */` in its conversation handler), so
during a lock the right PIN is simply refused. The app's Security tab shows
the time left; `secctl unlock` over SSH ends a lock at once, as yourself. The
state lives in `~/.local/state/furios-lockout/state`.

### Why the firewall asks for your network first

The chain defaults to drop. Switched on without knowing which subnet this
phone is at home in, it would cut the SSH session of whoever switched it on.
So `secctl apply firewall` refuses until `secctl lan` has been answered, and
`secctl lan auto` only ever *suggests* what it read from the interface.

## Install

```sh
git clone https://github.com/misc-de/furios_security
cd furios_security
./install.sh            # NOT with sudo
```

Nothing is switched on by the installer. That is the rule across this
collection, and here it matters most.

```sh
sudo secctl lan auto      # or: sudo secctl lan 192.168.0.0/24
sudo secctl apply all
```

Or use the **Security** tab in the [misc-de app](https://github.com/misc-de/furios_app).

## Use

```
secctl status [--json]     what is on, what is off, what listens where
secctl apply  [part|all]   turn it on
secctl revert [part|all]   turn it off and put back what was there
secctl set <part> on|off   the same, as one switch (the app calls this)
secctl lan <cidr>|auto     the network SSH may be reached from
```

Reading needs no root. Changing does.

## Undo

```sh
sudo secctl revert all     # or ./uninstall.sh, which does this first
```

What comes back is what was written down before the first change, not what
is assumed to have been there. Nothing is guessed:

| change | recorded before the first change | on revert / uninstall |
|---|---|---|
| each sysctl key | its live value (`sysctl_before`) | written back, only while the value is still ours; one changed since is left and named |
| `/etc/sysctl.d/99-furios-hardening.conf`, `/etc/modprobe.d/99-furios-hardening.conf`, `/etc/systemd/system/furios-firewall.service`, `firewall.nft`, `/usr/share/pam-configs/furios-lockout` | that nothing was there (`files_before`) - a file of somebody else's at these paths is refused, never overwritten | removed |
| the table `inet furios`, the unit's enable link | that there was none - one we did not create is refused | deleted, disabled |
| `/etc/pam.d/common-*`, `/var/lib/pam/*` | byte for byte with modes (`pam_before`), and again after our `--enable` (`pam_after`) | `pam-auth-update --remove`, then whatever still differs is written back from the record - all files or none, and only if none was changed by somebody else since |
| everything `install.sh` puts down | one line per path in `/etc/furios-security/installed/list`: `absent`, `saved` (a copy of somebody else's file), `older`, and each directory it created | put back or removed, only while the file is still ours; created directories go when empty |

The records live in `/etc/furios-security/state.json` (secctl) and
`/etc/furios-security/installed/` (install.sh). A record is written once and
never overwritten by a second apply or a reinstall. Where there is none - a
part switched on, or files installed, by a version before 30.9.2026 - revert
and uninstall do what they always did and say that they had nothing to go
by.

`sysctl` apply writes our six keys and nothing else; it no longer runs
`sysctl --system`, which re-reads every file in `/etc/sysctl.d`.

`secctl revert all` goes on past a part that refuses and fails at the end.
`uninstall.sh` stops before removing anything when a part could not be
taken back - secctl and its records stay, so it can still finish;
`./uninstall.sh --force` removes everything anyway.

Not recorded, and why: pam-auth-update's debconf answer (`--remove` takes our
name out of it again); `~/.local/state` and `~/.local`, which the module
creates with 0700 only if an account has neither - uninstall removes
`~/.local/state/furios-lockout` and leaves the parents, which almost every
account has anyway.

The firewall comes up from its own unit, `furios-firewall.service`, which
revert disables and removes. `/etc/nftables.conf` and `nftables.service` are
never touched: the file is a conffile of the nftables package, and changing
it meant a question in the middle of the next nftables update. Versions before
27.9.2026 did rewrite it; applying or reverting now puts the original back
from `/etc/furios-security/nftables.conf.orig`.

One value cannot be taken back on a running kernel:
`kernel.unprivileged_bpf_disabled` is one-way by design, so that an
exploit cannot clear it either. It returns to 0 at the next boot.

## What this does not reach

Written up in [FINDINGS.md](FINDINGS.md), because a security tool that only
lists its wins is misleading. The short version: the in-kernel Bluetooth stack
is in radio range of anybody, and a compromised browser still runs local code
on the phone.

## Tests

```sh
./tests/run-tests.sh       # NEVER with sudo
```

Everything against temporary roots; nothing touches the live firewall, the
kernel or `/etc`. `test-invariant.py` and `test-install-roundtrip.py` check
the rule above from the outside: a picture of the whole root before, and
after on/off or install/uninstall, must be the same. The roundtrip runs
`install.sh` and `uninstall.sh` themselves with `DESTDIR` and `sudo` as
`unshare -r` (root in a user namespace of its own, never the real sudo).

MIT, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
