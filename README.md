# furios_security

Hardening for a phone whose kernel has stopped receiving security fixes.

The FuriPhone FLX1s runs **4.19.325**. That is not just an old kernel, it is
the *last* release of the 4.19 series: upstream declared it end of life in
December 2024 and has published nothing for it since. The package changelog
of `4.19.325+furios8` contains no CVE reference and no stable merge — the
~1000 commits in it are feature backports (`openat2`, `close_range`, the new
mount API) so that a current Debian userland runs at all, plus MediaTek and
clang fixes.

A newer kernel is not on offer. Binder, hwcomposer, the audio HAL and the
modem driver are all compiled against this BSP, so moving to 5.x or 6.x means
new vendor blobs or mainline drivers, and for this SoC neither exists. CIP
maintains a `4.19.325-cip` series with security backports until 2029, which is
the one real way out, but it is a rebase of an Android fork and not something
a phone does to itself.

So the holes stay. What this project takes away is the **route** to them.

## The three parts

Each switches on its own, each goes away again cleanly.

| part | what it does |
|---|---|
| `sysctl` | unprivileged BPF off, JIT hardened, `dmesg` and kernel pointers closed, `ptrace` limited to one's own children |
| `modules` | the kernel stops auto-loading 14 protocol families, line disciplines and filesystems that nothing here uses |
| `firewall` | one nftables input chain with a default of **drop** — what listens on this phone is reachable from the home network, not from the carrier's |

Not one of them fixes a vulnerability. They make the cheap paths to one
expensive, which for an EOL kernel is the honest goal.

### Why `install`, not `blacklist`

`blacklist` only covers alias resolution. The kernel reaches a protocol family
through `socket(AF_TIPC, …)` and a filesystem through `mount()` regardless —
any process on the phone could pull in a driver nobody has audited in years.
`install <module> /bin/true` is what actually stops it.

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

The original `/etc/nftables.conf` is kept at
`/etc/furios-security/nftables.conf.orig` and put back; `nftables.service` is
disabled again only if this project enabled it.

One value cannot be taken back on a running kernel:
`kernel.unprivileged_bpf_disabled` is one-way on 4.19 by design, so that an
exploit cannot clear it either. It returns to 0 at the next boot.

## What this does not reach

Written up in [FINDINGS.md](FINDINGS.md), because a security tool that only
lists its wins is misleading. The short version: the in-kernel Bluetooth stack
is in radio range of anybody, and a compromised browser still runs local code
against an unpatched kernel.

## Tests

```sh
./tests/run-tests.sh       # NEVER with sudo
```

52 tests against a temporary `/etc`; nothing touches the live firewall.

MIT, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
