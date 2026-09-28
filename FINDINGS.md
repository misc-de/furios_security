# Findings

What was measured on this phone, in the order it was found. Including the
parts this project does **not** reach — a hardening tool that lists only its
wins is worse than none, because it produces confidence rather than safety.

## 1 · The kernel configuration

Measured from `/proc/config.gz`:

`CFI_CLANG=y`, `STACKPROTECTOR_STRONG`, `HARDENED_USERCOPY`, `RANDOMIZE_BASE`,
`STRICT_KERNEL_RWX`, `UNMAP_KERNEL_AT_EL0`, SELinux enabled. Spectre-v2 via
CSV2+BHB, SSB per prctl.

CFI in particular devalues a good share of the classic ROP paths.

## 2 · What was actually open (before this project)

```
kernel.unprivileged_bpf_disabled = 0     unprivileged BPF + JIT
kernel.dmesg_restrict            = 0     ring buffer readable by anyone
kernel.yama.ptrace_scope         = 0     any process may attach to its siblings
CONFIG_USER_NS                   = y     the precondition of many LPEs
```

Modules present and auto-loadable although nothing here uses them: `rds`,
`tipc`, `x25`, `atm`, `can`, `appletalk`, `n_hdlc`, `ppdev`, plus the
filesystems `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`.

No host firewall at all. The only nftables rules were LXC's own NAT tables
with `policy accept`. `sshd` listened on `0.0.0.0:22` — key-only, no password,
root only by key, so well configured, but reachable **on `ccmni1`**, the
mobile data interface, as well as in every foreign Wi-Fi.

## 3 · `blacklist` would not have worked

The first attempt used `blacklist <module>`. That only prevents alias
resolution; the kernel still loads a protocol family when a process calls
`socket(AF_TIPC, …)` and a filesystem when something is mounted. Verified by
switching to `install <module> /bin/true` and re-testing: `modprobe tipc`
loads nothing afterwards.

This is also why `secctl` asks **modprobe** what would happen rather than
reading its own file back. Another file in `/etc/modprobe.d` can override
ours, and a block that has been overridden is a block that does not exist.

## 4 · Flushing the ruleset would take LXC down with it

Debian's stock `/etc/nftables.conf` begins with `flush ruleset`. On this phone
that removes the LXC NAT tables as well. The generated ruleset therefore uses
the create/delete/define idiom:

```
table inet furios
delete table inet furios
table inet furios { … }
```

Idempotent — a second `nft -f` replaces our table instead of appending its
rules to the chain again — and it leaves every other table alone.

## 5 · `nft -c` needs root even to check

A parse check opens netlink to resolve the table it is asked to delete, so it
fails as an ordinary user with `cache initialization failed: Operation not
permitted`. The test suite skips it rather than running as root; on the phone
the same parse happens inside `secctl apply firewall`, which reports and
loads nothing when it fails.

## 6 · The tmpfs trap (21.9.2026)

The scratch directory on this phone is on `/tmp`, which is **tmpfs — RAM**,
3.8 GB. A full kernel clone started there would have consumed the phone's
memory. Noticed at 1.3 GB and moved to disk. Worth remembering for anything
that downloads more than a few hundred megabytes here.

---

# What this does not reach

**The Bluetooth stack.** `CONFIG_BT=y`, and on this phone bluebinder puts a
virtual HCI device in front of it, so the in-kernel L2CAP and SMP code really
is in the path. Bluetooth has historically been a productive source of kernel
vulnerabilities, and it is reachable by anyone in radio range. Nothing in this
project touches that. Turning Bluetooth off when it is not needed is the only
real answer available here.

**A compromised browser.** What this project removed are the convenient escalation paths (unprivileged
BPF, the auto-loading modules, the readable `dmesg`); `CONFIG_USER_NS=y`
remains, because taking it away breaks Bubblewrap and the portals.

**Wi-Fi driver and firmware.** Proprietary, on the vendor side, out of reach
from here.

**Everything already running as root.** This is hardening, not a sandbox.

## The firewall lived in a file that belongs to nftables (27.9.2026)

`/etc/nftables.conf` is a conffile of the nftables package. secctl rewrote it
to an include of our ruleset, so the next nftables update that ships a
changed file would stop and ask which version to keep. The package's version
turns the firewall off from the next boot, and nothing noticed: `status`
read "rules at boot" from that same file.

The ruleset now comes up from `furios-firewall.service`, a unit no package
owns. It runs `After=nftables.service`, because the stock file begins with
`flush ruleset`, and `PartOf=` it, so a package update that restarts nftables
restarts us right behind it instead of leaving the phone without a table
until the next boot. Its stop deletes our table only. Apply and revert both
put an older rewrite back from `nftables.conf.orig`.
