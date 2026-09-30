#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 misc-de
# SPDX-License-Identifier: MIT
"""install.sh, every part on, uninstall.sh - and the root is what it was.

The rule since 30.9.2026, for the scripts themselves: before the first
change, write down what was there; on the way out, put back exactly that.
test-uninstall-covers-install.py reads the two scripts as text. This runs
them - with DESTDIR pointing at a temporary root and every program that
would reach the phone replaced:

  sudo       "unshare -r": root inside a user namespace of our own, so
             secctl's own root check passes and every file it writes still
             belongs to whoever runs the tests. Never the real sudo.
  nft, systemctl, sysctl, modprobe, ss, ip
             small scripts that keep their state in the temporary root the
             way the real ones keep it in the kernel and in /etc
  pam-auth-update
             the real one, with --root (secctl passes it), on a copy of this
             phone's PAM configuration, and debconf pointed at a scratch
             database

Then a picture of the whole root before install.sh and after uninstall.sh is
compared: every file, its content and mode, every directory, every link.

Needs unprivileged user namespaces for the parts that need root; without
them only install and uninstall with nothing switched on are run.
"""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PAM_AUTH_UPDATE = "/usr/sbin/pam-auth-update"
BPF = "proc/sys/kernel/unprivileged_bpf_disabled"

BOOTED = {
    "kernel.unprivileged_bpf_disabled": "0",
    "net.core.bpf_jit_harden": "1",
    "kernel.dmesg_restrict": "0",
    "kernel.kptr_restrict": "1",
    "kernel.perf_event_paranoid": "2",
    "kernel.yama.ptrace_scope": "0",
}

STUBS = {
    # Root in a namespace of our own - never the real sudo.
    "sudo": 'if [ "$(id -u)" = 0 ]; then exec "$@"; fi\n'
            'exec unshare -r "$@"\n',
    "nft": r'''
T="$STUB_STATE/nft-table"
case "$1 $2 $3 $4" in
  "list table inet furios") [ -e "$T" ] && cat "$T" && exit 0; exit 1 ;;
  "delete table inet furios") [ -e "$T" ] || exit 1; rm -f "$T"; exit 0 ;;
esac
[ "$1" = -f ] && cp "$2" "$T" && exit 0
exit 0
''',
    "systemctl": r'''
W="$DESTDIR/etc/systemd/system/sysinit.target.wants"
U="$DESTDIR/etc/systemd/system/$2"
case "$1" in
  enable) [ -e "$U" ] || exit 1; mkdir -p "$W"; ln -sf "$U" "$W/$2" ;;
  disable) rm -f "$W/$2" ;;
  is-enabled)
    if [ -L "$W/$2" ]; then echo enabled; exit 0; fi
    if [ -e "$U" ]; then echo disabled; exit 1; fi
    echo not-found; exit 4 ;;
esac
exit 0
''',
    "sysctl": r'''
skip=0
for a in "$@"; do case "$a" in -e) skip=1 ;; esac; done
for a in "$@"; do
  case "$a" in
    -*) ;;
    *=*)
      k=${a%%=*}; v=${a#*=}
      f="$DESTDIR/proc/sys/$(echo "$k" | tr . /)"
      [ -e "$f" ] || { [ $skip = 1 ] && continue; exit 255; }
      if [ "$k" = kernel.unprivileged_bpf_disabled ] && [ "$(cat "$f")" = 1 ] \
         && [ "$v" != 1 ]; then exit 255; fi
      echo "$v" > "$f" ;;
  esac
done
exit 0
''',
    "modprobe": "exit 1\n",
    "ss": "exit 0\n",
    "ip": "exit 1\n",
}


def userns():
    try:
        return subprocess.run(["unshare", "-r", "true"],
                              capture_output=True).returncode == 0
    except OSError:
        return False


class Roundtrip(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.root = os.path.join(self.base, "root")
        self.stubs = os.path.join(self.base, "bin")
        self.state = os.path.join(self.base, "state")
        for d in (self.root, self.stubs, self.state):
            os.makedirs(d)
        for name, body in STUBS.items():
            path = os.path.join(self.stubs, name)
            with open(path, "w") as fh:
                fh.write("#!/bin/sh\n" + body)
            os.chmod(path, 0o755)
        rc = os.path.join(self.state, "debconf.conf")
        with open(rc, "w") as fh:
            fh.write("Config: configdb\nTemplates: templatedb\n\n"
                     "Name: configdb\nDriver: File\nFilename: %s/config.dat\n\n"
                     "Name: templatedb\nDriver: File\nMode: 644\n"
                     "Filename: %s/templates.dat\n" % (self.state, self.state))
        s = self.stubs
        self.env = dict(
            os.environ,
            PATH=s + ":" + os.environ.get("PATH", "/usr/bin:/bin"),
            DESTDIR=self.root, STUB_STATE=self.state,
            DEBCONF_SYSTEMRC=rc, DEBIAN_FRONTEND="noninteractive",
            FURIOS_SECURITY_NFT=os.path.join(s, "nft"),
            FURIOS_SECURITY_SYSTEMCTL=os.path.join(s, "systemctl"),
            FURIOS_SECURITY_SYSCTL=os.path.join(s, "sysctl"),
            FURIOS_SECURITY_MODPROBE=os.path.join(s, "modprobe"),
            FURIOS_SECURITY_SS=os.path.join(s, "ss"),
            FURIOS_SECURITY_IP=os.path.join(s, "ip"))
        # The one thing that must never happen: the real sudo.
        found = subprocess.run(["sh", "-c", "command -v sudo"], env=self.env,
                               capture_output=True, text=True).stdout.strip()
        self.assertEqual(os.path.join(s, "sudo"), found)
        self.phone()

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def phone(self):
        """What a phone has before install.sh: the directories every Debian
        has, PAM as configured here, the kernel values, a home."""
        r = self.root
        for d in ("usr/local/bin", "usr/local/share", "etc/sysctl.d",
                  "etc/modprobe.d", "etc/systemd/system/sysinit.target.wants",
                  "etc/pam.d", "var/lib/pam", "usr/share/pam-configs",
                  "usr/share/polkit-1/actions"):
            os.makedirs(os.path.join(r, d), exist_ok=True)
        self.put("etc/sysctl.d/10-theirs.conf", "vm.swappiness = 60\n")
        self.put("etc/nftables.conf", "#!/usr/sbin/nft -f\nflush ruleset\n")
        for key, value in BOOTED.items():
            self.put("proc/sys/" + key.replace(".", "/"), value + "\n")
        home = os.path.expanduser("~").lstrip("/")
        os.makedirs(os.path.join(r, home, ".local/state"), exist_ok=True)
        self.home = os.path.join(r, home)
        self.pam = os.path.exists("/etc/pam.d/common-auth") \
            and os.access(PAM_AUTH_UPDATE, os.X_OK)
        if not self.pam:
            return
        for name in os.listdir("/usr/share/pam-configs"):
            if name != "furios-lockout":
                shutil.copy(os.path.join("/usr/share/pam-configs", name),
                            os.path.join(r, "usr/share/pam-configs"))
        for name in ("common-auth", "common-account", "common-session",
                     "common-session-noninteractive", "common-password"):
            shutil.copy(os.path.join("/etc/pam.d", name),
                        os.path.join(r, "etc/pam.d"))
        for name in os.listdir("/var/lib/pam"):
            shutil.copy(os.path.join("/var/lib/pam", name),
                        os.path.join(r, "var/lib/pam"))
        seen = os.path.join(r, "var/lib/pam/seen")
        if os.path.exists(seen):
            with open(seen) as fh:
                keep = [l for l in fh if l.strip() != "furios-lockout"]
            with open(seen, "w") as fh:
                fh.writelines(keep)
        p = subprocess.run([PAM_AUTH_UPDATE, "--package", "--root", r],
                           env=self.env, capture_output=True, text=True)
        self.pam = p.returncode == 0

    def put(self, rel, text, mode=0o644):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
        os.chmod(path, mode)

    def read(self, rel):
        with open(os.path.join(self.root, rel)) as fh:
            return fh.read()

    def picture(self):
        pic = {}
        for dirpath, dirnames, filenames in os.walk(self.root):
            rel = os.path.relpath(dirpath, self.root)
            pic[rel + "/"] = oct(os.lstat(dirpath).st_mode)
            for name in filenames + [d for d in dirnames
                                     if os.path.islink(os.path.join(dirpath, d))]:
                path = os.path.join(dirpath, name)
                key = os.path.relpath(path, self.root)
                st = os.lstat(path)
                if stat.S_ISLNK(st.st_mode):
                    pic[key] = "-> " + os.readlink(path)
                else:
                    with open(path, "rb") as fh:
                        pic[key] = (oct(st.st_mode), fh.read())
        table = os.path.join(self.state, "nft-table")
        pic["<nft table>"] = os.path.exists(table)
        return pic

    def same(self, before, after, but=()):
        for key in sorted(set(before) | set(after)):
            if key in but:
                continue
            self.assertEqual(before.get(key), after.get(key),
                             "%s differs after install + uninstall" % key)

    def sh(self, *argv, ok=True):
        p = subprocess.run(list(argv), cwd=REPO, env=self.env,
                           capture_output=True, text=True, timeout=300)
        self.out = p.stdout + p.stderr
        if ok:
            self.assertEqual(0, p.returncode, self.out)
        return p.returncode

    def secctl(self, *args, ok=True):
        return self.sh("sudo", "env", "FURIOS_SECURITY_ROOT=" + self.root,
                       os.path.join(self.root, "usr/local/bin/secctl"),
                       *args, ok=ok)

    def all_on(self):
        if not userns():
            self.skipTest("no user namespaces - no root for secctl here")
        self.secctl("lan", "192.168.0.0/24")
        parts = ["sysctl", "modules", "firewall"] + (["lockout"]
                                                     if self.pam else [])
        for part in parts:
            self.secctl("apply", part)
        return parts

    # ---------------------------------------------------------------- tests

    def test_install_uninstall_nothing_switched_on(self):
        before = self.picture()
        self.sh("./install.sh")
        self.assertTrue(os.path.exists(
            os.path.join(self.root, "usr/local/bin/secctl")))
        self.assertIn("absent\t/usr/local/bin/secctl",
                      self.read("etc/furios-security/installed/list"))
        self.sh("./uninstall.sh")
        self.same(before, self.picture())

    def test_every_part_on_then_uninstall(self):
        before = self.picture()
        self.sh("./install.sh")
        parts = self.all_on()
        if "lockout" in parts:
            self.assertIn("pam_furios_lockout", self.read("etc/pam.d/common-auth"))
        self.assertTrue(os.path.exists(os.path.join(self.state, "nft-table")))
        # The module writes this for whoever unlocks.
        lock = os.path.join(self.home, ".local/state/furios-lockout")
        os.makedirs(lock)
        with open(os.path.join(lock, "state"), "w") as fh:
            fh.write("0 0 0 0 0\n")
        self.sh("./uninstall.sh")
        # bpf is the one value no running kernel gives back.
        self.same(before, self.picture(), but=(BPF,))
        self.assertIn("next boot", self.out)

    def test_install_twice_keeps_the_first_record(self):
        before = self.picture()
        self.sh("./install.sh")
        first = self.read("etc/furios-security/installed/list")
        self.sh("./install.sh")
        self.assertEqual(first, self.read("etc/furios-security/installed/list"))
        self.sh("./uninstall.sh")
        self.same(before, self.picture())

    def test_somebody_elses_file_comes_back(self):
        self.put("usr/share/polkit-1/actions/de.misc-de.secctl.policy",
                 "<policyconfig>theirs</policyconfig>\n", 0o640)
        before = self.picture()
        self.sh("./install.sh")
        self.assertIn("de.misc-de.secctl", self.read(
            "usr/share/polkit-1/actions/de.misc-de.secctl.policy"))
        self.sh("./uninstall.sh")
        self.same(before, self.picture())

    def test_a_file_replaced_after_install_is_left(self):
        before = self.picture()
        self.sh("./install.sh")
        policy = "usr/share/polkit-1/actions/de.misc-de.secctl.policy"
        self.put(policy, "<policyconfig>theirs now</policyconfig>\n")
        self.sh("./uninstall.sh")
        self.assertIn("not ours any more", self.out)
        self.assertIn("theirs now", self.read(policy))
        os.unlink(os.path.join(self.root, policy))
        self.same(before, self.picture())

    def test_an_older_installation_without_a_record(self):
        """Files of ours, no record: removed as before, and said."""
        before = self.picture()
        shutil.copy(os.path.join(REPO, "secctl"),
                    os.path.join(self.root, "usr/local/bin/secctl"))
        self.sh("./install.sh")
        self.assertIn("older\t/usr/local/bin/secctl",
                      self.read("etc/furios-security/installed/list"))
        self.sh("./uninstall.sh")
        self.assertIn("no record of what was at /usr/local/bin/secctl", self.out)
        self.same(before, self.picture())

    def test_uninstall_stops_when_a_part_cannot_be_taken_back(self):
        """Somebody else's file where secctl's sysctl file was: revert
        refuses it, and uninstall removes nothing - neither secctl nor the
        records it still needs - until told --force."""
        before = self.picture()
        self.sh("./install.sh")
        self.all_on()
        os.unlink(os.path.join(self.root,
                               "etc/sysctl.d/99-furios-hardening.conf"))
        self.put("etc/sysctl.d/99-furios-hardening.conf", "vm.swappiness = 1\n")
        self.assertNotEqual(0, self.sh("./uninstall.sh", ok=False))
        self.assertIn("Nothing has been removed", self.out)
        self.assertTrue(os.path.exists(
            os.path.join(self.root, "usr/local/bin/secctl")))
        self.assertTrue(os.path.exists(
            os.path.join(self.root, "etc/furios-security/state.json")))
        # Every other part was still taken back.
        self.assertFalse(os.path.exists(os.path.join(self.state, "nft-table")))
        self.sh("./uninstall.sh", "--force")
        self.assertEqual("vm.swappiness = 1\n",
                         self.read("etc/sysctl.d/99-furios-hardening.conf"))
        os.unlink(os.path.join(self.root,
                               "etc/sysctl.d/99-furios-hardening.conf"))
        self.same(before, self.picture(),
                  but=(BPF,) + tuple("proc/sys/" + k.replace(".", "/")
                                     for k in BOOTED))


if __name__ == "__main__":
    unittest.main(verbosity=2)
