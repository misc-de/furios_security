#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 misc-de
# SPDX-License-Identifier: MIT
"""On, then off, and the phone is what it was - checked from the outside.

The rule since 30.9.2026: every change secctl makes is written down before
the first time it is made, and switching a part off puts back exactly that.
test-secctl.py checks how each function goes about it; this file does not
look at how. It takes a picture of a temporary root - every file with its
content and mode, the fake /proc, the fake nftables and the fake systemd -
switches parts on and off, and compares the picture. A test that shares the
code's idea of what "back" means would never find the day that idea is
wrong; a picture does.

The stand-ins keep state the way the real programs do: nft remembers which
table is loaded, systemctl enable puts a link into sysinit.target.wants and
disable takes it out, sysctl -w writes the fake /proc and cannot clear
unprivileged_bpf_disabled. PAM goes through the REAL pam-auth-update,
pointed at a copy of this phone's PAM configuration in the temporary root.

Nothing here touches the real /etc, the real firewall or the real kernel.
"""

import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PAM_AUTH_UPDATE = "/usr/sbin/pam-auth-update"


def load(root):
    os.environ["FURIOS_SECURITY_ROOT"] = root
    os.environ["FURIOS_SECURITY_PROC"] = os.path.join(root, "proc")
    loader = importlib.machinery.SourceFileLoader(
        "secctl", os.path.join(ROOT, "secctl"))
    spec = importlib.util.spec_from_loader("secctl", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


# What this kernel booted with, deliberately NOT the values secctl sets and
# NOT all zero: a revert that writes "the default" instead of "what was
# there" shows up as a difference on every one of them.
BOOTED = {
    "kernel.unprivileged_bpf_disabled": "0",
    "net.core.bpf_jit_harden": "1",
    "kernel.dmesg_restrict": "0",
    "kernel.kptr_restrict": "1",
    "kernel.perf_event_paranoid": "2",
    "kernel.yama.ptrace_scope": "0",
}
BPF = "kernel.unprivileged_bpf_disabled"


class World(unittest.TestCase):
    """A temporary root with programs that remember what was done to it."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.s = load(self.tmp)
        self.table = None           # the loaded "inet furios", or None
        self.said = []
        self.s.say = lambda *text: self.said.append(
            " ".join(str(part) for part in text))
        self.s.is_root = lambda: True
        self.s.run = self.fake_run
        self.pam_real = False
        for key, value in BOOTED.items():
            self.set_proc(key, value)
        # Something of somebody else's in every directory secctl writes to,
        # so "identical" also means "their files untouched".
        for rel in ("etc/sysctl.d/10-theirs.conf",
                    "etc/modprobe.d/theirs.conf",
                    "etc/systemd/system/theirs.service",
                    "etc/nftables.conf"):
            self.put(rel, "# not secctl's\n")
        os.makedirs(os.path.join(self.tmp, "etc/systemd/system/"
                                 "sysinit.target.wants"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------ helpers

    def put(self, rel, text, mode=0o644):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
        os.chmod(path, mode)

    def proc_path(self, key):
        return os.path.join(self.tmp, "proc", "sys", key.replace(".", "/"))

    def set_proc(self, key, value):
        os.makedirs(os.path.dirname(self.proc_path(key)), exist_ok=True)
        with open(self.proc_path(key), "w") as fh:
            fh.write(value + "\n")

    def proc(self, key):
        try:
            with open(self.proc_path(key)) as fh:
                return fh.read().strip()
        except OSError:
            return None

    def wants(self, unit):
        return os.path.join(self.tmp, "etc/systemd/system/sysinit.target.wants",
                            unit)

    def fake_run(self, argv, stdin=None):
        argv = list(argv)
        s = self.s
        if argv[0] == s.SYSCTL and "-w" in argv:
            for arg in argv[argv.index("-w") + 1:]:
                key, _, value = arg.partition("=")
                if self.proc(key) is None:
                    if "-e" in argv:
                        continue
                    return (255, "sysctl: cannot stat %s" % key)
                if key == BPF and self.proc(key) == "1" and value != "1":
                    return (255, "sysctl: permission denied on key '%s'" % key)
                self.set_proc(key, value)
            return (0, "")
        if argv[0] == s.NFT:
            if argv[1:] == ["list", "table", "inet", "furios"]:
                return (0, self.table) if self.table else (1, "Error: no table")
            if argv[1:] == ["delete", "table", "inet", "furios"]:
                had, self.table = self.table, None
                return (0, "") if had else (1, "Error: no table")
            if argv[1] == "-f":
                with open(argv[2]) as fh:
                    self.table = fh.read()
                return (0, "")
        if argv[0] == s.SYSTEMCTL:
            verb, unit = argv[1], (argv[2] if len(argv) > 2 else "")
            unit_file = os.path.join(self.tmp, "etc/systemd/system", unit)
            if verb == "enable":
                if not os.path.exists(unit_file):
                    return (1, "Unit %s does not exist" % unit)
                if not os.path.lexists(self.wants(unit)):
                    os.symlink(unit_file, self.wants(unit))
                return (0, "")
            if verb == "disable":
                if os.path.lexists(self.wants(unit)):
                    os.unlink(self.wants(unit))
                return (0, "")
            if verb == "is-enabled":
                if os.path.lexists(self.wants(unit)):
                    return (0, "enabled\n")
                if os.path.exists(unit_file):
                    return (1, "disabled\n")
                return (4, "not-found\n")
            return (0, "")
        if argv[0] == s.PAM_AUTH_UPDATE:
            return self.pam_auth_update(argv)
        if argv[0] in (s.SS, s.IP, s.MODPROBE):
            return (1, "")
        raise AssertionError("not stubbed: %r" % argv)

    def snapshot(self, exclude=("etc/furios-security",)):
        """Every file and directory below the root: content, mode, link
        target - plus the nftables table, which has no file."""
        picture = {}
        for dirpath, dirnames, filenames in os.walk(self.tmp):
            rel_dir = os.path.relpath(dirpath, self.tmp)
            if any(rel_dir == e or rel_dir.startswith(e + "/") for e in exclude):
                dirnames[:] = []
                continue
            picture[rel_dir + "/"] = oct(os.stat(dirpath).st_mode)
            for name in filenames:
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, self.tmp)
                if os.path.islink(path):
                    picture[rel] = "-> " + os.readlink(path)
                    continue
                with open(path, "rb") as fh:
                    picture[rel] = (oct(os.stat(path).st_mode), fh.read())
        picture["<nft table inet furios>"] = self.table
        return picture

    def assertSamePicture(self, before, after, but=()):
        for key in sorted(set(before) | set(after)):
            if any(key.startswith(b) for b in but):
                continue
            self.assertEqual(before.get(key), after.get(key),
                             "%s differs after on/off" % key)

    def on(self, *parts):
        for part in parts:
            self.assertEqual(0, self.s.APPLY[part](), (part, self.said))

    def off(self, *parts):
        for part in parts:
            self.assertEqual(0, self.s.REVERT[part](), (part, self.said))

    def set_lan(self):
        self.s.write_file(self.s.CONFIG_FILE,
                          json.dumps(dict(self.s.DEFAULT_CONFIG,
                                          lan="192.168.0.0/24")))

    # ------------------------------------------------------------ real PAM

    def real_pam(self):
        """A copy of this phone's PAM configuration in the root, and the
        real pam-auth-update working on it."""
        if not (os.access(PAM_AUTH_UPDATE, os.X_OK)
                and os.path.exists("/etc/pam.d/common-auth")):
            self.skipTest("no pam-auth-update here")
        for sub in ("etc/pam.d", "var/lib/pam", "usr/share/pam-configs"):
            os.makedirs(os.path.join(self.tmp, sub), exist_ok=True)
        for name in os.listdir("/usr/share/pam-configs"):
            if name != self.s.PAM_PROFILE_NAME:
                shutil.copy(os.path.join("/usr/share/pam-configs", name),
                            os.path.join(self.tmp, "usr/share/pam-configs"))
        for name in ("common-auth", "common-account", "common-session",
                     "common-session-noninteractive", "common-password"):
            shutil.copy(os.path.join("/etc/pam.d", name),
                        os.path.join(self.tmp, "etc/pam.d"))
        for name in os.listdir("/var/lib/pam"):
            shutil.copy(os.path.join("/var/lib/pam", name),
                        os.path.join(self.tmp, "var/lib/pam"))
        # The real phone may carry our profile's name in "seen" already (an
        # earlier install on it). A new phone does not - start from that.
        seen = os.path.join(self.tmp, "var/lib/pam/seen")
        if os.path.exists(seen):
            with open(seen) as fh:
                lines = [l for l in fh if l.strip() != self.s.PAM_PROFILE_NAME]
            with open(seen, "w") as fh:
                fh.writelines(lines)
        d = os.path.join(self.tmp, "usr/lib/test-multiarch/security")
        os.makedirs(d)
        subprocess.run(["gcc", "-shared", "-fPIC", "-o",
                        os.path.join(d, self.s.PAM_MODULE_NAME),
                        os.path.join(ROOT, "pam", "pam_furios_lockout.c"),
                        "-lpam"], check=True)
        # debconf's database in the scratch area, outside the picture.
        self.debconf = tempfile.mkdtemp()
        rc = os.path.join(self.debconf, "debconf.conf")
        with open(rc, "w") as fh:
            fh.write("Config: configdb\nTemplates: templatedb\n\n"
                     "Name: configdb\nDriver: File\nFilename: %s/config.dat\n\n"
                     "Name: templatedb\nDriver: File\nMode: 644\n"
                     "Filename: %s/templates.dat\n"
                     % (self.debconf, self.debconf))
        self.addCleanup(shutil.rmtree, self.debconf, True)
        self.pam_env = dict(os.environ, DEBCONF_SYSTEMRC=rc)
        self.pam_real = True
        if self.pam_auth_update([PAM_AUTH_UPDATE, "--package", "--root",
                                 self.tmp])[0] != 0:
            self.skipTest("pam-auth-update does not run on this copy")

    def pam_auth_update(self, argv):
        if not self.pam_real:
            raise AssertionError("pam-auth-update without real_pam()")
        p = subprocess.run(argv, capture_output=True, text=True,
                           env=self.pam_env)
        return p.returncode, p.stdout + p.stderr


class Sysctl(World):
    def test_on_off_is_identical(self):
        """bpf aside - the one key the kernel will not let go of."""
        before = self.snapshot()
        self.on("sysctl")
        for key, want, _ in self.s.SYSCTLS:
            self.assertEqual(want, self.proc(key), key)
        self.off("sysctl")
        self.assertSamePicture(before, self.snapshot(),
                               but=("proc/sys/kernel/unprivileged_bpf",))
        self.assertIn("still on until the next boot", " ".join(self.said))

    def test_bpf_already_on_is_fully_identical(self):
        self.set_proc(BPF, "1")
        before = self.snapshot()
        self.on("sysctl")
        self.off("sysctl")
        self.assertSamePicture(before, self.snapshot())
        self.assertNotIn("still on", " ".join(self.said))

    def test_the_stuck_record_survives_to_the_next_boot(self):
        """After the reboot bpf is 0 again; a second round must still know
        that 0 was the original, not the 1 the first round left."""
        self.on("sysctl")
        self.off("sysctl")
        self.assertEqual({BPF: "0"}, self.s.state()["sysctl_before"])
        self.set_proc(BPF, "0")                 # the boot
        before = self.snapshot()
        self.on("sysctl")
        self.off("sysctl")
        self.assertSamePicture(before, self.snapshot(),
                               but=("proc/sys/kernel/unprivileged_bpf",))

    def test_a_second_apply_keeps_the_first_record(self):
        before = self.snapshot()
        self.on("sysctl")
        self.on("sysctl")                       # install.sh's refresh
        self.off("sysctl")
        self.assertSamePicture(before, self.snapshot(),
                               but=("proc/sys/kernel/unprivileged_bpf",))

    def test_a_value_changed_after_us_is_left_and_said(self):
        self.on("sysctl")
        self.set_proc("kernel.yama.ptrace_scope", "3")
        self.off("sysctl")
        self.assertEqual("3", self.proc("kernel.yama.ptrace_scope"))
        self.assertEqual(BOOTED["kernel.kptr_restrict"],
                         self.proc("kernel.kptr_restrict"))
        self.assertIn("changed by somebody else", " ".join(self.said))

    def test_a_key_the_kernel_does_not_have(self):
        os.unlink(self.proc_path("kernel.yama.ptrace_scope"))
        before = self.snapshot()
        self.on("sysctl")
        self.off("sysctl")
        self.assertSamePicture(before, self.snapshot(),
                               but=("proc/sys/kernel/unprivileged_bpf",))

    def test_apply_touches_no_other_key(self):
        """sysctl --system would re-read every file in /etc/sysctl.d and put
        back whatever somebody had set at runtime. Only our keys move."""
        self.set_proc("vm.swappiness", "7")
        self.on("sysctl")
        self.assertEqual("7", self.proc("vm.swappiness"))
        for call in [c for c in self.s_calls()]:
            self.assertNotIn("--system", call)

    def s_calls(self):
        calls = []
        orig = self.s.run

        def spy(argv, stdin=None):
            calls.append(list(argv))
            return orig(argv, stdin)
        self.s.run = spy
        self.off("sysctl")
        self.on("sysctl")
        return calls

    def test_without_a_record_it_says_so(self):
        """Switched on by an older secctl: nothing to go by - left, and said."""
        self.s.write_file(self.s.SYSCTL_FILE, self.s.sysctl_text())
        for key, want, _ in self.s.SYSCTLS:
            self.set_proc(key, want)
        self.off("sysctl")
        self.assertEqual("2", self.proc("kernel.kptr_restrict"))
        text = " ".join(self.said)
        self.assertIn("no record", text)

    def test_a_foreign_file_is_not_overwritten(self):
        self.put("etc/sysctl.d/99-furios-hardening.conf", "vm.swappiness = 1\n")
        before = self.snapshot()
        self.assertEqual(1, self.s.sysctl_apply())
        self.assertSamePicture(before, self.snapshot())


class Modules(World):
    def test_on_off_is_identical(self):
        before = self.snapshot()
        self.on("modules")
        self.assertTrue(os.path.exists(self.s.MODPROBE_FILE))
        self.off("modules")
        self.assertSamePicture(before, self.snapshot())
        self.assertIsNone(self.s.state()["files_before"])

    def test_the_record_says_there_was_nothing(self):
        self.on("modules")
        self.assertEqual({"/etc/modprobe.d/99-furios-hardening.conf": None},
                         self.s.state()["files_before"])

    def test_a_foreign_file_is_not_overwritten(self):
        self.put("etc/modprobe.d/99-furios-hardening.conf", "install x /bin/false\n")
        before = self.snapshot()
        self.assertEqual(1, self.s.modules_apply())
        self.assertSamePicture(before, self.snapshot())

    def test_without_a_record_it_says_so(self):
        self.s.write_file(self.s.MODPROBE_FILE, self.s.modprobe_text())
        self.off("modules")
        self.assertIn("no record", " ".join(self.said))


class Firewall(World):
    def test_on_off_is_identical(self):
        self.set_lan()
        before = self.snapshot(exclude=("etc/furios-security",))
        self.on("firewall")
        self.assertIsNotNone(self.table)
        self.assertTrue(os.path.lexists(self.wants(self.s.UNIT_NAME)))
        self.off("firewall")
        self.assertSamePicture(before, self.snapshot())
        self.assertFalse(os.path.exists(self.s.FIREWALL_FILE))

    def test_twice_on_once_off(self):
        self.set_lan()
        before = self.snapshot()
        self.on("firewall")
        self.on("firewall")
        self.off("firewall")
        self.assertSamePicture(before, self.snapshot())

    def test_a_table_of_our_name_that_is_not_ours(self):
        """Revert deletes "inet furios". One we did not load would be gone
        for good - so it is refused before anything is written."""
        self.set_lan()
        self.table = "table inet furios { }"
        before = self.snapshot()
        self.assertEqual(1, self.s.firewall_apply())
        self.assertSamePicture(before, self.snapshot())

    def test_a_unit_of_our_name_elsewhere(self):
        self.set_lan()
        self.s.run = self.wrap({(self.s.SYSTEMCTL, "is-enabled"): (1, "disabled\n")})
        before = self.snapshot()
        self.assertEqual(1, self.s.firewall_apply())
        self.assertSamePicture(before, self.snapshot())

    def test_a_foreign_ruleset_file(self):
        self.set_lan()
        self.put("etc/furios-security/firewall.nft", "table ip theirs {}\n")
        self.assertEqual(1, self.s.firewall_apply())
        self.assertEqual("table ip theirs {}\n",
                         self.s.read_file(self.s.FIREWALL_FILE))

    def wrap(self, answers):
        inner = self.fake_run

        def run(argv, stdin=None):
            for prefix, answer in answers.items():
                if tuple(argv[:len(prefix)]) == prefix:
                    return answer
            return inner(argv, stdin)
        return run


class Lockout(World):
    def pam_picture(self):
        return {k: v for k, v in self.snapshot().items()
                if k.startswith(("etc/pam.d/", "var/lib/pam/",
                                 "usr/share/pam-configs/"))}

    def test_on_off_is_identical_through_the_real_pam_auth_update(self):
        """/var/lib/pam/seen included: pam-auth-update --remove keeps our
        name there, and only the record puts it back as it was."""
        self.real_pam()
        before = self.pam_picture()
        self.on("lockout")
        self.assertTrue(self.s.lockout_in_stack())
        self.off("lockout")
        self.assertFalse(self.s.lockout_in_stack())
        self.assertSamePicture(before, self.pam_picture())
        self.assertIsNone(self.s.state()["pam_before"])

    def test_twice_on_once_off(self):
        self.real_pam()
        before = self.pam_picture()
        self.on("lockout")
        self.on("lockout")
        self.off("lockout")
        self.assertSamePicture(before, self.pam_picture())

    def test_a_stack_changed_after_us_is_not_written_back(self):
        """A package that brings its own profile while ours is on: its
        profile must survive our revert. The record is not written over it;
        pam-auth-update --remove decides, and it is said."""
        self.real_pam()
        self.on("lockout")
        self.put("usr/share/pam-configs/theirs",
                 "Name: theirs\nDefault: yes\nPriority: 0\n"
                 "Session-Type: Additional\nSession:\n\toptional\tpam_env.so\n")
        self.assertEqual(0, self.pam_auth_update(
            [PAM_AUTH_UPDATE, "--package", "--root", self.tmp])[0])
        self.off("lockout")
        self.assertFalse(self.s.lockout_in_stack())
        session = self.s.read_file(os.path.join(self.tmp,
                                                "etc/pam.d/common-session"))
        self.assertIn("pam_env.so", session)
        self.assertIn("changed by somebody else", " ".join(self.said))

    def test_a_reapply_after_a_foreign_change_drops_the_record(self):
        self.real_pam()
        self.on("lockout")
        self.put("usr/share/pam-configs/theirs",
                 "Name: theirs\nDefault: yes\nPriority: 0\n"
                 "Session-Type: Additional\nSession:\n\toptional\tpam_env.so\n")
        self.pam_auth_update([PAM_AUTH_UPDATE, "--package", "--root", self.tmp])
        self.on("lockout")
        self.assertIsNone(self.s.state()["pam_before"])
        self.off("lockout")
        self.assertIn("pam_env.so", self.s.read_file(os.path.join(
            self.tmp, "etc/pam.d/common-session")))
        self.assertFalse(self.s.lockout_in_stack())

    def test_a_hand_edited_stack_comes_back_as_it_was(self):
        """A line added to common-auth by hand: pam-auth-update carries it
        through --enable and --remove, and whatever it does not carry the
        record puts back."""
        self.real_pam()
        with open(os.path.join(self.tmp, "etc/pam.d/common-auth"), "a") as fh:
            fh.write("auth\toptional\tpam_env.so\n")
        before = self.pam_picture()
        self.on("lockout")
        self.off("lockout")
        self.assertSamePicture(before, self.pam_picture())

    def test_a_refused_enable_leaves_the_stack_as_it_was(self):
        """pam-auth-update says no ("local modifications"): nothing in the
        stack moves, and revert takes our profile file out again."""
        self.real_pam()
        before = self.pam_picture()
        inner = self.s.run
        self.s.run = lambda argv, stdin=None: (
            (0, "Local modifications to /etc/pam.d/common-*, not updating.")
            if argv[0] == self.s.PAM_AUTH_UPDATE and "--enable" in argv
            else inner(argv, stdin))
        self.assertEqual(1, self.s.lockout_apply())
        self.s.run = inner
        self.off("lockout")
        self.assertSamePicture(before, self.pam_picture())

    def test_a_refused_enable_then_a_good_one(self):
        """The record of the refused attempt is taken again, not mistaken
        for a stack somebody changed."""
        self.real_pam()
        before = self.pam_picture()
        inner = self.s.run
        self.s.run = lambda argv, stdin=None: (
            (1, "refused") if argv[0] == self.s.PAM_AUTH_UPDATE
            and "--enable" in argv else inner(argv, stdin))
        self.assertEqual(1, self.s.lockout_apply())
        self.s.run = inner
        self.on("lockout")
        self.assertNotIn("no longer applies", " ".join(self.said))
        self.off("lockout")
        self.assertSamePicture(before, self.pam_picture())

    def test_what_remove_does_not_put_back_the_record_does(self):
        """pam-auth-update versions that leave our name in /var/lib/pam/seen
        after --remove (what uninstall.sh used to clean with sed): the
        record writes the file back as it was."""
        self.real_pam()
        before = self.pam_picture()
        self.on("lockout")
        inner = self.s.run
        seen = os.path.join(self.tmp, "var/lib/pam/seen")

        def remove_leaves_seen(argv, stdin=None):
            rc = inner(argv, stdin)
            if argv[0] == self.s.PAM_AUTH_UPDATE and "--remove" in argv:
                with open(seen, "a") as fh:
                    fh.write(self.s.PAM_PROFILE_NAME + "\n")
            return rc
        self.s.run = remove_leaves_seen
        self.off("lockout")
        self.assertSamePicture(before, self.pam_picture())

    def test_the_restored_files_keep_their_mode(self):
        self.real_pam()
        seen = os.path.join(self.tmp, "var/lib/pam/seen")
        os.chmod(seen, 0o600)
        before = self.pam_picture()
        self.on("lockout")
        self.off("lockout")
        self.assertSamePicture(before, self.pam_picture())


class All(World):
    def test_revert_all_does_not_stop_at_a_foreign_file(self):
        """uninstall.sh runs "revert all" and then deletes secctl. Stopping
        at the first refusal left the rest switched on for good."""
        self.set_lan()
        self.on("modules", "firewall")
        self.put("etc/sysctl.d/99-furios-hardening.conf", "vm.swappiness = 1\n")
        rc = self.s.do("all", self.s.REVERT, "reverted")
        self.assertNotEqual(0, rc)
        self.assertFalse(os.path.exists(self.s.MODPROBE_FILE))
        self.assertIsNone(self.table)

    def test_apply_all_still_stops_at_the_first_failure(self):
        self.put("etc/sysctl.d/99-furios-hardening.conf", "vm.swappiness = 1\n")
        self.assertEqual(1, self.s.do("all", self.s.APPLY, "applied"))
        self.assertFalse(os.path.exists(self.s.MODPROBE_FILE))

    def test_three_parts_on_off(self):
        self.set_lan()
        before = self.snapshot()
        self.on("sysctl", "modules", "firewall")
        self.off("sysctl", "modules", "firewall")
        self.assertSamePicture(before, self.snapshot(),
                               but=("proc/sys/kernel/unprivileged_bpf",))


if __name__ == "__main__":
    unittest.main(verbosity=2)
