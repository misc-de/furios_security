#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 misc-de
# SPDX-License-Identifier: MIT
"""Everything in secctl that can be decided without changing this phone.

The whole program is paths and generated text, so a temporary directory is a
complete stand-in for /etc: apply writes into it, revert takes it out again,
and the question "is that file ours" is answered against files the test
wrote. What cannot be a directory - nft, systemctl, sysctl, modprobe - is
stubbed at the one function every external call goes through.

Nothing in here touches the real /etc, the real firewall or the real kernel.
That is not politeness: a suite that reached the live ruleset would take the
firewall off the phone it is testing, and the sibling project already has a
finding about a test that read past its own stub.

What is NOT in here: that the chain actually drops a packet from the mobile
interface. That is a measurement with a second machine, and it lives in
FINDINGS.md.
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


def load(root):
    """A fresh module bound to a fresh temporary /etc.

    Re-imported per test rather than re-pointed, because every path in
    secctl is a module constant computed from FURIOS_SECURITY_ROOT at import
    time - which is what makes them impossible to get half-redirected.
    """
    os.environ["FURIOS_SECURITY_ROOT"] = root
    os.environ["FURIOS_SECURITY_PROC"] = os.path.join(root, "proc")
    loader = importlib.machinery.SourceFileLoader(
        "secctl", os.path.join(ROOT, "secctl"))
    spec = importlib.util.spec_from_loader("secctl", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.s = load(self.tmp)
        # Every external program, answered from here. A test that forgets to
        # queue an answer gets "command not stubbed" rather than reaching the
        # phone.
        self.calls = []
        self.answers = {}

        def fake_run(argv, stdin=None):
            self.calls.append(list(argv))
            for prefix, answer in self.answers.items():
                if list(argv)[:len(prefix)] == list(prefix):
                    return answer
            # Two answers are not "0, nothing", because the real programs do
            # not give that one: nft asked for a table that is not loaded
            # fails, and sysctl -w changes /proc - here the fake one, with
            # the kernel's refusal to clear unprivileged_bpf_disabled.
            if list(argv[:3]) == [self.s.NFT, "list", "table"]:
                return (1, "Error: No such file or directory")
            if argv[:1] == [self.s.SYSCTL] and "-w" in argv:
                return self.fake_sysctl_w(argv)
            return (0, "")

        self.s.run = fake_run
        # Everything the program prints, collected instead of scrolling past
        # the test results - and available to assert on, which is why say()
        # is the only way this program writes a line.
        self.said = []
        self.s.say = lambda *text: self.said.append(
            " ".join(str(part) for part in text))
        # Root, unless a test says otherwise: apply and revert refuse without
        # it, and that refusal has its own test.
        self.s.is_root = lambda: True

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fake_sysctl_w(self, argv):
        for arg in argv[argv.index("-w") + 1:]:
            key, _, value = arg.partition("=")
            path = os.path.join(self.tmp, "proc", "sys", key.replace(".", "/"))
            if not os.path.exists(path):
                if "-e" in argv:
                    continue
                return (255, "sysctl: cannot stat %s" % path)
            with open(path) as fh:
                now = fh.read().strip()
            if key == "kernel.unprivileged_bpf_disabled" and now == "1" \
                    and value != "1":
                return (255, "sysctl: permission denied on key '%s'" % key)
            with open(path, "w") as fh:
                fh.write(value + "\n")
        return (0, "")

    def proc_value(self, key):
        path = os.path.join(self.tmp, "proc", "sys", key.replace(".", "/"))
        try:
            with open(path) as fh:
                return fh.read().strip()
        except OSError:
            return None

    def proc_sysctl(self, key, value):
        path = os.path.join(self.tmp, "proc", "sys", key.replace(".", "/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(value + "\n")

    def set_lan(self, cidr="192.168.0.0/24"):
        cfg = self.s.config()
        cfg["lan"] = cidr
        self.s.write_file(self.s.CONFIG_FILE, json.dumps(cfg))


class Paths(Base):
    def test_every_path_is_under_the_test_root(self):
        """The one property the whole suite rests on."""
        for path in (self.s.SYSCTL_FILE, self.s.MODPROBE_FILE,
                     self.s.FIREWALL_FILE, self.s.CONFIG_FILE,
                     self.s.STATE_FILE, self.s.NFT_CONF, self.s.NFT_BACKUP,
                     self.s.UNIT_FILE):
            self.assertTrue(path.startswith(self.tmp), path)


class SysctlText(Base):
    def test_every_key_is_in_the_file(self):
        text = self.s.sysctl_text()
        for key, value, _why in self.s.SYSCTLS:
            self.assertIn("%s = %s" % (key, value), text)

    def test_every_key_carries_its_reason(self):
        """A value without a reason is one nobody dares remove later."""
        text = self.s.sysctl_text()
        for _key, _value, why in self.s.SYSCTLS:
            self.assertIn(why, text)

    def test_the_file_is_recognisable_as_ours(self):
        self.s.sysctl_apply()
        self.assertTrue(self.s.ours(self.s.SYSCTL_FILE))


class SysctlState(Base):
    def test_all_set_is_on(self):
        for key, value, _ in self.s.SYSCTLS:
            self.proc_sysctl(key, value)
        self.assertEqual(self.s.sysctl_state()["state"], "on")

    def test_none_set_is_off(self):
        for key, _value, _ in self.s.SYSCTLS:
            self.proc_sysctl(key, "0")
        self.assertEqual(self.s.sysctl_state()["state"], "off")

    def test_some_set_is_partial(self):
        for index, (key, value, _) in enumerate(self.s.SYSCTLS):
            self.proc_sysctl(key, value if index == 0 else "0")
        self.assertEqual(self.s.sysctl_state()["state"], "partial")

    def test_a_key_that_cannot_be_read_is_not_a_failure(self):
        """net.core.bpf_jit_harden is root-only. Unreadable is "unknown",
        never "off" - the difference decides whether a switch looks broken."""
        for key, value, _ in self.s.SYSCTLS:
            if key != "net.core.bpf_jit_harden":
                self.proc_sysctl(key, value)
        state = self.s.sysctl_state()
        self.assertIsNone(state["keys"]["net.core.bpf_jit_harden"]["ok"])
        self.assertEqual(state["state"], "on")


class SysctlRevert(Base):
    def test_a_foreign_file_is_left_alone(self):
        """Somebody else's file at our path is reported, not deleted."""
        self.s.write_file(self.s.SYSCTL_FILE, "# somebody else\nvm.swappiness = 1\n")
        self.assertEqual(self.s.sysctl_revert(), 1)
        self.assertTrue(os.path.exists(self.s.SYSCTL_FILE))
        self.assertIn("left alone", " ".join(self.said))

    def test_our_file_goes(self):
        self.s.sysctl_apply()
        self.s.sysctl_revert()
        self.assertFalse(os.path.exists(self.s.SYSCTL_FILE))

    def test_bpf_is_not_written_back_to_zero(self):
        """It cannot be cleared at runtime and trying looks like a failure in
        the output. The code has to skip it rather than try and report."""
        self.s.sysctl_apply()
        self.proc_sysctl("kernel.unprivileged_bpf_disabled", "1")
        self.s.sysctl_revert()
        written = [c for c in self.calls
                   if "kernel.unprivileged_bpf_disabled=0" in " ".join(c)]
        self.assertEqual(written, [])

    def test_revert_puts_back_what_was_there_not_zero(self):
        """This kernel boots with ptrace_scope 1 (Yama) and
        perf_event_paranoid 3 (PERF_EVENTS_RESTRICT). Writing 0 left a
        reverted phone more open than one that never had this."""
        booted = {"kernel.yama.ptrace_scope": "1",
                  "kernel.perf_event_paranoid": "3",
                  "kernel.kptr_restrict": "0"}
        for key, value in booted.items():
            self.proc_sysctl(key, value)
        self.s.sysctl_apply()
        for key, value, _ in self.s.SYSCTLS:
            self.proc_sysctl(key, value)
        self.calls.clear()
        self.s.sysctl_revert()
        for key, value in booted.items():
            self.assertEqual(value, self.proc_value(key), key)
        written = [c[-1] for c in self.calls if "-w" in c]
        self.assertNotIn("kernel.yama.ptrace_scope=0", written)
        self.assertNotIn("kernel.perf_event_paranoid=0", written)

    def test_a_second_apply_does_not_record_our_own_values(self):
        self.proc_sysctl("kernel.yama.ptrace_scope", "1")
        self.s.sysctl_apply()
        self.proc_sysctl("kernel.yama.ptrace_scope", "1")
        self.proc_sysctl("kernel.dmesg_restrict", "1")
        self.s.sysctl_apply()
        before = self.s.state()["sysctl_before"]
        self.assertNotIn("kernel.dmesg_restrict", before)

    def test_without_a_record_nothing_is_lowered(self):
        """Applied by a secctl that kept no record: leave the values for the
        next boot rather than guess 0."""
        self.s.write_file(self.s.SYSCTL_FILE, self.s.sysctl_text())
        for key, value, _ in self.s.SYSCTLS:
            self.proc_sysctl(key, value)
        self.s.sysctl_revert()
        self.assertEqual([c for c in self.calls if "-w" in c], [])


class Modules(Base):
    def test_install_true_not_blacklist(self):
        """blacklist only covers alias resolution; socket() and mount() walk
        straight past it."""
        text = self.s.modprobe_text()
        self.assertNotIn("\nblacklist ", text)
        for name in self.s.BLOCKED_MODULES:
            self.assertIn("install %s /bin/true" % name, text)

    def test_modprobe_decides_not_our_file(self):
        """Another file in /etc/modprobe.d can override ours. What counts is
        what modprobe would do."""
        self.s.modules_apply()
        self.answers[("/usr/sbin/modprobe", "-n", "-v", "tipc")] = (0, "insmod /lib/tipc.ko\n")
        self.assertFalse(self.s.modules_state()["modules"]["tipc"])

    def test_unanswerable_is_not_blocked_and_not_open(self):
        self.answers[("/usr/sbin/modprobe",)] = (127, "not installed")
        state = self.s.modules_state()
        self.assertTrue(all(v is None for v in state["modules"].values()))

    def test_a_foreign_file_is_left_alone(self):
        self.s.write_file(self.s.MODPROBE_FILE, "# somebody else\n")
        self.assertEqual(self.s.modules_revert(), 1)
        self.assertTrue(os.path.exists(self.s.MODPROBE_FILE))


class FirewallText(Base):
    def test_it_can_be_loaded_twice(self):
        """create, delete, define - without this a second apply appends its
        rules to the chain that is already there and the ruleset grows."""
        self.set_lan()
        text = self.s.firewall_text()
        self.assertIn("table inet furios\ndelete table inet furios", text)

    def test_it_does_not_flush_the_whole_ruleset(self):
        """LXC's tables are somebody else's and have to survive an apply."""
        self.set_lan()
        self.assertNotIn("flush ruleset", self.s.firewall_text())

    def test_the_home_network_reaches_the_rule(self):
        self.set_lan("10.1.2.0/24")
        text = self.s.firewall_text()
        self.assertIn("ip saddr 10.1.2.0/24 tcp dport 22 accept", text)

    def test_no_ssh_rule_without_a_network(self):
        """Not "any": a missing value must not widen the rule."""
        text = self.s.firewall_text()
        self.assertNotIn("dport 22", text)

    def test_the_default_is_drop(self):
        self.set_lan()
        self.assertIn("policy drop", self.s.firewall_text())

    def test_icmp_survives(self):
        """Without it PMTU breaks and IPv6 stops working - the classic way to
        make a phone look like it has a bad connection."""
        self.set_lan()
        self.assertIn("ipv6-icmp", self.s.firewall_text())


class FirewallApply(Base):
    def test_it_refuses_without_a_home_network(self):
        """The one failure mode that matters: switched on blind, it takes the
        SSH session of whoever switched it on."""
        self.assertEqual(self.s.firewall_apply(), 1)
        self.assertFalse(os.path.exists(self.s.FIREWALL_FILE))

    def test_nftables_conf_is_not_touched(self):
        """A conffile of the nftables package. Changing it means a question
        in the middle of the next nftables update, and answering it with the
        package's version took the firewall away after the next boot."""
        self.set_lan()
        self.s.write_file(self.s.NFT_CONF, "#!/usr/sbin/nft -f\nflush ruleset\n")
        self.s.firewall_apply()
        self.assertEqual(self.s.read_file(self.s.NFT_CONF),
                         "#!/usr/sbin/nft -f\nflush ruleset\n")
        self.assertFalse(os.path.exists(self.s.NFT_BACKUP))

    def test_our_own_unit_is_written_and_enabled(self):
        self.set_lan()
        self.s.firewall_apply()
        self.assertTrue(self.s.ours(self.s.UNIT_FILE))
        self.assertIn([self.s.SYSTEMCTL, "enable", self.s.UNIT_NAME], self.calls)
        self.assertNotIn([self.s.SYSTEMCTL, "enable", "nftables"], self.calls)

    def test_the_unit_comes_after_the_stock_flush(self):
        """FuriOS' nftables.conf starts with "flush ruleset"; run before it,
        our table would be gone by the end of the boot."""
        text = self.s.unit_text()
        self.assertIn("After=nftables.service", text)
        self.assertIn("PartOf=nftables.service", text)

    def test_the_unit_never_flushes_the_whole_ruleset(self):
        """LXC's NAT tables have to survive our stop."""
        text = self.s.unit_text()
        self.assertNotIn("flush ruleset", text)
        self.assertIn("delete table inet furios", text)

    def test_an_older_rewrite_of_nftables_conf_is_put_back(self):
        """What earlier versions did: our include in nftables.conf, the
        original kept aside. Applying now restores it."""
        self.set_lan()
        self.s.write_file(self.s.NFT_BACKUP, "the real original\n")
        self.s.write_file(self.s.NFT_CONF, "# %s\ninclude x\n" % self.s.MARKER)
        self.s.firewall_apply()
        self.assertEqual(self.s.read_file(self.s.NFT_CONF), "the real original\n")
        self.assertFalse(os.path.exists(self.s.NFT_BACKUP))

    def test_a_foreign_unit_file_is_refused(self):
        self.set_lan()
        self.s.write_file(self.s.UNIT_FILE, "[Unit]\nsomebody else's\n")
        self.assertEqual(self.s.firewall_apply(), 1)
        self.assertEqual(self.s.read_file(self.s.UNIT_FILE), "[Unit]\nsomebody else's\n")

    def test_nft_is_asked_to_load_the_file(self):
        self.set_lan()
        self.s.firewall_apply()
        self.assertIn([self.s.NFT, "-f", self.s.FIREWALL_FILE], self.calls)

    def test_a_refused_ruleset_is_a_failure(self):
        """Reported, not swallowed: somebody would otherwise believe the
        chain is up."""
        self.set_lan()
        self.answers[(self.s.NFT, "-f")] = (1, "Error: syntax error")
        self.assertEqual(self.s.firewall_apply(), 1)


class FirewallRevert(Base):
    def test_our_unit_and_ruleset_go(self):
        self.set_lan()
        self.s.firewall_apply()
        self.s.firewall_revert()
        self.assertFalse(os.path.exists(self.s.FIREWALL_FILE))
        self.assertFalse(os.path.exists(self.s.UNIT_FILE))
        self.assertIn([self.s.SYSTEMCTL, "disable", self.s.UNIT_NAME], self.calls)

    def test_the_live_table_is_deleted(self):
        self.set_lan()
        self.s.firewall_apply()
        self.calls.clear()
        self.s.firewall_revert()
        self.assertIn([self.s.NFT, "delete", "table", "inet", "furios"],
                      self.calls)

    def test_nftables_service_is_left_alone(self):
        """It is the package's, enabled or not."""
        self.set_lan()
        self.s.firewall_apply()
        self.s.firewall_revert()
        for call in self.calls:
            self.assertNotEqual(call[-1:], ["nftables"], call)

    def test_an_older_rewrite_is_undone_on_revert_too(self):
        self.s.write_file(self.s.NFT_BACKUP, "the real original\n")
        self.s.write_file(self.s.NFT_CONF, "# %s\ninclude x\n" % self.s.MARKER)
        self.s.write_file(self.s.STATE_FILE, json.dumps({"nftables_was_enabled": False}))
        self.s.firewall_revert()
        self.assertEqual(self.s.read_file(self.s.NFT_CONF), "the real original\n")
        self.assertIn([self.s.SYSTEMCTL, "disable", "nftables"], self.calls)


class Cidr(Base):
    def test_good(self):
        for text in ("192.168.0.0/24", "10.0.0.0/8", "172.16.5.0/22"):
            self.assertTrue(self.s.valid_cidr(text), text)

    def test_bad(self):
        for text in ("", None, "192.168.0.0", "192.168.0.0/33", "any",
                     "999.1.1.0/24", "192.168.0.0/24 ; rm -rf /"):
            self.assertFalse(self.s.valid_cidr(text), repr(text))

    def test_guess_reads_the_interface(self):
        self.answers[(self.s.IP,)] = (0, "wlan0  UP  192.168.0.25/24 fe80::1/64\n")
        self.assertEqual(self.s.guess_lan(), "192.168.0.0/24")

    def test_guess_is_the_network_the_phone_is_in(self):
        """Not the first three octets with .0: on a /26 that is a network
        the phone is not in, and SSH from the home machine is dropped."""
        for line, want in (("wlan0  UP  192.168.1.200/26\n", "192.168.1.192/26"),
                           ("wlan0  UP  10.20.30.40/16\n", "10.20.0.0/16")):
            self.answers[(self.s.IP,)] = (0, line)
            self.assertEqual(self.s.guess_lan(), want)

    def test_guess_says_nothing_when_it_cannot(self):
        self.answers[(self.s.IP,)] = (1, "Device does not exist")
        self.assertEqual(self.s.guess_lan(), "")


class Exposure(Base):
    SS_OUT = (
        "udp   UNCONN 0 0    127.0.0.53%lo:53    0.0.0.0:*\n"
        "udp   UNCONN 0 0    0.0.0.0%lxcbr0:67   0.0.0.0:*\n"
        "tcp   LISTEN 0 128  0.0.0.0:22          0.0.0.0:*\n"
        "tcp   LISTEN 0 128  127.0.0.1:631       0.0.0.0:*\n"
    )

    def test_loopback_is_not_counted(self):
        self.answers[(self.s.SS,)] = (0, self.SS_OUT)
        ports = [e["port"] for e in self.s.exposure()["open"]]
        self.assertNotIn("631", ports)
        self.assertNotIn("53", ports)

    def test_the_interface_suffix_is_not_part_of_the_address(self):
        self.answers[(self.s.SS,)] = (0, self.SS_OUT)
        addrs = [e["addr"] for e in self.s.exposure()["open"]]
        self.assertIn("0.0.0.0", addrs)
        self.assertFalse(any("%" in a for a in addrs))

    def test_every_interface_is_flagged(self):
        self.answers[(self.s.SS,)] = (0, self.SS_OUT)
        ssh = [e for e in self.s.exposure()["open"] if e["port"] == "22"][0]
        self.assertTrue(ssh["any"])

    def test_unreadable_is_said_rather_than_shown_as_empty(self):
        self.answers[(self.s.SS,)] = (127, "not installed")
        self.assertFalse(self.s.exposure()["readable"])


class Chain(Base):
    def test_apply_stops_at_the_first_failure(self):
        """A half-applied state reported as success is the one outcome this
        must not produce."""
        order = []
        self.s.APPLY = {"sysctl": lambda: order.append("sysctl") or 0,
                        "modules": lambda: order.append("modules") or 1,
                        "firewall": lambda: order.append("firewall") or 0}
        rc = self.s.do("all", self.s.APPLY, "applied")
        self.assertEqual(rc, 1)
        self.assertEqual(order, ["sysctl", "modules"])

    def test_an_unknown_part_is_refused(self):
        self.assertEqual(self.s.do("everything", self.s.APPLY, "applied"), 2)


class Root(Base):
    def test_apply_needs_root(self):
        self.s.is_root = lambda: False
        self.assertEqual(self.s.main(["secctl", "apply"]), 1)
        self.assertFalse(os.path.exists(self.s.SYSCTL_FILE))

    def test_status_does_not(self):
        self.s.is_root = lambda: False
        self.assertEqual(self.s.main(["secctl", "status", "--json"]), 0)

    def test_lan_needs_root(self):
        self.s.is_root = lambda: False
        self.assertEqual(self.s.main(["secctl", "lan", "192.168.0.0/24"]), 1)


class Cli(Base):
    def test_set_on_applies_one_part(self):
        self.assertEqual(self.s.main(["secctl", "set", "modules", "on"]), 0)
        self.assertTrue(os.path.exists(self.s.MODPROBE_FILE))

    def test_set_off_reverts_one_part(self):
        self.s.main(["secctl", "set", "modules", "on"])
        self.assertEqual(self.s.main(["secctl", "set", "modules", "off"]), 0)
        self.assertFalse(os.path.exists(self.s.MODPROBE_FILE))

    def test_set_rejects_anything_but_on_and_off(self):
        self.assertEqual(self.s.main(["secctl", "set", "modules", "maybe"]), 2)

    def test_lan_rejects_nonsense(self):
        self.assertEqual(self.s.main(["secctl", "lan", "the office"]), 2)

    def test_lan_does_not_switch_the_firewall_on(self):
        """Setting the network is not asking for the chain. Nothing in this
        collection switches itself on."""
        self.s.main(["secctl", "lan", "192.168.0.0/24"])
        self.assertFalse(os.path.exists(self.s.FIREWALL_FILE))

    def test_lan_rewrites_a_firewall_that_is_already_on(self):
        self.set_lan("192.168.0.0/24")
        self.s.firewall_apply()
        self.s.main(["secctl", "lan", "10.9.0.0/24"])
        self.assertIn("10.9.0.0/24", self.s.read_file(self.s.FIREWALL_FILE))

    def test_status_json_has_what_the_app_reads(self):
        for key, value, _ in self.s.SYSCTLS:
            self.proc_sysctl(key, value)
        self.s.main(["secctl", "status", "--json"])
        data = json.loads("\n".join(self.said))
        for field in ("parts", "exposure", "state"):
            self.assertIn(field, data)
        for part in self.s.PARTS:
            self.assertIn("state", data["parts"][part])



class Lockout(Base):
    """The lock-screen part. The module's own behaviour is test-pam.py; this
    is secctl putting it into the login stack and taking it out again."""

    def module_dir(self):
        d = os.path.join(self.tmp, "usr/lib/test-multiarch/security")
        os.makedirs(d, exist_ok=True)
        return d

    def real_module(self):
        path = os.path.join(self.module_dir(), self.s.PAM_MODULE_NAME)
        subprocess.run(["gcc", "-shared", "-fPIC", "-o", path,
                        os.path.join(ROOT, "pam", "pam_furios_lockout.c"),
                        "-lpam"], check=True)
        return path

    def stub_pam_auth_update(self):
        """Does what pam-auth-update does to the two files, as far as the
        question "is the module named" goes."""
        def answer(argv, stdin=None):
            self.calls.append(list(argv))
            if argv[:1] != [self.s.PAM_AUTH_UPDATE]:
                return (0, "")
            for f in (self.s.COMMON_AUTH, self.s.COMMON_ACCOUNT):
                os.makedirs(os.path.dirname(f), exist_ok=True)
                with open(f, "w") as fh:
                    if "--enable" in argv:
                        fh.write("auth requisite pam_furios_lockout.so preauth\n")
                    else:
                        fh.write("auth [success=1 default=ignore] pam_unix.so\n")
            return (0, "")
        self.s.run = answer

    def test_paths_are_under_the_test_root(self):
        for path in (self.s.PAM_PROFILE, self.s.COMMON_AUTH, self.s.COMMON_ACCOUNT):
            self.assertTrue(path.startswith(self.tmp), path)

    def test_off_after_installation(self):
        self.assertEqual("off", self.s.lockout_state()["state"])

    def test_without_the_module_it_refuses(self):
        """A stack naming a module that is not there fails every login."""
        self.stub_pam_auth_update()
        self.assertEqual(1, self.s.lockout_apply())
        self.assertFalse(os.path.exists(self.s.PAM_PROFILE))
        self.assertEqual([], [c for c in self.calls
                              if c[:1] == [self.s.PAM_AUTH_UPDATE]])

    def test_a_module_that_does_not_load_is_refused(self):
        with open(os.path.join(self.module_dir(), self.s.PAM_MODULE_NAME), "w") as fh:
            fh.write("not an ELF file")
        self.stub_pam_auth_update()
        self.assertEqual(1, self.s.lockout_apply())
        self.assertFalse(self.s.lockout_in_stack())

    def test_on_and_off(self):
        self.real_module()
        self.stub_pam_auth_update()
        self.assertEqual(0, self.s.lockout_apply())
        self.assertEqual("on", self.s.lockout_state()["state"])
        self.assertTrue(self.s.pam_profile_ours())
        self.assertIn(["--root", self.tmp], [c[-2:] for c in self.calls])
        self.assertEqual(0, self.s.lockout_revert())
        self.assertEqual("off", self.s.lockout_state()["state"])
        self.assertFalse(os.path.exists(self.s.PAM_PROFILE))

    def test_a_refusing_pam_auth_update_is_reported(self):
        self.real_module()
        self.answers[(self.s.PAM_AUTH_UPDATE,)] = (
            0, "pam-auth-update: Local modifications to /etc/pam.d/common-*, not updating.")
        self.assertEqual(1, self.s.lockout_apply())
        self.assertTrue(any("did not take it" in line for line in self.said))

    def test_a_foreign_profile_is_left_alone(self):
        self.real_module()
        self.s.write_file(self.s.PAM_PROFILE, "Name: somebody else\n")
        self.stub_pam_auth_update()
        self.assertEqual(1, self.s.lockout_apply())
        self.assertEqual(1, self.s.lockout_revert())
        self.assertEqual("Name: somebody else\n", self.s.read_file(self.s.PAM_PROFILE))

    def test_revert_needs_nothing_to_be_there(self):
        self.stub_pam_auth_update()
        self.assertEqual(0, self.s.lockout_revert())

    def test_the_profile_as_the_real_pam_auth_update_reads_it(self):
        """Not a stub: the system's pam-auth-update, pointed at a copy of
        this phone's PAM configuration. The module has to land before
        pam_unix in common-auth, and after it in common-account."""
        tool = "/usr/sbin/pam-auth-update"
        if not os.path.exists("/etc/pam.d/common-auth") or not os.access(tool, os.X_OK):
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
        self.real_module()
        # debconf wants to write its database under /var/cache, which this
        # suite may not. A database of its own in the test root instead.
        rc = os.path.join(self.tmp, "debconf.conf")
        with open(rc, "w") as fh:
            fh.write("Config: configdb\nTemplates: templatedb\n\n"
                     "Name: configdb\nDriver: File\nFilename: %s/config.dat\n\n"
                     "Name: templatedb\nDriver: File\nMode: 644\n"
                     "Filename: %s/templates.dat\n" % (self.tmp, self.tmp))
        env = dict(os.environ, DEBCONF_SYSTEMRC=rc)

        def real(argv, stdin=None):
            p = subprocess.run(argv, capture_output=True, text=True, env=env)
            return p.returncode, p.stdout + p.stderr
        self.s.run = real
        self.assertEqual(0, self.s.lockout_apply(), self.said)
        auth = [l.split() for l in open(self.s.COMMON_AUTH)
                if l.strip() and not l.startswith("#")]
        mods = [next((w for w in l if w.endswith(".so")), "") for l in auth]
        self.assertLess(mods.index(self.s.PAM_MODULE_NAME),
                        [i for i, l in enumerate(auth) if "pam_unix.so" in l][0])
        line = [l for l in open(self.s.COMMON_AUTH) if self.s.PAM_MODULE_NAME in l][0]
        self.assertIn(self.s.PAM_AUTH_CONTROL, line)
        self.assertNotIn("requisite", line)
        account = open(self.s.COMMON_ACCOUNT).read()
        self.assertIn("optional\t" + self.s.PAM_MODULE_NAME, account)
        self.assertEqual(0, self.s.lockout_revert())
        self.assertNotIn(self.s.PAM_MODULE_NAME, open(self.s.COMMON_AUTH).read())
        self.assertNotIn(self.s.PAM_MODULE_NAME, open(self.s.COMMON_ACCOUNT).read())

    def test_unlock_clears_the_callers_state(self):
        home = os.path.join(self.tmp, "home")
        path = os.path.join(home, ".local/state/furios-lockout/state")
        os.makedirs(os.path.dirname(path))
        with open(path, "w") as fh:
            fh.write("0 2 %d 600 0\n" % int(__import__("time").time()))
        self.s.lockout_user_state = lambda: {"path": path}
        self.assertEqual(0, self.s.main(["secctl", "unlock"]))
        self.assertFalse(os.path.exists(path))

if __name__ == "__main__":
    unittest.main(verbosity=2)
