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
                     self.s.STATE_FILE, self.s.NFT_CONF, self.s.NFT_BACKUP):
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
        """It cannot be cleared on 4.19 and trying looks like a failure in
        the output. The code has to skip it rather than try and report."""
        self.s.sysctl_apply()
        self.proc_sysctl("kernel.unprivileged_bpf_disabled", "1")
        self.s.sysctl_revert()
        written = [c for c in self.calls
                   if "kernel.unprivileged_bpf_disabled=0" in " ".join(c)]
        self.assertEqual(written, [])


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

    def test_the_original_nftables_conf_is_kept(self):
        self.set_lan()
        self.s.write_file(self.s.NFT_CONF, "#!/usr/sbin/nft -f\nflush ruleset\n")
        self.s.firewall_apply()
        self.assertIn("flush ruleset", self.s.read_file(self.s.NFT_BACKUP))
        self.assertTrue(self.s.ours(self.s.NFT_CONF))

    def test_a_second_apply_does_not_overwrite_the_backup(self):
        """The bug this is here for: back up on every apply and the second
        one saves a copy of OUR file as "the original"."""
        self.set_lan()
        self.s.write_file(self.s.NFT_CONF, "the real original\n")
        self.s.firewall_apply()
        self.s.firewall_apply()
        self.assertEqual(self.s.read_file(self.s.NFT_BACKUP), "the real original\n")

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
    def test_the_original_comes_back(self):
        self.set_lan()
        self.s.write_file(self.s.NFT_CONF, "the real original\n")
        self.s.firewall_apply()
        self.s.firewall_revert()
        self.assertEqual(self.s.read_file(self.s.NFT_CONF), "the real original\n")
        self.assertFalse(os.path.exists(self.s.FIREWALL_FILE))

    def test_the_live_table_is_deleted(self):
        self.set_lan()
        self.s.firewall_apply()
        self.calls.clear()
        self.s.firewall_revert()
        self.assertIn([self.s.NFT, "delete", "table", "inet", "furios"],
                      self.calls)

    def test_a_service_we_enabled_is_disabled_again(self):
        self.set_lan()
        self.answers[(self.s.SYSTEMCTL, "is-enabled")] = (1, "disabled\n")
        self.s.firewall_apply()
        self.calls.clear()
        self.s.firewall_revert()
        self.assertIn([self.s.SYSTEMCTL, "disable", "nftables"], self.calls)

    def test_a_service_that_was_already_enabled_is_left_on(self):
        """It was somebody else's before us. Revert puts the phone back the
        way it was found, which here means not touching it."""
        self.set_lan()
        self.answers[(self.s.SYSTEMCTL, "is-enabled")] = (0, "enabled\n")
        self.s.firewall_apply()
        self.calls.clear()
        self.s.firewall_revert()
        self.assertNotIn([self.s.SYSTEMCTL, "disable", "nftables"], self.calls)


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
