#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 misc-de
# SPDX-License-Identifier: MIT
"""pam_furios_lockout through the real libpam, the way phosh calls it.

Nothing here touches /etc/pam.d or the real lock-screen state: the module is
built into a temporary directory, the stack is read from a directory of our
own (pam_start_confdir), and state goes where dir= says. The password check
is a stand-in (pam_exec with a script that accepts "right"), because the
tests cannot know the owner's PIN - what is tested is the module around it,
in the position pam-auth-update puts it.
"""
import ctypes
import ctypes.util
import getpass
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "pam", "pam_furios_lockout.c")

libc = ctypes.CDLL(ctypes.util.find_library("c"))
libc.calloc.restype = ctypes.c_void_p
libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
libc.strdup.restype = ctypes.c_void_p
libc.strdup.argtypes = [ctypes.c_char_p]
libpam = ctypes.CDLL(ctypes.util.find_library("pam"))

PAM_PROMPT_ECHO_OFF, PAM_ERROR_MSG = 1, 3
PAM_SUCCESS, PAM_AUTH_ERR = 0, 7


class PamMessage(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class PamResponse(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int)]


CONV_FUNC = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_int,
    ctypes.POINTER(ctypes.POINTER(PamMessage)),
    ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p)


class PamConv(ctypes.Structure):
    _fields_ = [("conv", CONV_FUNC), ("appdata_ptr", ctypes.c_void_p)]


libpam.pam_start_confdir.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(PamConv),
    ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
libpam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
libpam.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
libpam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]


# The control secctl puts the module under - read from secctl itself, so the
# stack tested here is the one that ends up in common-auth.
CONTROL = next(l.split('"')[1] for l in open(os.path.join(HERE, "..", "secctl"))
               if l.startswith("PAM_AUTH_CONTROL"))


def login(confdir, password, service="phosh"):
    """What phosh does: pam_start, pam_authenticate, and pam_acct_mgmt only
    after a success. Returns (auth result, error messages seen)."""
    errors = []

    def conv(n, msgs, resp, _data):
        arr = libc.calloc(n, ctypes.sizeof(PamResponse))
        replies = ctypes.cast(arr, ctypes.POINTER(PamResponse))
        for i in range(n):
            m = msgs[i].contents
            if m.msg_style == PAM_PROMPT_ECHO_OFF:
                replies[i].resp = libc.strdup(password.encode())
            elif m.msg_style == PAM_ERROR_MSG:
                errors.append(m.msg.decode())
        resp[0] = arr
        return PAM_SUCCESS

    c = PamConv(CONV_FUNC(conv), None)
    h = ctypes.c_void_p()
    assert libpam.pam_start_confdir(service.encode(), getpass.getuser().encode(),
                                    ctypes.byref(c), confdir.encode(),
                                    ctypes.byref(h)) == PAM_SUCCESS
    r = libpam.pam_authenticate(h, 0)
    if r == PAM_SUCCESS:
        libpam.pam_acct_mgmt(h, 0)
    libpam.pam_end(h, r)
    return r, errors


class Lockout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.so = os.path.join(cls.tmp, "pam_furios_lockout.so")
        subprocess.run(["gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra",
                        "-Werror", "-o", cls.so, SRC, "-lpam"], check=True)
        cls.check = os.path.join(cls.tmp, "check.sh")
        with open(cls.check, "w") as f:
            f.write('#!/bin/sh\np=$(tr -d "\\000")\n[ "$p" = right ]\n')
        os.chmod(cls.check, 0o755)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def setUp(self):
        self.state = tempfile.mkdtemp(dir=self.tmp)
        self.conf = tempfile.mkdtemp(dir=self.tmp)
        self.stack("phosh")
        # A service it must leave alone, with the module in it all the same:
        # after pam-auth-update it is in common-auth, which sudo reads too.
        self.stack("sudo")

    def stack(self, service, args=""):
        """The shape pam-auth-update produces, with the password check
        swapped for the stand-in."""
        mod = f"{self.so} dir={self.state} {args}".strip()
        with open(os.path.join(self.conf, service), "w") as f:
            f.write(f"auth {CONTROL} {mod} preauth\n"
                    f"auth [success=1 default=ignore] pam_exec.so expose_authtok quiet {self.check}\n"
                    "auth requisite pam_deny.so\n"
                    "auth required pam_permit.so\n"
                    "account required pam_permit.so\n"
                    f"account optional {mod}\n")

    def statefile(self):
        return os.path.join(self.state, getpass.getuser(), "state")

    def read(self):
        with open(self.statefile()) as f:
            return [int(x) for x in f.read().split()]

    def write(self, pending, strikes, start, length, last):
        with open(self.statefile(), "w") as f:
            f.write(f"{pending} {strikes} {start} {length} {last}\n")

    def age(self, seconds):
        """Move every timestamp into the past instead of waiting."""
        p, s, start, length, last = self.read()
        self.write(p, s, start - seconds if start else 0, length,
                   last - seconds if last else 0)

    def fail(self, n=1):
        for _ in range(n):
            self.assertEqual(PAM_AUTH_ERR, login(self.conf, "wrong")[0])

    # ------------------------------------------------------------------

    def test_the_right_pin_works(self):
        self.assertEqual(PAM_SUCCESS, login(self.conf, "right")[0])

    def test_a_module_that_does_not_load_locks_nobody_out(self):
        """After an update that breaks the module: the lock screen, sudo and
        pkexec must go on working on the PIN alone."""
        for service in ("phosh", "sudo"):
            with open(os.path.join(self.conf, service), "w") as f:
                f.write(f"auth {CONTROL} /nonexistent/pam_furios_lockout.so preauth\n"
                        f"auth [success=1 default=ignore] pam_exec.so expose_authtok quiet {self.check}\n"
                        "auth requisite pam_deny.so\n"
                        "auth required pam_permit.so\n"
                        "account required pam_permit.so\n")
            self.assertEqual(PAM_SUCCESS, login(self.conf, "right", service)[0], service)
            self.assertEqual(PAM_AUTH_ERR, login(self.conf, "wrong", service)[0], service)

    def test_two_failures_do_not_lock(self):
        self.fail(2)
        self.assertEqual(PAM_SUCCESS, login(self.conf, "right")[0])

    def test_three_failures_lock_even_the_right_pin(self):
        self.fail(3)
        r, errors = login(self.conf, "right")
        self.assertEqual(PAM_AUTH_ERR, r)
        self.assertTrue(any("Try again in 4:" in e or "Try again in 5:" in e
                            for e in errors), errors)

    def test_the_first_lock_is_five_minutes(self):
        self.fail(3)
        login(self.conf, "right")
        self.assertEqual(300, self.read()[3])

    def test_it_ends_after_its_time(self):
        self.fail(3)
        login(self.conf, "right")
        self.age(301)
        self.assertEqual(PAM_SUCCESS, login(self.conf, "right")[0])

    def test_each_lock_is_longer_5_10_15_30_60(self):
        want = [5, 10, 15, 30, 60, 120, 240, 480, 480]
        got = []
        for _ in want:
            self.fail(3)
            login(self.conf, "wrong")           # this one meets the lock
            got.append(self.read()[3] // 60)
            self.age(self.read()[3] + 1)
        self.assertEqual(want, got)

    def test_a_success_starts_the_schedule_over(self):
        self.fail(3)
        login(self.conf, "right")
        self.age(301)
        self.assertEqual(PAM_SUCCESS, login(self.conf, "right")[0])
        self.assertEqual([0, 0, 0, 0, 0], self.read())
        self.fail(3)
        login(self.conf, "right")
        self.assertEqual(300, self.read()[3], "second series did not start at 5")

    def test_failures_far_apart_are_forgotten(self):
        self.fail(2)
        self.age(901)
        self.fail(1)
        self.assertEqual(PAM_SUCCESS, login(self.conf, "right")[0])

    def test_the_lock_runs_from_the_third_failure(self):
        self.fail(3)
        self.age(200)
        r, errors = login(self.conf, "right")
        self.assertEqual(PAM_AUTH_ERR, r)
        self.assertTrue(any("Try again in 1:" in e for e in errors), errors)

    def test_a_clock_that_went_back_does_not_lengthen_the_lock(self):
        now = int(time.time())
        os.makedirs(os.path.dirname(self.statefile()), exist_ok=True)
        self.write(0, 1, now + 86400, 300, now + 86400)
        login(self.conf, "right")
        start, length = self.read()[2:4]
        self.assertLessEqual(start + length - int(time.time()), 300)

    def test_other_services_are_not_touched(self):
        for _ in range(5):
            self.assertEqual(PAM_AUTH_ERR, login(self.conf, "wrong", "sudo")[0])
        self.assertEqual(PAM_SUCCESS, login(self.conf, "right", "sudo")[0])
        self.assertFalse(os.path.exists(self.statefile()))

    def test_a_garbled_state_fails_open(self):
        os.makedirs(os.path.dirname(self.statefile()), exist_ok=True)
        with open(self.statefile(), "w") as f:
            f.write("rubbish\n")
        self.assertEqual(PAM_SUCCESS, login(self.conf, "right")[0])

    def test_an_unwritable_state_fails_open(self):
        d = os.path.dirname(self.statefile())
        os.makedirs(d, exist_ok=True)
        self.write(3, 0, 0, 0, int(time.time()))
        os.chmod(d, 0o500)
        try:
            self.assertEqual(PAM_SUCCESS, login(self.conf, "right")[0])
        finally:
            os.chmod(d, 0o700)

    def test_state_is_private(self):
        self.fail(1)
        self.assertEqual(0o600, os.stat(self.statefile()).st_mode & 0o777)
        self.assertEqual(0o700, os.stat(os.path.dirname(self.statefile())).st_mode & 0o777)

    def test_quiet_sends_no_message_but_still_refuses(self):
        self.stack("phosh", "quiet")
        self.fail(3)
        r, errors = login(self.conf, "right")
        self.assertEqual(PAM_AUTH_ERR, r)
        self.assertEqual([], errors)

    def test_a_schedule_and_deny_from_the_arguments(self):
        self.stack("phosh", "deny=2 schedule=1,2")
        self.fail(2)
        login(self.conf, "wrong")
        self.assertEqual(60, self.read()[3])

    def test_a_schedule_that_does_not_parse_keeps_the_default(self):
        self.stack("phosh", "schedule=abc")
        self.fail(3)
        login(self.conf, "wrong")
        self.assertEqual(300, self.read()[3])


if __name__ == "__main__":
    unittest.main(verbosity=1)
