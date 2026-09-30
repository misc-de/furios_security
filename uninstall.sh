#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2026 misc-de
# SPDX-License-Identifier: MIT
#
# Takes everything back out - and, first, everything that was switched on.
# The order matters: the hardening has to be reverted before the program that
# knows how to revert it is deleted.
set -uo pipefail

if [ "$(id -u)" = 0 ]; then
    echo "Please run WITHOUT sudo." >&2
    exit 1
fi

BIN=/usr/local/bin
POLKIT=/usr/share/polkit-1/actions
DOC=/usr/local/share/doc/furios-security

if [ -x "$BIN/secctl" ]; then
    sudo "$BIN/secctl" revert all || true
fi

sudo rm -f "$BIN/secctl" "$POLKIT/de.misc-de.secctl.policy"
# Only now: revert above took it out of the login stack, and a stack that
# names a missing module fails every login, sudo included.
if ! grep -qs pam_furios_lockout /etc/pam.d/common-auth /etc/pam.d/common-account; then
    sudo rm -f /usr/lib/*/security/pam_furios_lockout.so
else
    echo "pam_furios_lockout is still in /etc/pam.d/common-* - module left in place." >&2
fi
sudo rm -rf "$DOC"
# The state directory last. Our own files go: config.json and state.json are
# written by secctl itself (revert above rewrites state.json), and left behind
# they hand an old SSH/LAN choice to the next installation - found on
# 30.9.2026 in a clean-install test. The directory itself only goes when that
# leaves it empty: an older secctl kept its copy of /etc/nftables.conf in it,
# and one still there means revert did not put it back.
sudo rm -f /etc/furios-security/config.json /etc/furios-security/state.json \
           /etc/furios-security/firewall.nft
sudo rmdir /etc/furios-security 2>/dev/null || true

echo "Removed."
echo "Note: kernel.unprivileged_bpf_disabled cannot be cleared on a running"
echo "kernel - it goes back to 0 at the next boot."
