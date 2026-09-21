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
sudo rm -rf "$DOC"
# The state directory last, and only when it is empty of anything we did not
# put there: it holds the copy of whatever /etc/nftables.conf was before us,
# and revert above is what puts that back.
sudo rmdir /etc/furios-security 2>/dev/null || true

echo "Removed."
echo "Note: kernel.unprivileged_bpf_disabled cannot be cleared on a running"
echo "4.19 kernel - it goes back to 0 at the next boot."
