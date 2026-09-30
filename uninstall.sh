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
# The .so.new is install.sh's half-copied file from a run that stopped
# between install and mv.
if ! grep -qs pam_furios_lockout /etc/pam.d/common-auth /etc/pam.d/common-account; then
    sudo rm -f /usr/lib/*/security/pam_furios_lockout.so \
               /usr/lib/*/security/pam_furios_lockout.so.new
    # pam-auth-update lists every profile it has seen in /var/lib/pam/seen,
    # and revert asked it to remove ours while the profile still existed - so
    # the name stays there until the next run of pam-auth-update. Harmless
    # for a "Default: no" profile, but not what a new phone has. Only our
    # own line, and only once the profile itself is gone.
    if [ ! -e /usr/share/pam-configs/furios-lockout ] \
       && grep -qx furios-lockout /var/lib/pam/seen 2>/dev/null; then
        sudo sed -i '/^furios-lockout$/d' /var/lib/pam/seen
    fi
else
    echo "pam_furios_lockout is still in /etc/pam.d/common-* - module left in place." >&2
fi
# The module keeps each account's failures and lock in that account's home
# (~/.local/state/furios-lockout, written as the account itself). Left behind,
# a reinstall starts with the old strike count - the next wrong PIN would
# lock for longer than on a new phone. Every account, not just the one
# running this: the module writes for whoever unlocks.
getent passwd | cut -d: -f6 | sort -u | while IFS= read -r home; do
    case "$home" in /|"") continue ;; esac
    [ -d "$home/.local/state/furios-lockout" ] || continue
    sudo rm -rf "$home/.local/state/furios-lockout"
done
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
