#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2026 misc-de
# SPDX-License-Identifier: MIT
#
# Installs secctl and its polkit action. It does NOT turn anything on.
#
# That is the rule in this collection since 16.9.2026, and here it matters
# more than anywhere else: the firewall needs to know which network this
# phone is at home in, and a chain that defaults to drop, switched on by an
# installer before anybody said which network that is, would cut the SSH
# session the installer is very likely running in.
#
# Run it as yourself, NOT with sudo: only the lines below that need root take
# it, the way they would in a terminal.
set -euo pipefail
cd "$(dirname "$0")"

if [ "$(id -u)" = 0 ]; then
    echo "Please run WITHOUT sudo - the sudo lines inside take root where" >&2
    echo "they need it. Run as root, the state directory ends up owned" >&2
    echo "wrongly and pkexec has no session to allow." >&2
    exit 1
fi

# Checked before anything is installed. secctl without nft is a program that
# can report and can harden two thirds - which is worth saying up front
# rather than discovering at the switch.
missing=()
command -v nft >/dev/null || missing+=("nft (Paket nftables)")
command -v ss >/dev/null || missing+=("ss (Paket iproute2)")
[ -x /usr/sbin/modprobe ] || command -v modprobe >/dev/null \
    || missing+=("modprobe (Paket kmod)")
if [ ${#missing[@]} -gt 0 ]; then
    printf 'Missing: %s\n' "${missing[@]}" >&2
    echo "Nothing was installed." >&2
    exit 1
fi

# /usr/local, not /usr: this is a hand installation and it stays out of the
# way of anything apt might put down. The polkit action names this path, so
# the two have to agree.
BIN=/usr/local/bin
POLKIT=/usr/share/polkit-1/actions
DOC=/usr/local/share/doc/furios-security

sudo install -Dm755 secctl "$BIN/secctl"
sudo install -Dm644 polkit/de.misc-de.secctl.policy \
    "$POLKIT/de.misc-de.secctl.policy"
sudo install -Dm644 README.md FINDINGS.md NOTICE -t "$DOC"

echo
echo "Installed. Nothing has been switched on."
echo
"$BIN/secctl" status || true
cat <<'HINT'

Turn it on, one part at a time or all at once:

    sudo secctl lan auto          # or: sudo secctl lan 192.168.0.0/24
    sudo secctl apply sysctl
    sudo secctl apply modules
    sudo secctl apply firewall

The firewall refuses to come up until the home network is set - with a
default of drop and no rule for your own subnet it would take SSH with it.

Or use the app, under "Security".
HINT
