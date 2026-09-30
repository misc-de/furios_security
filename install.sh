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
#
# Looked for on PATH *and* in /usr/sbin. These are administrator tools and a
# non-login shell on this phone does not carry /usr/sbin - checking with
# "command -v" alone reported nftables missing on a phone that has it, which
# is a refusal to install over nothing at all.
have() {
    command -v "$1" >/dev/null && return 0
    [ -x "/usr/sbin/$1" ] || [ -x "/sbin/$1" ]
}

missing=()
have nft      || missing+=("nft (Paket nftables)")
have ss       || missing+=("ss (Paket iproute2)")
have modprobe || missing+=("modprobe (Paket kmod)")
have gcc      || missing+=("gcc (Paket gcc)")
[ -e /usr/include/security/pam_modules.h ] || missing+=("PAM headers (Paket libpam0g-dev)")
if [ ${#missing[@]} -gt 0 ]; then
    printf 'Missing: %s\n' "${missing[@]}" >&2
    echo "Nothing was installed." >&2
    exit 1
fi

# DESTDIR is for the tests only: they install into a temporary root and
# uninstall from it again. Empty on the phone, where every path below is the
# real one.
: "${DESTDIR:=}"

# /usr/local, not /usr: this is a hand installation and it stays out of the
# way of anything apt might put down. The polkit action names this path, so
# the two have to agree.
BIN=$DESTDIR/usr/local/bin
POLKIT=$DESTDIR/usr/share/polkit-1/actions
DOC=$DESTDIR/usr/local/share/doc/furios-security
PAMDIR=$DESTDIR/usr/lib/$(gcc -print-multiarch)/security
# secctl, as the lines below run it. On the phone just the program; in a
# test root told where that root is - through env, because sudo would drop
# the variable otherwise.
if [ -n "$DESTDIR" ]; then
    SECCTL=(env FURIOS_SECURITY_ROOT="$DESTDIR" "$BIN/secctl")
else
    SECCTL=("$BIN/secctl")
fi

# ---------------------------------------------------------------- the record
#
# The rule since 30.9.2026: before the first change, write down what was
# there, so that uninstall.sh puts back exactly that instead of guessing.
# For every path this script writes, one line in $RECORD/list:
#
#   absent  <path>   nothing was there - uninstall removes ours
#   saved   <path>   somebody else's file was there; a copy is in
#                    $RECORD/saved<path>, and uninstall puts it back
#   older   <path>   ours already, from an install.sh older than the record:
#                    what was there before that is not known any more, and
#                    uninstall removes it as it always did - and says so
#   dir     <path>   a directory this script had to create; uninstall
#                    removes it again if it is empty
#
# Written once per path and never again: a reinstall finds the line and
# leaves it, because by then the file at that path is ours. It lives with
# secctl's own state, in /etc/furios-security, which uninstall.sh takes out
# last - after it has used the record.
RECORD=$DESTDIR/etc/furios-security/installed

recorded() {
    awk -F'\t' -v p="$1" '$2 == p { found = 1 } END { exit !found }' \
        "$RECORD/list" 2>/dev/null
}

record_line() {
    printf '%s\t%s\n' "$1" "$2" | sudo tee -a "$RECORD/list" >/dev/null
}

# The directories on the way to $1 that do not exist yet - they are about to
# be created by "install -D" and have to be taken out again.
remember_dirs() {
    local d missing=()
    d=$(dirname "$1")
    while [ ! -e "$d" ]; do
        missing+=("$d")
        d=$(dirname "$d")
    done
    for d in "${missing[@]}"; do
        recorded "${d#"$DESTDIR"}" || record_line dir "${d#"$DESTDIR"}"
    done
}

# remember <path> <text only our own copy contains>
remember() {
    local path=$1 sig=$2 rel=${1#"$DESTDIR"}
    recorded "$rel" && return 0
    remember_dirs "$path"
    if [ ! -e "$path" ]; then
        record_line absent "$rel"
    elif grep -qsaF -- "$sig" "$path"; then
        record_line older "$rel"
        echo "no record of what was at $rel before the first installation" \
             "- uninstall.sh will remove it, as it always did" >&2
    else
        sudo install -D -m600 /dev/null "$RECORD/saved$rel"
        sudo cp -a "$path" "$RECORD/saved$rel"
        record_line saved "$rel"
        echo "kept somebody else's $rel - uninstall.sh puts it back" >&2
    fi
}

# The record's own directory first, and the ones it had to create for it.
new_dirs=()
d=$RECORD
while [ ! -e "$d" ]; do
    new_dirs+=("$d")
    d=$(dirname "$d")
done
sudo mkdir -p "$RECORD"
for d in "${new_dirs[@]}"; do
    recorded "${d#"$DESTDIR"}" || record_line dir "${d#"$DESTDIR"}"
done

# Everything written below, before any of it is. What identifies an older
# copy as ours: the marker secctl carries, the action's name, the lockout
# state path compiled into the module. The documentation lives in a
# directory of our own name, so anything in it is ours.
remember "$BIN/secctl" "furios-security: managed file"
remember "$POLKIT/de.misc-de.secctl.policy" "de.misc-de.secctl"
for f in README.md FINDINGS.md NOTICE; do
    remember "$DOC/$f" ""
done
remember "$PAMDIR/pam_furios_lockout.so" "furios-lockout"
remember "$PAMDIR/pam_furios_lockout.so.new" "furios-lockout"

sudo install -Dm755 secctl "$BIN/secctl"
sudo install -Dm644 polkit/de.misc-de.secctl.policy \
    "$POLKIT/de.misc-de.secctl.policy"
sudo install -Dm644 README.md FINDINGS.md NOTICE -t "$DOC"

# The lock-screen module. Where PAM looks first: the multiarch directory.
# Built into a temporary file and put in place whole - PAM loads it on the
# next unlock, and a half-copied file there would be a lock screen that no
# longer opens once the lockout is switched on.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
gcc -shared -fPIC -O2 -Wall -Wextra -Werror -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now \
    -o "$tmp/pam_furios_lockout.so" pam/pam_furios_lockout.c -lpam
sudo install -Dm644 "$tmp/pam_furios_lockout.so" "$PAMDIR/pam_furios_lockout.so.new"
sudo mv -f "$PAMDIR/pam_furios_lockout.so.new" "$PAMDIR/pam_furios_lockout.so"

# What is already on gets this version's files: an older one wrote the PAM
# line as "requisite" (a module that fails to load after an update locked
# every login out), the firewall unit without a start timeout and sysctl keys
# a newer kernel may not have. Only parts that are on - nothing is switched on
# here that was off.
for part in sysctl firewall lockout; do
    state=$("${SECCTL[@]}" status --json 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["parts"][sys.argv[1]]["state"])' "$part" 2>/dev/null)
    if [ "$state" = on ]; then
        sudo "${SECCTL[@]}" apply "$part" >/dev/null && echo "refreshed: $part"
    fi
done

echo
echo "Installed. Nothing has been switched on."
echo
"${SECCTL[@]}" status || true
cat <<'HINT'

Turn it on, one part at a time or all at once:

    sudo secctl lan auto          # or: sudo secctl lan 192.168.0.0/24
    sudo secctl apply sysctl
    sudo secctl apply modules
    sudo secctl apply firewall
    sudo secctl apply lockout     # lock screen: 3 wrong PINs, 5 min, 10, 15 ...

The firewall refuses to come up until the home network is set - with a
default of drop and no rule for your own subnet it would take SSH with it.

Or use the app, under "Security".
HINT
