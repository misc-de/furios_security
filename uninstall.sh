#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2026 misc-de
# SPDX-License-Identifier: MIT
#
# Takes everything back out - and, first, everything that was switched on.
# The order matters: the hardening has to be reverted before the program that
# knows how to revert it is deleted.
#
# What goes back is what the records say was there, not what we assume:
# secctl's own (state.json, see README) for everything it switched on, and
# install.sh's ($RECORD/list) for the files it put down. Where there is no
# record - an installation older than the records - it removes ours as it
# always did, and says so.
#
#   ./uninstall.sh           stops before removing anything if secctl could
#                            not take every part back
#   ./uninstall.sh --force   removes everything anyway
set -uo pipefail

if [ "$(id -u)" = 0 ]; then
    echo "Please run WITHOUT sudo." >&2
    exit 1
fi

FORCE=0
[ "${1:-}" = --force ] && FORCE=1

# DESTDIR is for the tests only, as in install.sh.
: "${DESTDIR:=}"

BIN=$DESTDIR/usr/local/bin
POLKIT=$DESTDIR/usr/share/polkit-1/actions
DOC=$DESTDIR/usr/local/share/doc/furios-security
STATE=$DESTDIR/etc/furios-security
RECORD=$STATE/installed
if [ -n "$DESTDIR" ]; then
    SECCTL=(env FURIOS_SECURITY_ROOT="$DESTDIR" "$BIN/secctl")
else
    SECCTL=("$BIN/secctl")
fi

# Not "|| true" any more. A part secctl could not take back is still on, and
# its record of what was there before is in state.json - removing secctl and
# that file now would leave it on for good, with nothing on the phone that
# knows the way back.
if [ -x "$BIN/secctl" ]; then
    if ! sudo "${SECCTL[@]}" revert all; then
        if [ "$FORCE" = 0 ]; then
            cat >&2 <<'MSG'

secctl could not take everything back - see above. Nothing has been removed:
secctl and its records of what was there before stay, so it can still finish.
Sort out what it named and run ./uninstall.sh again - or ./uninstall.sh --force
to remove everything anyway, records included.
MSG
            exit 1
        fi
        echo "--force: going on, although not everything was taken back." >&2
    fi
fi

if [ ! -e "$RECORD/list" ]; then
    echo "no install record (installed by an older install.sh) - removing" \
         "our files as before; what was at those paths before is not known" >&2
fi

# put_back <text only our own copy contains> <path>...
#
# What install.sh's record says about one path, done: a file of somebody
# else's that was there is copied back (through a temporary name and a
# rename, so it is never half there), one that was not there is removed.
# Only while the file is still ours - one somebody replaced since is theirs
# and is left. No signature (the documentation, in a directory of our own
# name) means anything there is ours.
put_back() {
    local sig=$1 path rel kind
    shift
    for path in "$@"; do
        rel=${path#"$DESTDIR"}
        kind=$(awk -F'\t' -v p="$rel" '$2 == p { k = $1 } END { print k }' \
            "$RECORD/list" 2>/dev/null)
        if [ -e "$path" ] && [ -n "$sig" ] && ! grep -qsaF -- "$sig" "$path"; then
            echo "$rel is not ours any more - left as it is" >&2
            continue
        fi
        case "$kind" in
            saved)
                sudo cp -a "$RECORD/saved$rel" "$path.furios-restore" \
                    && sudo mv -f "$path.furios-restore" "$path" \
                    && echo "put back the $rel that was there before"
                ;;
            older)
                sudo rm -f "$path"
                echo "no record of what was at $rel before the first" \
                     "installation - removed ours" >&2
                ;;
            *)
                # "absent", or no record at all (said once, above). A glob
                # that matched nothing arrives here as itself: rm -f of a
                # name that does not exist.
                sudo rm -f "$path"
                ;;
        esac
    done
}

put_back "furios-security: managed file" "$BIN/secctl"
put_back "de.misc-de.secctl" "$POLKIT/de.misc-de.secctl.policy"
put_back "" "$DOC/README.md" "$DOC/FINDINGS.md" "$DOC/NOTICE"
sudo rmdir "$DOC" 2>/dev/null

# Only now: revert above took it out of the login stack, and a stack that
# names a missing module fails every login, sudo included.
# The .so.new is install.sh's half-copied file from a run that stopped
# between install and mv.
if ! grep -qs pam_furios_lockout "$DESTDIR/etc/pam.d/common-auth" \
        "$DESTDIR/etc/pam.d/common-account"; then
    put_back "furios-lockout" \
        "$DESTDIR"/usr/lib/*/security/pam_furios_lockout.so \
        "$DESTDIR"/usr/lib/*/security/pam_furios_lockout.so.new
    # pam-auth-update lists every profile it has seen in /var/lib/pam/seen.
    # secctl's revert puts that file back from its record; this is for a
    # lockout switched on by an older secctl, which kept none. Only our own
    # line, and only once the profile itself is gone.
    if [ ! -e "$DESTDIR/usr/share/pam-configs/furios-lockout" ] \
       && grep -qx furios-lockout "$DESTDIR/var/lib/pam/seen" 2>/dev/null; then
        sudo sed -i '/^furios-lockout$/d' "$DESTDIR/var/lib/pam/seen"
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
    [ -d "$DESTDIR$home/.local/state/furios-lockout" ] || continue
    sudo rm -rf "$DESTDIR$home/.local/state/furios-lockout"
done

# The directories install.sh had to create, read before the record goes -
# deepest first, and each only if empty: somebody may have put something of
# their own in /usr/local/share/doc since.
mapfile -t made < <(awk -F'\t' '$1 == "dir" { print length($2) "\t" $2 }' \
    "$RECORD/list" 2>/dev/null | sort -rn | cut -f2-)

# The state directory last. Our own files go: config.json and state.json are
# written by secctl itself (revert above rewrites state.json), and left behind
# they hand an old SSH/LAN choice to the next installation - found on
# 30.9.2026 in a clean-install test. The directory itself only goes when that
# leaves it empty: an older secctl kept its copy of /etc/nftables.conf in it,
# and one still there means revert did not put it back.
sudo rm -f "$STATE/config.json" "$STATE/state.json" "$STATE/firewall.nft"
sudo rm -rf "$RECORD"
sudo rmdir "$STATE" 2>/dev/null
for d in "${made[@]}"; do
    [ -n "$d" ] && sudo rmdir "$DESTDIR$d" 2>/dev/null
done

echo "Removed."
echo "Note: kernel.unprivileged_bpf_disabled cannot be cleared on a running"
echo "kernel - it goes back to what it was at the next boot."
