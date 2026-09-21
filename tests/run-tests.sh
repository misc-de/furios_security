#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2026 misc-de
# SPDX-License-Identifier: MIT
# Everything that can be checked without changing this phone.
#
# Runs without a display, without root and without touching the live
# firewall. NEVER with sudo - as root the python suite would write its
# temporary /etc as root and, worse, a mistake in a path would reach the real
# one.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
FAILED=0

if [ "$(id -u)" = 0 ]; then
    echo "never start run-tests.sh with sudo." >&2
    exit 1
fi

run() {
    printf '\n\033[1m== %s\033[0m\n' "$1"
    shift
    if "$@"; then :; else FAILED=$((FAILED + 1)); fi
}

run "secctl: the three parts, their state and their way back" \
    python3 "$HERE/test-secctl.py"

printf '\n\033[1m== the generated ruleset, as nft reads it\033[0m\n'
NFT_BIN=$(command -v nft || echo /usr/sbin/nft)
# "nft -c" parses, but it still opens netlink to resolve the table it is
# asked to delete - so even a check needs root, and this suite must never be
# root. On the phone the same parse happens for real inside "secctl apply
# firewall", which refuses and reports rather than loading half a ruleset.
if [ ! -x "$NFT_BIN" ]; then
    printf '  \033[33mskipped\033[0m - no nft\n'
elif [ "$(id -u)" != 0 ]; then
    printf '  \033[33mskipped\033[0m - nft -c needs root even to check\n'
else
    tmp=$(mktemp -d)
    FURIOS_SECURITY_ROOT="$tmp" python3 - "$ROOT" "$tmp" <<'PY'
import importlib.machinery, importlib.util, os, sys
root, tmp = sys.argv[1], sys.argv[2]
loader = importlib.machinery.SourceFileLoader("secctl", os.path.join(root, "secctl"))
spec = importlib.util.spec_from_loader("secctl", loader)
m = importlib.util.module_from_spec(spec); loader.exec_module(m)
cfg = dict(m.DEFAULT_CONFIG, lan="192.168.0.0/24")
open(os.path.join(tmp, "ruleset.nft"), "w").write(m.firewall_text(cfg))
PY
    if "$NFT_BIN" -c -f "$tmp/ruleset.nft" 2>&1; then
        printf '  \033[32mok\033[0m   nft accepts it\n'
    else
        printf '  \033[31mFAIL\033[0m nft rejected the generated ruleset\n'
        FAILED=$((FAILED + 1))
    fi
    rm -rf "$tmp"
fi

printf '\n\033[1m== the polkit action\033[0m\n'
if python3 -c "import xml.dom.minidom,sys; xml.dom.minidom.parse(sys.argv[1])" \
        "$ROOT/polkit/de.misc-de.secctl.policy" 2>/dev/null; then
    # allow_inactive must stay "no". An SSH login is inactive to polkit, and
    # a yes here would hand the whole point of this project to anybody who
    # got that far.
    if grep -q '<allow_inactive>no</allow_inactive>' \
            "$ROOT/polkit/de.misc-de.secctl.policy"; then
        printf '  \033[32mok\033[0m   well formed, and inactive sessions are refused\n'
    else
        printf '  \033[31mFAIL\033[0m allow_inactive is not "no"\n'
        FAILED=$((FAILED + 1))
    fi
else
    printf '  \033[31mFAIL\033[0m the policy is not well-formed XML\n'
    FAILED=$((FAILED + 1))
fi

printf '\n\033[1m== shell\033[0m\n'
if command -v shellcheck >/dev/null; then
    for f in "$ROOT"/*.sh "$HERE"/*.sh; do
        if shellcheck -x -P "$HERE" "$f"; then
            printf '  \033[32mok\033[0m   %s\n' "${f#"$ROOT"/}"
        else
            FAILED=$((FAILED + 1))
        fi
    done
else
    printf '  \033[33mskipped\033[0m - no shellcheck (apt install shellcheck)\n'
fi

printf '\n\033[1m== SPDX headers\033[0m\n'
missing=0
while IFS= read -r f; do
    if ! head -5 "$f" | grep -q 'SPDX-License-Identifier'; then
        printf '  \033[31mFAIL\033[0m %s without an SPDX header\n' "${f#"$ROOT"/}"
        missing=$((missing + 1))
    fi
done < <(find "$ROOT" -type f \( -name '*.sh' -o -name '*.py' -o -name '*.policy' \
    -o -name secctl \) -not -path '*/.git/*')
if [ "$missing" -eq 0 ]; then
    printf '  \033[32mok\033[0m   every file\n'
else
    FAILED=$((FAILED + 1))
fi

echo
if [ "$FAILED" -eq 0 ]; then
    printf '\033[32mall suites passed\033[0m\n'
else
    printf '\033[31m%d suite(s) failed\033[0m\n' "$FAILED"
fi
exit $((FAILED > 0))
