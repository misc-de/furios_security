#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 misc-de
# SPDX-License-Identifier: MIT
"""Every path install.sh puts down, uninstall.sh takes away.

The rule since 30.9.2026: after uninstall.sh, a fresh install has to behave
exactly as on a new phone. The easy way to break that is to add a line to
install.sh and forget its counterpart - which is how the half-copied
pam_furios_lockout.so.new went unnoticed.

Read from the outside, as text: this does not import anything from the
scripts it checks and does not know which paths they are meant to handle. It
reads install.sh the way a shell would (variables, line continuations, sudo,
pipes), collects every destination of install / tee / mv / cp / ln / mkdir,
every unit it enables - and, where there is a packaging/build-deb.sh, the
package that older way in left behind - and then asks whether some rm / rmdir in uninstall.sh
reaches it - exactly, through a glob, or as part of a directory removed
whole - whether each enabled unit is disabled again, and whether the package
is purged.

Usage: test-uninstall-covers-install.py [install.sh] [uninstall.sh]
"""
import fnmatch
import os
import re
import shlex
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

REDIRECT = {">", ">>", "<", ">&", "&>", "<<", "<<<", ">|"}
SEPARATORS = {"|", "||", "&&", ";", "&", "(", ")", "\\;", "{", "}"}


def logical_lines(text):
    """Continuation lines joined, comments and here-documents dropped."""
    out, buf, heredoc = [], "", None
    for raw in text.splitlines():
        if heredoc is not None:
            if raw.strip() == heredoc:
                heredoc = None
            continue
        line = raw.rstrip()
        if not buf and line.lstrip().startswith("#"):
            continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        m = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", buf)
        if m:
            heredoc = m.group(1)
        out.append(buf)
        buf = ""
    if buf:
        out.append(buf)
    return out


def substitute(line, env):
    # A command substitution stands for "some name" - a glob will do.
    line = re.sub(r"\$\([^()]*\)", "*", line)

    def var(m):
        name = m.group(1) or m.group(2)
        return env.get(name, m.group(0))
    return re.sub(r"\$\{(\w+)\}|\$(\w+)", var, line)


def tokens(line):
    lex = shlex.shlex(line, posix=True, punctuation_chars=";&|<>()")
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError:
        return []


def commands(text):
    """Each simple command as a token list, sudo and redirections removed."""
    env = {}
    for line in logical_lines(text):
        line = substitute(line, env)
        m = re.match(r"^\s*([A-Za-z_]\w*)=(\S+)\s*$", line)
        if m:
            val = tokens(m.group(2))
            env[m.group(1)] = val[0] if val else ""
            continue
        cmd, skip = [], False
        for tok in tokens(line) + [";"]:
            if skip:
                skip = False
                continue
            if tok in REDIRECT:
                skip = True
                continue
            if tok in SEPARATORS:
                if cmd:
                    yield cmd
                cmd = []
                continue
            if not cmd and tok in ("sudo", "then", "do", "else", "!", "if",
                                   "while", "until", "exec"):
                continue
            cmd.append(tok)


def absolute(p):
    return p.startswith("/") and "$" not in p and p not in ("/dev/null",)


def install_targets(argv):
    """Destinations of one `install` command line."""
    args, opts_t, is_dir = [], None, False
    it = iter(argv[1:])
    for a in it:
        if a == "-t":
            opts_t = next(it, None)
        elif a.startswith("--target-directory="):
            opts_t = a.split("=", 1)[1]
        elif a.startswith("-") and len(a) > 1:
            if "d" in a.lstrip("-") and not a.startswith("--"):
                is_dir = True
            if a in ("-m", "-o", "-g"):
                next(it, None)
        else:
            args.append(a)
    if is_dir:
        return [(a, True) for a in args]
    if opts_t:
        return [(os.path.join(opts_t, os.path.basename(s) if s != "{}" else "*"),
                 False) for s in args] + [(opts_t, True)]
    if len(args) < 2:
        return []
    dest = args[-1]
    if dest.endswith("/") or len(args) > 2:
        return [(os.path.join(dest, os.path.basename(s) if s != "{}" else "*"),
                 False) for s in args[:-1]]
    return [(dest, False)]


def installed(text):
    """(path, is_dir) for everything install.sh writes, plus enabled units."""
    paths, units = [], []
    for argv in commands(text):
        # find ... -exec install ... {} DIR \;
        if argv[0] == "find" and "-exec" in argv:
            argv = [a for a in argv[argv.index("-exec") + 1:] if a != "sudo"]
        prog = os.path.basename(argv[0])
        if prog == "install":
            paths += install_targets(argv)
        elif prog == "tee":
            paths += [(a, False) for a in argv[1:] if not a.startswith("-")]
        elif prog in ("mv", "cp", "ln"):
            rest = [a for a in argv[1:] if not a.startswith("-")]
            if len(rest) >= 2:
                paths.append((rest[-1], False))
        elif prog == "mkdir":
            paths += [(a, True) for a in argv[1:] if not a.startswith("-")]
        elif prog == "systemctl" and "enable" in argv:
            units += [a for a in argv[argv.index("enable") + 1:]
                      if not a.startswith("-")]
    return [(p, d) for p, d in paths if absolute(p)], units


def removed(text):
    files, trees, dirs, disabled, purged = [], [], [], [], []
    for argv in commands(text):
        prog = os.path.basename(argv[0])
        if prog == "dpkg" and ("--purge" in argv or "-P" in argv):
            purged += [a for a in argv[1:] if not a.startswith("-")]
        elif prog == "apt-get" or prog == "apt":
            if "purge" in argv or "--purge" in argv:
                purged += [a for a in argv[1:] if not a.startswith("-")]
        elif prog == "rm":
            flags = "".join(a for a in argv[1:] if a.startswith("-"))
            recursive = "r" in flags or "R" in flags
            for a in argv[1:]:
                if absolute(a):
                    (trees if recursive else files).append(a)
        elif prog == "rmdir":
            dirs += [a for a in argv[1:] if absolute(a)]
        elif prog == "systemctl" and "disable" in argv:
            disabled += [a for a in argv[argv.index("disable") + 1:]
                         if not a.startswith("-")]
    return files, trees, dirs, disabled, purged


def package_name(build_deb):
    """The package an older .deb installation put down, or None."""
    if not os.path.exists(build_deb):
        return None
    m = re.search(r'^PKG=["\']?([\w.+-]+)', open(build_deb).read(), re.M)
    return m.group(1) if m else None


def covered(path, is_dir, files, trees, dirs):
    for r in files + trees:
        if fnmatch.fnmatchcase(path, r):
            return True
    parts = path.split("/")
    for r in trees:
        for i in range(2, len(parts)):
            if fnmatch.fnmatchcase("/".join(parts[:i]), r):
                return True
    if is_dir:
        return any(fnmatch.fnmatchcase(path.rstrip("/"), r.rstrip("/"))
                   for r in dirs)
    return False


def main(argv):
    inst = argv[1] if len(argv) > 1 else os.path.join(ROOT, "install.sh")
    uninst = argv[2] if len(argv) > 2 else os.path.join(ROOT, "uninstall.sh")
    paths, units = installed(open(inst).read())
    files, trees, dirs, disabled, purged = removed(open(uninst).read())
    pkg = package_name(os.path.join(os.path.dirname(os.path.abspath(inst)),
                                    "packaging", "build-deb.sh"))

    failed = 0
    if not paths:
        print("  \033[31mFAIL\033[0m found nothing install.sh writes - the "
              "reader is broken, not the scripts")
        return 1
    for path, is_dir in sorted(set(paths)):
        if covered(path, is_dir, files, trees, dirs):
            print("  \033[32mok\033[0m   %s" % path)
        else:
            print("  \033[31mFAIL\033[0m install.sh writes %s, uninstall.sh "
                  "never removes it" % path)
            failed += 1
    for unit in sorted(set(units)):
        if unit in disabled:
            print("  \033[32mok\033[0m   %s is disabled again" % unit)
        else:
            print("  \033[31mFAIL\033[0m install.sh enables %s, uninstall.sh "
                  "never disables it" % unit)
            failed += 1
    if pkg:
        if pkg in purged:
            print("  \033[32mok\033[0m   the .deb %s is purged" % pkg)
        else:
            print("  \033[31mFAIL\033[0m packaging/ builds %s, uninstall.sh "
                  "never purges it" % pkg)
            failed += 1
    print("\n  %d paths, %d units, %d not taken back" %
          (len(set(paths)), len(set(units)), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
