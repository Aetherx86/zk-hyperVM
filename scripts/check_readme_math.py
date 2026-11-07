#!/usr/bin/env python3
"""Fails if README math would be damaged by GitHub.

GitHub runs Markdown before MathJax, and Markdown removes the backslash from an escaped punctuation
mark. So \\_ becomes _, which is an error inside \\text{}, and \\{ becomes {, which silently renders
with no braces at all. Math with those sequences has to use the forms Markdown leaves alone: $`...`$
inline, and a ```math fence for display.
"""
import re
import sys

ESCAPED_PUNCTUATION = re.compile(r"\\[!-/:-@\[-`{-~]")
MATH = re.compile(r"(?<![\\$])\$\$?([^$\n]+?)\$\$?")


def main(paths):
    problems = 0
    for path in paths:
        fenced = False
        for number, line in enumerate(open(path, encoding="utf-8"), 1):
            if line.lstrip().startswith("```"):
                fenced = not fenced
                continue
            if fenced:
                continue
            # Code spans are safe, and that includes the $`...`$ form.
            bare = re.sub(r"`[^`]*`", "", line)
            for match in MATH.finditer(bare):
                if ESCAPED_PUNCTUATION.search(match.group(1)):
                    print(f"{path}:{number}: GitHub will damage this math: {match.group(0)[:80]}")
                    problems += 1
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["README.md"]))
