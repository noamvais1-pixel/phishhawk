#!/usr/bin/env python3
"""Fail if PhishHawk ever grows a third-party import.

"No dependencies" is a feature, not an accident: the tool has to run on an
air-gapped analysis host with no package index reachable. A stray ``import
requests`` would quietly break that promise, so CI checks it on every push.

Walks the AST of every shipped module and asserts that each top-level import
resolves to the standard library.
"""

from __future__ import annotations

import ast
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKED_DIRS = ("phishhawk", "tests", "samples", "tools")

# Names that are part of this project rather than an external package.
LOCAL_PACKAGES = {"phishhawk"}


def top_level_imports(path: str) -> set[str]:
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            # level > 0 is a relative import, which is always local.
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


def main() -> int:
    stdlib = set(sys.stdlib_module_names)
    offenders: list[tuple[str, str]] = []
    scanned = 0

    for directory in CHECKED_DIRS:
        base = os.path.join(ROOT, directory)
        if not os.path.isdir(base):
            continue
        for current, _, files in os.walk(base):
            for name in sorted(files):
                if not name.endswith(".py"):
                    continue
                path = os.path.join(current, name)
                scanned += 1
                for module in sorted(top_level_imports(path)):
                    if module in stdlib or module in LOCAL_PACKAGES:
                        continue
                    offenders.append((os.path.relpath(path, ROOT), module))

    if offenders:
        print("Third-party imports found — PhishHawk must stay dependency-free:")
        for path, module in offenders:
            print(f"  {path}: {module}")
        return 1

    print(f"Checked {scanned} files across {len(CHECKED_DIRS)} directories.")
    print("Standard library only — as intended.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
