#!/usr/bin/env python3
import subprocess
from pathlib import Path


# These two guarded literals are rewritten to raw-string prefixes by the
# validation workflow before this wrapper runs.
PATCH_LITERAL_MARKERS = r'''
    """        output.extend_from_slice(if source.submodules {
    """        output.extend_from_slice(if source.submodules {
'''


def previous_driver() -> str:
    result = subprocess.run(
        ["git", "show", "HEAD^:scripts/patch-kernel-package-adapter.py"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def run_reviewed_driver() -> None:
    source = previous_driver()
    marker = "    " + '\"\"\"' + "        output.extend_from_slice(if source.submodules {"
    if source.count(marker) != 2:
        raise SystemExit("expected two source-lock patch literals in reviewed driver")
    source = source.replace(marker, "    r" + marker.lstrip())
    exec(compile(source, "scripts/patch-kernel-package-adapter.reviewed.py", "exec"), {})


def complete_repository_source_initializer() -> None:
    path = Path("src/hardware.rs")
    text = path.read_text(encoding="utf-8")
    old = """            version: None,
            submodules,
        })
"""
    new = """            version: None,
            destination: None,
            submodules,
        })
"""
    if text.count(old) != 1:
        raise SystemExit(
            f"expected one repository source initializer, found {text.count(old)}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8")


run_reviewed_driver()
complete_repository_source_initializer()
