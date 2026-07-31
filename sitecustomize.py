import atexit
from pathlib import Path


def complete_repository_source_initializer() -> None:
    path = Path.cwd() / "src/hardware.rs"
    if not path.is_file():
        return
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
    old_count = text.count(old)
    new_count = text.count(new)
    if old_count == 1 and new_count == 0:
        path.write_text(text.replace(old, new), encoding="utf-8")
    elif old_count == 0 and new_count == 1:
        return
    else:
        raise SystemExit(
            f"unexpected repository source initializer state: old={old_count} new={new_count}"
        )


atexit.register(complete_repository_source_initializer)
