import atexit
from pathlib import Path


def complete_repository_source_initializer() -> None:
    path = Path.cwd() / "src/hardware.rs"
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


atexit.register(complete_repository_source_initializer)
