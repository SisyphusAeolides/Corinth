#!/usr/bin/env python3
from pathlib import Path

path = Path("src/corpus.rs")
text = path.read_text(encoding="utf-8")
old = "use alloc::{collections::BTreeSet, format, string::String, vec::Vec};\n"
new = """use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};
#[cfg(test)]
use alloc::format;
"""
if text.count(old) != 1:
    raise SystemExit("corpus import line differs")
path.write_text(text.replace(old, new), encoding="utf-8")
