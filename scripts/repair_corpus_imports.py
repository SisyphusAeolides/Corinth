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

path = Path("src/semantics.rs")
text = path.read_text(encoding="utf-8")
old = ".zip([b'r', b'w', b'x'])"
new = '.zip(*b"rwx")'
if text.count(old) != 1:
    raise SystemExit("permission byte slice differs")
path.write_text(text.replace(old, new), encoding="utf-8")

path = Path("src/bin/corinth-corpus.rs")
text = path.read_text(encoding="utf-8")
old = '''fn parse_flags(
    arguments: Vec<String>,
) -> Result<(BTreeMap<String, PathBuf>, bool, Option<u16>), String> {
'''
new = '''type ParsedFlags = (BTreeMap<String, PathBuf>, bool, Option<u16>);

fn parse_flags(arguments: Vec<String>) -> Result<ParsedFlags, String> {
'''
if text.count(old) != 1:
    raise SystemExit("corpus flag signature differs")
path.write_text(text.replace(old, new), encoding="utf-8")
