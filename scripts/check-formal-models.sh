#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
idris="${IDRIS2:-idris2}"
agda="${AGDA:-agda}"
idris_source="$root/formal/idris2/CorinthSource.idr"
agda_source="$root/formal/agda/CorinthAuthority.agda"

grep -Fxq '%default total' "$idris_source"
grep -Fxq '{-# OPTIONS --safe --without-K #-}' "$agda_source"
if grep -En 'believe_me|assert_total|assert_smaller|unsafe|(^|[^[:alnum:]_])partial([^[:alnum:]_]|$)|[?][A-Za-z_]|[?][?][?]' "$idris_source"; then
    exit 1
fi
if grep -En '^[[:space:]]*postulate\b|\{![^!]*!\}|TERMINATING|NON_TERMINATING|NO_TERMINATION_CHECK' "$agda_source"; then
    exit 1
fi

scratch="$(mktemp -d "${TMPDIR:-/tmp}/corinth-formal.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT
cp "$idris_source" "$agda_source" "$scratch/"
(
    cd "$scratch"
    "$idris" --check CorinthSource.idr
    XDG_DATA_HOME="$scratch/data" XDG_CONFIG_HOME="$scratch/config" \
        "$agda" --no-libraries --safe --without-K CorinthAuthority.agda
)
