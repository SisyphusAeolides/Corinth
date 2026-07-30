#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tools="${FORMAL_TOOLCHAIN_ROOT:-$root/target/formal/toolchains}"
bundled_idris="$tools/Idris2-0.8.0/build/exec/idris2"
bundled_agda="$tools/Agda-v2.8.0-linux/agda"
if [[ -n "${IDRIS2:-}" ]]; then
    idris="$IDRIS2"
elif [[ -x "$bundled_idris" ]]; then
    idris="$bundled_idris"
    export IDRIS2_PATH="$tools/Idris2-0.8.0/libs/prelude/build/ttc:$tools/Idris2-0.8.0/libs/base/build/ttc"
else
    idris="idris2"
fi
if [[ -n "${AGDA:-}" ]]; then
    agda="$AGDA"
elif [[ -x "$bundled_agda" ]]; then
    agda="$bundled_agda"
else
    agda="agda"
fi
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
