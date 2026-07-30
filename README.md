# Corinth

Corinth is the transactional source and binary package manager for Arach OS.
It stages canonical package-state changes, validates locked source identities,
measures artifacts, commits complete generations atomically, and retains a
bounded rollback history.

Repository authority is typed. crates.io sparse packages and Git revisions are
accepted as locked build inputs; they cannot directly authorize system drivers.
System packages require signed Arach native metadata and artifacts, while
driver and firmware transactions require the separate signed Arach hardware
index consumed by Arach-HWD.

Rust implements the resolver, source gates, package ledger, and native service.
Fortran provides build scheduling telemetry that cannot grant trust. Idris 2
makes source selection total, and Agda proves that crates.io and raw Git sources
cannot acquire system-driver authority.

The canonical generation codec and `host-store` backend provide the installer
with durable package-state publication. Generation files are immutable and
content-addressed; the active pointer is replaced only after the generation is
written and synchronized. Every image names its exact parent, stale publishers
are rejected, and rollback requires the current generation digest before the
parent pointer can be restored. This is durable package state, not yet artifact
deployment: an artifact transaction must bind verified files to the generation
before Arach OS can claim a complete installation.

## Validation

```sh
cargo fmt --all -- --check
cargo test --features fortran-policy,host-store
scripts/check-formal-models.sh
```
