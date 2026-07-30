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

## Validation

```sh
cargo fmt --all -- --check
cargo test --features fortran-policy
scripts/check-formal-models.sh
```
