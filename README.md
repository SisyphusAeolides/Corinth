# Corinth

Corinth is the transactional source and binary package manager for Arach OS.
It stages canonical package-state changes, validates locked source identities,
measures artifacts, commits complete generations atomically, and retains a
bounded rollback history. The host-store bridge can also consume an
Arach-HWD signed provisioning plan, fetch its exact source revision, run a
recipe, measure every declared output, and publish the result only after all
three plan digests agree.

Repository authority is typed. crates.io sparse packages and Git revisions are
accepted as locked build inputs; they cannot directly authorize system drivers.
System packages require signed Arach native metadata and artifacts, while
driver and firmware transactions require the separate signed Arach hardware
index consumed by Arach-HWD.

Rust implements the resolver, source gates, package ledger, native service,
and host recipe executor. Fortran provides build scheduling telemetry that
cannot grant trust. Idris 2 makes source selection total, and Agda proves that
crates.io and raw Git sources cannot acquire system-driver authority.

The canonical generation codec and `host-store` backend provide the installer
with durable package-state publication. Generation files are immutable and
content-addressed; the active pointer is replaced only after the generation is
written and synchronized. Every image names its exact parent, stale publishers
are rejected, and rollback requires the current generation digest before the
parent pointer can be restored.

## Recipe build matrix

Recipes are source-based and use one locked source plus an explicit output
list. Ordinary recipes never invoke a shell; commands are tokenized,
allow-listed, and run with reproducibility and network policy applied. The
special `cosmic` adapter is a fixed compatibility boundary for the pinned
upstream `justfile` and accepts only its build/install phases.

| Recipe system | Supported toolchain examples | Source inputs |
| --- | --- | --- |
| `cargo` | Rust workspaces and binaries | Git, crates.io archive, local cache |
| `c` | `cc`, GCC, Clang, Make | Git or local cache |
| `fortran` | `gfortran`, Flang, Make | Git or local cache |
| `idris2` | Idris 2 compiler | Git or local cache |
| `agda` | Agda compiler/checker | Git or local cache |
| `cmake`, `meson`, `custom` | native projects using the allow-list | Git or local cache |
| `cosmic` | pinned COSMIC Epoch workspace adapter | Git with locked submodules |

The source lock, recipe metadata, and measured artifact digest are independent
checks. crates.io, Git, and local sources are build inputs; they do not grant
system, driver, or firmware authority. System packages require Arach-native
metadata, while drivers and firmware must arrive through an Ed25519-verified
Arach-HWD plan with a compatible Driver ABI and health/rollback policy.
The COSMIC adapter recursively measures its install tree and rejects symlinks
before staging the result.

The host API is `hardware::verify_plan` followed by
`HardwareProvisioner::build_verified`. With the `host-store` feature, the
`corinth` binary exposes the same transaction boundary through
`install`, `update`, and `remove`; `--recipes-git URL REV` accepts only a
pinned HTTPS recipe repository and still requires the signed plan's exact
metadata and source-lock digests. The freestanding `os-bin` keeps its
capability-oriented service boundary until artifact deployment is bound to the
live generation store.

Binary repositories use a signed `package-index` key. A native binary can be
installed with `--index INDEX --signature SIG --keyring KEYRING`; Corinth
validates the index, downloads the exact HTTPS artifact, checks its size and
SHA-256, and records the measured output atomically. Supplying `--root`
decodes the signed `ARCPKG01` payload, verifies every file, and performs a
rollback-aware live-root install/update/remove; omitting it is an explicit
image-builder staging mode. Driver and firmware records are refused by this
path unless a matching HWD plan is supplied. The complete index schema,
payload format, offline-cache behavior, and generation boundary are documented
in [`docs/BINARY_REPOSITORY.md`](docs/BINARY_REPOSITORY.md).

The `arch_import` module parses static PKGBUILD assignments without sourcing
shell. It emits a canonical recipe only when a target policy supplies explicit
commands and outputs. Split packages, dynamic variables, unpinned Git sources,
and local shell-only steps fail closed and must use a separately sandboxed
compatibility worker.

The host CLI exposes that conversion boundary directly:

```text
corinth import-pkgbuild \
  --pkgbuild PKGBUILD \
  --target TARGET.toml \
  --target-signature TARGET.toml.sig \
  --keyring /etc/arach/hwd/keys.toml \
  --output recipes/generated/package.toml
```

`TARGET.toml` is the signed, target-specific policy emitted by the Arach-HWD
policy pipeline. Corinth verifies it with the `package-index` key scope,
binds its package name to the parsed PKGBUILD, and prints the metadata and
source-lock digests needed for the signed Arach package intent. The generated
recipe is not an install authorization by itself; the normal Arach-HWD plan,
repository authority, and measured artifact gates still apply.

## External recipe sources

Corinth should import, rather than execute unchanged, the large ecosystems
that already describe packages. The first adapter should target the official
Arch packaging Git repositories (`archlinux/packaging/packages/*`) and the
`pkgctl`/`makepkg` workflow:

* Arch Build System `PKGBUILD` trees provide broad source coverage, but their
  `prepare()`, `build()`, and `package()` bodies are shell programs. The
  importer should pin the package Git commit, parse metadata and checksums,
  and emit a canonical Corinth recipe. If the legacy body is needed, it must
  run in a separately sandboxed compatibility worker; it must never run inside
  the Corinth service or silently acquire Arach authority.
* Fedora RPM spec files and Debian `debian/rules` expose useful dependency and
  file metadata, but macros and maintainer scripts are likewise compatibility
  inputs, never native Corinth authority.
* Nixpkgs derivations are an excellent source of pinned hashes and dependency
  graphs. A Nix evaluator can export a signed intermediate manifest; Corinth
  should not embed an unrestricted Nix language evaluator in the package
  service.

The import boundary produces the same recipe, source-lock, SBOM, and artifact
digest used by native Arach-Packages. Imported metadata can help discover and
port software; only an Arach signature or an Arach-HWD plan can authorize a
system, driver, or firmware transaction. This gives Corinth broad source
coverage without pretending that a PKGBUILD, RPM spec, Debian rules file, or
Nix expression is itself a portable, trusted package.

## Validation

```sh
cargo fmt --all -- --check
cargo test --locked --features fortran-policy,host-store
scripts/check-formal-models.sh
```
