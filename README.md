# Corinth

Corinth is the transactional source and binary package manager for Arach OS.
It stages canonical package-state changes, validates locked source identities,
measures artifacts, commits complete generations atomically, and retains a
bounded rollback history.

Repository authority is typed. crates.io sparse packages, archives, and Git
revisions are accepted as locked build inputs; they cannot directly authorize a
system package or driver. System packages require signed Arach native metadata
and artifacts. Driver and firmware transactions additionally require a signed
Arach-HWD provisioning plan and compatible Driver ABI.

Rust implements the resolver, source gates, package ledger, native service,
host recipe executor, and generation store. Fortran provides build scheduling
telemetry that cannot grant trust. Idris 2 makes source selection total, and
Agda proves that raw build sources cannot acquire system-driver authority.

## Current Arach OS integration

The current Arach OS component lock pins Corinth
`017a20599e68c5d374890de33ea611c491e07ec6`.

Arach-Packages validation fetches that exact revision and builds its declared
native outputs rather than substituting a local checkout. Arach OS then
materializes versioned Corinth artifacts into the signed live root and requires
the package manager, package generation, and installer paths before publishing
the SquashFS and UEFI ISO layout.

The host-store generation codec, stale-publisher rejection, rollback checks,
and installer transaction boundary are implemented and tested. The
freestanding `os-bin` still keeps a capability-oriented service boundary until
on-target artifact deployment is connected to the live generation store. The
current release therefore qualifies exact artifact production and image
composition; it does not yet claim a complete package transaction inside a
booted COSMIC session.

## Generation and rollback boundary

The canonical generation codec and `host-store` backend provide the installer
with durable package-state publication. Generation files are immutable and
content-addressed. The active pointer is replaced only after the generation is
written and synchronized. Every generation names its exact parent, stale
publishers are rejected, and rollback requires the current generation digest
before the parent pointer can be restored.

The host-store bridge can consume an Arach-HWD signed provisioning plan, fetch
its exact source revision, run the selected recipe, measure every declared
output, and publish only after the plan's artifact, metadata, and source-lock
digests agree.

## Recipe build matrix

Recipes use one locked source plus an explicit output list. Ordinary recipes do
not invoke a shell; commands are tokenized, allow-listed, and executed with
reproducibility and network policy applied. The special `cosmic` adapter is a
fixed compatibility boundary for the pinned upstream `justfile` and accepts
only its build and install phases.

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
checks. The COSMIC adapter recursively measures its install tree and rejects
symlinks before staging the result.

## Provisioning and native package APIs

The host API is `hardware::verify_plan` followed by
`HardwareProvisioner::build_verified`. With the `host-store` feature, the
`corinth` binary exposes the same transaction boundary through `install`,
`update`, and `remove`.

`--recipes-git URL REV` accepts only a pinned HTTPS recipe repository and still
requires the signed plan's exact metadata and source-lock digests. Network use
is explicit and source retrieval never grants install authority.

Binary repositories use a signed `package-index` key. A native binary can be
installed with:

```text
corinth install --index INDEX --signature SIG --keyring KEYRING
```

Corinth validates the index, downloads or reads the exact artifact, checks its
size and SHA-256, and records the measured output atomically. Supplying
`--root` decodes the signed `ARCPKG01` payload, verifies every file, and performs
a rollback-aware live-root install, update, or removal. Omitting `--root` is an
explicit image-builder staging mode.

Driver and firmware records are refused by the native package path unless a
matching HWD plan is supplied. The complete index schema, payload format,
offline-cache behavior, and generation boundary are documented in
[`docs/BINARY_REPOSITORY.md`](docs/BINARY_REPOSITORY.md).

## External recipe imports

The `arch_import` module parses static PKGBUILD assignments without sourcing
shell. It emits a canonical recipe only when a signed target policy supplies
explicit commands and outputs. Split packages, dynamic variables, unpinned Git
sources, and local shell-only steps fail closed.

```text
corinth import-pkgbuild \
  --pkgbuild PKGBUILD \
  --target TARGET.toml \
  --target-signature TARGET.toml.sig \
  --keyring /etc/arach/hwd/keys.toml \
  --output recipes/generated/package.toml
```

For unattended discovery, Corinth can fetch one official packaging repository
at one exact 40-hex commit and read a path that remains inside the checkout:

```text
corinth import-pkgbuild \
  --pkgbuild-git https://github.com/archlinux/packaging/packages/example.git \
  0123456789abcdef0123456789abcdef01234567 PKGBUILD \
  --target TARGET.toml \
  --target-signature TARGET.toml.sig \
  --keyring /etc/arach/hwd/keys.toml \
  --work /var/cache/corinth/import \
  --output recipes/generated/example.toml \
  --allow-network
```

Symlink traversal and parent components are rejected. The detached HWD policy
still decides how the machine may build and install the imported package.
PKGBUILD, RPM, Debian, and Nix metadata can help discover and port software;
none of those formats is Arach installation authority by itself.

## Validation

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --features fortran-policy,host-store
scripts/check-formal-models.sh
```
