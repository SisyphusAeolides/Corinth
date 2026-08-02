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

The Arach OS component lock is the authority for the exact Corinth revision
used by a release.

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
digests agree. Plan verification reproduces the signed Driver ABI bounds,
health checks, rollback policy, recovery policy, and CPU compiler policy; these
fields cannot be changed after profile verification.

## Recipe build matrix

Recipes use one or more locked sources plus an explicit output list. Ordinary recipes do
not invoke a shell; commands are tokenized, allow-listed, and executed with
reproducibility and network policy applied. Every admitted build phase runs in
a fresh bubblewrap boundary with a private process/session/IPC/UTS namespace,
no capabilities, an isolated temporary HOME, read-only toolchains and caches,
and only its measured source tree writable. Offline recipes also receive an
isolated network namespace. Corinth fails closed when this boundary is absent
or mutable. The special `cosmic` adapter is a fixed compatibility boundary for
the pinned upstream `justfile` and accepts only its build and install phases.

For native builds, Corinth re-observes the local CPU and requires an exact
match with HWD's architecture/vendor/family/model/stepping identity. It then
recomputes the intersection of observed features and the signed profile's
allowed feature set. Only closed typed capabilities are translated to
`CFLAGS`, `CXXFLAGS`, `FFLAGS`, and `RUSTFLAGS` inside bubblewrap. Raw flags,
model names, and vendor strings never become command input; absent compiler
policy produces a portable architecture baseline.

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

The standard host interface searches every repository named by signed service
metadata and needs no per-repository flags:

```text
corinth search example
corinth install example
corinth update example
corinth remove example
```

Native Arach packages outrank source catalogs. Native indexes and source
catalogs retain multiple exact versions and use a signed monotonic sequence
for deterministic defaults; `PACKAGE@VERSION` is an exact pin. Equal-priority
conflicts fail as ambiguous; `PROVIDER:PACKAGE` is the explicit override.
Updates retain the installed provider and channel and reject lower service,
repository, or package sequences. Removal is entirely receipt-driven and
offline after it verifies that no remaining package requires the target.

Every standard install and update solves signed runtime requirements,
alternatives, exact retained-version sets, virtual capabilities, and conflicts
against the fixed installed set. Corinth prepares the dependency-first closure,
writes one graph journal, installs new dependencies, and commits the requested
root last. Interrupted partial graphs roll back when the root is absent or
still old; fully owned graphs roll forward. Signed source entries run the same
graph boundary after the immutable-lock, target-policy, canonical recipe,
sandboxed build, and measurement checks. Source build dependencies resolve as
a separate dependency-first closure from authenticated native indexes. Corinth
materializes that closure in a fresh private root, exposes it read-only only to
the build sandbox, records every selected artifact in the source receipt, and
removes the root without publishing build-only tools into the target system.
The configuration and source-catalog formats are documented in
[`docs/PACKAGE_SERVICE.md`](docs/PACKAGE_SERVICE.md).

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

`corinth-discover` resolves mutable Arch, AUR, Fedora, Debian, Alpine, Gentoo,
CRUX, and Nix provider references into unsigned candidates containing only
exact Git commits and measured metadata. Arch and AUR repository identities
are derived from the package name. The other Git-backed ecosystems accept an
explicit HTTPS transport; Fedora specs, Debian control files, Alpine
APKBUILDs, Gentoo ebuilds, and CRUX Pkgfiles also require an independently
measured source manifest. Discovery cannot emit a recipe or install anything.
Cargo discovery resolves an exact crate version into a complete `Cargo.lock`,
binds every transitive registry archive checksum, and produces recipes that
materialize the graph through an offline directory source. The provider
contract and examples are documented in
[`docs/UNIVERSAL_DISCOVERY.md`](docs/UNIVERSAL_DISCOVERY.md).

Normal users do not invoke discovery or ingestion. Repository infrastructure
publishes their admitted outputs through a signed source catalog; the ordinary
`corinth install` and `corinth update` commands consume that catalog directly.

`corinth-ingest` is the unified unattended ingress path. It verifies a signed
ingress lock and a separately signed target policy, resolves only an exact Git
object or checksummed crates.io archive, remeasures upstream metadata, emits
one canonical recipe, and writes a receipt binding the ingress lock, upstream
evidence, recipe, and recipe source-lock digests. Arch and AUR PKGBUILDs,
Fedora specs, Debian control files, Alpine APKBUILDs, Gentoo ebuilds, CRUX
Pkgfiles, fixed-output Nix exports, Cargo crates, and GitHub-hosted repositories
therefore use one reproducibility boundary:

```text
corinth-ingest \
  --lock ingress.toml \
  --lock-signature ingress.toml.sig \
  --target target.toml \
  --target-signature target.toml.sig \
  --keyring /etc/arach/hwd/keys.toml \
  --work /var/cache/corinth/ingress \
  --output /var/lib/corinth/recipes/example.toml \
  --receipt /var/lib/corinth/receipts/example.toml \
  --allow-network
```

GitHub is transport rather than package authority. The lock names the package
ecosystem, repository, full revision, bounded metadata path, and SHA-256.
Cargo locks instead name an exact crates.io package version and archive
checksum. A discovered candidate cannot skip either signature or install
directly; normal signed repository admission, measured build, and generation
publication remain downstream.

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

Symlink traversal and parent components are rejected. The detached package
policy still decides how the machine may build the imported package; a
separate HWD plan is required before any driver or firmware installation.
For non-Arch ecosystems, the `corinth-import-foreign` host worker accepts only
static, source-locked metadata:

```text
corinth-import-foreign \
  --format <fedora|debian|alpine|gentoo> \
  --input METADATA \
  --source-lock SOURCES.toml \
  --target TARGET.toml \
  --target-signature TARGET.toml.sig \
  --keyring /etc/arach/hwd/keys.toml \
  --output recipes/generated/package.toml
```

Fedora spec preambles, Debian control stanzas, Alpine APKBUILD assignments,
and Gentoo ebuild variable preambles are parsed without shell evaluation.
Macros, phase functions, versioned or alternative dependency expressions,
unlocked URLs, checksum drift, and unsupported architectures fail closed. The
signed target policy still chooses the actual Arach build adapter and outputs;
foreign metadata never becomes installation authority by itself. Packages that
need dynamic upstream scripts belong in a separately sandboxed compatibility
worker and are not silently admitted by these parsers.

These four static adapters also enter the signed universal ingress and source
catalog consumed by ordinary `corinth install` and `corinth update`; the
format-specific worker remains available for repository diagnostics. Arch
PKGBUILD, Fedora, Debian, Alpine, Gentoo, CRUX, fixed-output Nix, and Cargo
metadata therefore enter one measured recipe pipeline while retaining native
Arach signature, source-lock, artifact, and rollback requirements.

## Validation

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --features fortran-policy,host-store
scripts/check-formal-models.sh
```
