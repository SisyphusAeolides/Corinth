# Foreign repository adapters

Corinth can consume packaging metadata from Arch/AUR, CRUX, and Nix without
turning any of those package languages into an installation authority.
External metadata is only an input to recipe generation. A detached-signature
Arach target policy supplies architecture, package scope, build adapter,
outputs, sandbox policy, Driver ABI metadata, health checks, and rollback
requirements. The generated recipe must then be measured and admitted by a
signed Corinth or Arach-HWD package intent before it can be installed.

## Unified signed ingress

`corinth-ingest` replaces format-specific orchestration with one signed lock.
The lock separates ecosystem semantics from transport. `arch`, `aur`, `crux`,
and `nix` origins use a pinned HTTPS Git repository, a full 40-hex revision, a
contained metadata path, and an exact metadata SHA-256. This includes GitHub
repositories without making GitHub an authority. CRUX additionally binds the
companion source lock. Metadata repositories cannot enable submodules; source
submodules, when a generated recipe needs them, remain a separately measured
recipe concern. `cargo` origins bind an exact crates.io version,
checksum, package metadata, and dependency atoms.

```toml
format = 1
ecosystem = "aur"
package = "example"

[origin]
kind = "git"
repository = "https://aur.archlinux.org/example.git"
revision = "0123456789abcdef0123456789abcdef01234567"
metadata_path = "PKGBUILD"
metadata_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
submodules = false
```

```toml
format = 1
ecosystem = "cargo"
package = "example"

[origin]
kind = "crates-io"
version = "1.2.3"
release = 1
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
summary = "Example Rust package"
license = "MIT"
architectures = ["x86-64"]
depends = []
makedepends = []
provides = []
conflicts = []
```

The complete ingress lock and target policy are independently verified with
the `package-index` key scope. Corinth then proves source availability,
remeasures metadata, translates through the static adapter, and writes both a
canonical recipe and an ingress receipt. The receipt binds the signed lock,
upstream metadata or crate archive evidence, recipe metadata, and recipe
source-lock digests. It is
evidence for repository admission, not installation authority by itself.

## Trust flow

```text
foreign metadata + immutable source lock
                    |
                    v
          static Corinth adapter
                    |
                    v
       signed Arach target policy
                    |
                    v
          canonical Arach recipe
                    |
                    v
 isolated build -> measured native package -> signed repository index
                    |
                    v
       Corinth install / update / remove
```

Calamares never sources a PKGBUILD, executes a CRUX Pkgfile, or evaluates a Nix
expression. Driver and firmware recipes must use the `arach-hardware` authority
and carry the complete typed hardware policy. System packages must use the
`arach-native` authority.

## Arch and AUR

The existing `import-pkgbuild` command reads a bounded static assignment subset.
Use an exact packaging-repository object ID or a local regular PKGBUILD, plus a
signed target policy. Dynamic assignments, split package functions, command
substitution, unpinned Git sources, and archives without SHA-256 fail closed.

```sh
corinth import-pkgbuild \
  --pkgbuild-git https://aur.archlinux.org/example.git \
    0123456789abcdef0123456789abcdef01234567 PKGBUILD \
  --target /etc/corinth/targets/example.toml \
  --target-signature /etc/corinth/targets/example.toml.sig \
  --keyring /etc/arach/hwd/keys.toml \
  --work /var/cache/corinth/import \
  --output /var/lib/corinth/recipes/example.toml \
  --allow-network
```

AUR is a discovery source, not a trust root. The imported recipe remains
uninstallable until its metadata and source-lock digests appear in a signed
Arach repository record.

## CRUX

`corinth-import-crux` accepts only static `name`, `version`, `release`,
`source`, and `depends` assignments before `build()`. The build function is
never parsed or executed. Every source must match the companion immutable TOML
source lock exactly.

```toml
format = 1

[package]
name = "example-driver"
summary = "Example device driver"
license = "MIT"
architectures = ["x86-64"]
depends = []
makedepends = ["cmake"]
provides = []
conflicts = []

[[source]]
kind = "archive"
url = "https://example.org/example-driver-1.0.tar.gz"
sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

```sh
corinth-import-crux \
  --pkgfile Pkgfile \
  --source-lock sources.lock.toml \
  --target target.toml \
  --target-signature target.toml.sig \
  --keyring /etc/arach/hwd/keys.toml \
  --output /var/lib/corinth/recipes/example-driver.toml
```

Variable expansion, command substitution, local unmeasured source files, shell
operators, and mismatched source order are rejected.

## Nix

`corinth-import-nix` consumes a fixed-output export manifest. It does not embed
a Nix evaluator. A build service may derive the manifest from an already locked
flake or derivation, but the manifest must enumerate the final package identity
and every HTTPS archive digest or full Git object ID.

```toml
format = 1

[package]
name = "example-driver"
version = "1.0.0"
release = 1
summary = "Example device driver"
license = "MIT"
architectures = ["x86-64"]
depends = []
makedepends = ["meson"]
provides = []
conflicts = []

[[source]]
kind = "git"
url = "https://example.org/example-driver.git"
revision = "0123456789abcdef0123456789abcdef01234567"
```

```sh
corinth-import-nix \
  --manifest fixed-output.toml \
  --target target.toml \
  --target-signature target.toml.sig \
  --keyring /etc/arach/hwd/keys.toml \
  --output /var/lib/corinth/recipes/example-driver.toml
```

NAR or derivation output may be used by an isolated build worker, but Corinth
re-measures the native package payload and verifies the signed repository index
before target mutation.

## Package lifecycle

Foreign origin does not change lifecycle semantics. A native package owns only
paths listed in its receipt. Installation validates all target paths before the
first mutation. Update retains the prior receipt and restores it on failure.
Removal refuses to delete modified or unowned files. Driver and firmware
packages additionally require an HWD plan and use the same transaction journal
as kernel, boot, and generation activation.
