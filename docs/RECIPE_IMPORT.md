# PKGBUILD import contract

Corinth can convert a pinned Arch `PKGBUILD` into an Arach recipe without
executing package shell code. The conversion is target-aware, but it is not a
shell translator:

```text
PKGBUILD metadata + checksums
             │
             ▼
  static importer (no sourcing)
             │
             ├── exact package name/version/architecture
             ├── HTTPS archive checksums or full Git revisions
             └── HWD-signed target policy
                         │
                         ▼
              canonical Arach recipe + digests
```

The target policy is a detached-signed TOML payload. It is verified with an
Arach-HWD key whose scope is `package-index` before it is used:

```toml
format = 1
package = "example"
architecture = "x86-64"
scope = "system"
publish_authority = "arach-native"
build_system = "cmake"
build_commands = ["cmake -S . -B build", "cmake --build build"]
outputs = ["build/example"]
network = false
sandbox = true
reproducible = true
```

Driver and firmware policies must use `scope = "driver"` or
`scope = "firmware"`, `publish_authority = "arach-hardware"`, and include the
typed driver ABI and health/rollback metadata. System packages must use the
Arach-native authority. A target policy cannot change those authority rules.

Run the conversion with:

```sh
cargo run --locked --features host-store -- \
  import-pkgbuild \
  --pkgbuild PKGBUILD \
  --target TARGET.toml \
  --target-signature TARGET.toml.sig \
  --keyring /etc/arach/hwd/keys.toml \
  --output generated/example.toml
```

The command prints `metadata_sha256` and `source_lock_sha256`. Those values
must be copied into the signed Arach package intent before Corinth will build
or install the recipe. The generated recipe remains subject to the same
sandbox, command allow-list, output measurement, binary-index, and rollback
checks as native recipes.

Unsupported or unsafe input fails closed: dynamic assignments, split package
functions, shell substitutions, unpinned Git branches, missing archive
checksums, unsafe output paths, and arbitrary COSMIC `just` commands are not
translated. Such packages require a separately isolated compatibility worker
whose output is re-measured and re-authorized; it never runs inside Corinth's
native recipe path.
