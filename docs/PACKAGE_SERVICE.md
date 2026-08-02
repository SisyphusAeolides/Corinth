# Corinth package service

The ordinary package interface is deliberately small:

```text
corinth search PACKAGE
corinth install PACKAGE
corinth update PACKAGE
corinth remove PACKAGE
```

These commands load `/etc/corinth/service.toml`, its detached
`service.toml.sig`, and `/etc/arach/hwd/keys.toml`. `--config`,
`--config-signature`, and `--keyring` select an alternate signed deployment.
`--offline` forbids new downloads and permits only objects already present in
the digest-addressed cache.

`PACKAGE@VERSION` selects an exact catalog version. `PROVIDER:PACKAGE` selects
one configured provider explicitly. Ecosystem namespaces such as
`aur:PACKAGE` and `cargo:PACKAGE` are also accepted when more than one source
catalog is configured.

Signed native index format `3` and signed source catalog format `2` may both retain
multiple exact versions. An unversioned request selects the greatest
publisher-assigned package `sequence`; Corinth deliberately does not compare
foreign version syntaxes. Exact pins can select an older retained version for
initial installation, while updates still reject any sequence lower than the
installed receipt. Native index format `2` remains readable as a dependency-free
multi-version index, native format `1` remains readable as a single-version
index with sequence zero, and source catalog format `1` remains readable
without dependency metadata.

## Resolution contract

One invocation authenticates every configured index and source catalog before
it selects a package. A missing, expired, digest-mismatched, or incorrectly
signed provider is an error; an unavailable native repository cannot silently
turn an install into a lower-trust source build.

Resolution follows these rules:

1. retain the requested package, architecture, channel, and optional exact
   version from every configured provider;
2. prefer native Arach binary records whenever any are available;
3. retain only candidates at the highest configured priority in that route;
4. accept duplicate evidence only when the complete package identity agrees;
5. report conflicting equal-priority providers as ambiguous;
6. expand every signed runtime requirement into package and virtual-capability
   providers from every authenticated repository;
7. solve requirements, alternatives, exact retained-version sets, provides,
   conflicts, and the fixed installed set as one bounded graph;
8. reject cycles, ambiguity, unsatisfied clauses, and graph-capacity overflow
   before downloading or mutating the target;
9. on update, retain the installed provider, route, and channel and enforce
   monotonic service and provider generations plus package sequence.

`remove` never searches an upstream repository. It uses the local service
provenance receipt and the binary ownership receipt, verifies that they agree,
and removes only unmodified files owned by that package. It authenticates the
metadata for the remaining installed set and refuses a removal that would
leave another package's runtime requirement unsatisfied. Dependencies that
become unreferenced are left installed for an explicit later removal; there is
no implicit orphan garbage collection.

Service receipt format `2` stores the exact signed requirements, provides, and
conflicts selected at installation time. This keeps reverse-dependency checks
local and prevents a repository from rewriting the installed closure without
an update. Legacy receipt format `1` remains readable with an empty dependency
closure, matching the dependency-free catalog formats that produced it.

## Signed service configuration

The configuration is package-index-signed root metadata. Every referenced
provider document and detached signature is independently digest-bound. Local
resources must use normalized absolute paths; remote resources must use HTTPS.

```toml
format = 1
key_id = "0123456789abcdef0123456789abcdef"
generation = 42
channel = "stable"
expires_unix = 1893456000
state = "/var/lib/corinth"
work = "/var/cache/corinth/work"
artifacts = "/var/cache/corinth/artifacts"
root = "/"
allow_network = true

[compiler]
architecture = "x86-64"
allowed_features = ["sse2", "sse3", "ssse3", "sse41", "sse42", "avx", "avx2"]
required_features = ["sse2"]

[[native]]
name = "arach-stable"
priority = 1000
generation = 42
channel = "stable"
architectures = ["x86-64"]
index = "https://packages.arach.example/stable/x86-64/index.toml"
index_sha256 = "<64 lowercase hex characters>"
signature = "https://packages.arach.example/stable/x86-64/index.toml.sig"
signature_sha256 = "<64 lowercase hex characters>"

[[source]]
name = "curated-aur"
priority = 500
generation = 17
channel = "stable"
architectures = ["x86-64"]
catalog = "https://packages.arach.example/source/aur.toml"
catalog_sha256 = "<64 lowercase hex characters>"
signature = "https://packages.arach.example/source/aur.toml.sig"
signature_sha256 = "<64 lowercase hex characters>"
```

State, work, and artifact roots must be private, non-overlapping directories.
The signed compiler policy is a capability ceiling. For source builds,
Arach-HWD observes the host CPU and Corinth passes only the intersection of
observed and allowed typed features to Rust, C, C++, and Fortran compilers.

## Signed source catalogs

A source catalog is generated by repository infrastructure after discovery,
review, and signature admission. It may retain several exact versions of a
package; the largest monotonic `sequence` is the default for the configured
channel.

```toml
format = 2
key_id = "0123456789abcdef0123456789abcdef"
name = "curated-aur"
channel = "stable"
generation = 17
expires_unix = 1893456000

[[package]]
name = "example"
version = "1.2.3"
release = 1
sequence = 9
ecosystem = "aur"
architectures = ["x86-64"]
ingress_lock = "https://packages.arach.example/source/example.lock.toml"
ingress_lock_sha256 = "<64 lowercase hex characters>"
ingress_signature = "https://packages.arach.example/source/example.lock.toml.sig"
ingress_signature_sha256 = "<64 lowercase hex characters>"
target_policy = "https://packages.arach.example/source/example.target.toml"
target_policy_sha256 = "<64 lowercase hex characters>"
target_signature = "https://packages.arach.example/source/example.target.toml.sig"
target_signature_sha256 = "<64 lowercase hex characters>"
recipe_sha256 = "<64 lowercase hex characters>"
source_lock_sha256 = "<64 lowercase hex characters>"

[[package.requirements]]

[[package.requirements.alternatives]]
name = "ssl-api"
versions = ["3"]

[[package.provides]]
name = "example-api"
version = "1.2.3"

[[package.conflicts]]
name = "example-legacy"
versions = []
```

Each `requirements` entry is one clause and must have at least one
`alternatives` entry. A constraint can name a concrete package or a capability
declared by `provides`. An empty `versions` list accepts any retained version.
Repository publication converts each ecosystem's native range semantics into
a sorted set of exact versions retained by that signed snapshot; the client
does not pretend that Arch, Nix, Cargo, Debian, and RPM versions share one
comparison algorithm.

Both the immutable ingress lock and target policy carry their own
package-index signatures. Corinth then checks out the exact Git commit or
checksummed crates.io closure, remeasures upstream metadata, regenerates the
canonical recipe, and requires its recipe and source-lock digests to equal the
catalog. The admitted recipe must be a sandboxed, reproducible native system
recipe that publishes `@install-tree`. The resulting locally optimized build
is measured and installed through the same ownership-aware payload boundary as
a native binary package. Package-service builds expose only OS-managed
toolchains under `/usr`; mutable per-user Cargo, Rustup, Idris, and Agda
installations and caches are not mounted into the build sandbox.

Source recipes may carry runtime dependency, capability, and conflict atoms
when the signed catalog metadata agrees with the regenerated canonical recipe.
Those runtime requirements enter the same solver and graph journal as native
packages. Build dependencies enter a separate bounded graph whose candidates
must come from authenticated native indexes. Corinth materializes the selected
dependency-first closure under a fresh private root and mounts it read-only at
`/corinth-build` for the admitted source build. The sandbox receives bounded
tool, compiler, linker, CMake, and pkg-config search paths rooted there. It does
not receive the live target root. Every selected native artifact, provider,
authority sequence, index digest, metadata digest, and source-lock digest is
retained in the source receipt; the temporary root is removed after the build.
An unresolved or source-only build dependency fails before target mutation.

Arch and AUR locks parse static PKGBUILD metadata. Fedora, Debian, Alpine,
Gentoo, and CRUX locks bind both their bounded packaging metadata and a source
manifest. Nix locks consume fixed-output exports, and Cargo locks bind the
complete registry closure. GitHub can host those exact inputs, but hosting is
transport and never package authority. Driver and firmware records remain
outside this service route and still require a matching signed Arach-HWD device
plan.

## Transaction recovery

Lifecycle operations take an exclusive lock. Install and update first solve the
complete bounded closure and prepare every selected payload without target
mutation. Existing packages are fixed; an update replaces only its requested
root and may add missing dependencies, so it never performs surprise
dependency upgrades. New dependencies are ordered before the root, and the
root is always the final graph entry.

Corinth then writes one synchronized graph journal before the first provenance
or target mutation. The service provenance receipts and binary ownership
receipts remain independent. On restart, a graph whose every ownership receipt
matches the new side rolls forward. A partial install, or a partial update whose
root still matches the old side, removes newly owned dependencies in reverse
order and restores the old receipt set. A partial update with a committed new
root, foreign ownership, or ownership that matches neither side fails closed
instead of guessing.

The solver admits at most 256 candidate records, 1,024 clauses, and 15 concrete
providers in any one dependency clause. Repository publication must split or
pre-resolve larger domains. Target-file conflicts, modified owned files, build
failures, download failures, cycles, and unsatisfied constraints leave the
previous installation intact.
