# Universal provider discovery

Provider discovery is deliberately separated from recipe ingestion. A mutable
branch, tag, or provider `HEAD` can identify what is available, but it cannot
authorize a build or installation.

`corinth-discover` performs the availability phase:

1. derive or validate the provider repository;
2. resolve the requested reference to one full Git commit;
3. fetch that exact commit through the locked source cache;
4. reject submodules, symlinks, path traversal, and oversized metadata;
5. measure the package metadata and any separate source lock;
6. write a new unsigned universal ingress candidate without overwriting an
   existing path.

The candidate contains no mutable reference. It must be reviewed and signed by
a `package-index` authority before `corinth-ingest` can translate it. The
separately signed target policy still chooses commands, outputs, package scope,
and publication authority. Discovery therefore has no path to system, driver,
or firmware authority.

## Arch and AUR

Arch and AUR repository identities are derived from the package name, so a
caller cannot redirect a well-known provider name to a different server:

```text
corinth-discover \
  --ecosystem arch \
  --package linux \
  --reference HEAD \
  --work /var/cache/corinth/discovery \
  --output /var/lib/corinth/candidates/linux.toml \
  --allow-network

corinth-discover \
  --ecosystem aur \
  --package yay \
  --reference HEAD \
  --work /var/cache/corinth/discovery \
  --output /var/lib/corinth/candidates/yay.toml \
  --allow-network
```

`HEAD` is convenience input only. Each output records the commit returned by
the provider and the measured `PKGBUILD`, never `HEAD` itself.

## CRUX and Nix exports

CRUX and Nix support independently hosted HTTPS Git repositories. CRUX
requires both the `Pkgfile` and a static source-lock manifest. Nix requires a
fixed-output export manifest rather than evaluation of arbitrary Nix code.

```text
corinth-discover \
  --ecosystem crux \
  --package example \
  --repository https://github.com/example/ports.git \
  --reference refs/heads/main \
  --metadata-path example/Pkgfile \
  --source-lock-path example/sources.toml \
  --work /var/cache/corinth/discovery \
  --output /var/lib/corinth/candidates/example.toml \
  --allow-network

corinth-discover \
  --ecosystem nix \
  --package example \
  --repository https://github.com/example/package-exports.git \
  --reference refs/tags/v1.0.0 \
  --metadata-path example/fixed-output.toml \
  --work /var/cache/corinth/discovery \
  --output /var/lib/corinth/candidates/example.toml \
  --allow-network
```

GitHub is transport in both cases. The commit and file measurements become the
candidate identity; the hosting account does not gain Arach publication
authority.

## Cargo closures

Cargo discovery requires an exact version. Corinth resolves the published
crate in an isolated Cargo home, verifies the root `.crate` checksum, resolves
the crate's own lock graph, fetch-verifies the graph, and records the exact
checksum of every registry archive. It rejects Git, path, alternate-registry,
missing-checksum, and ambiguous dependencies.

```text
corinth-discover \
  --ecosystem cargo \
  --package sha2 \
  --version 0.10.9 \
  --architecture x86-64 \
  --work /var/cache/corinth/discovery \
  --output /var/lib/corinth/candidates/sha2.toml \
  --allow-network
```

After signature admission, the canonical recipe names the root crate and every
transitive crate as independent locked sources. Corinth materializes dependency
archives into a private directory source, writes file-level Cargo checksums,
installs the candidate's exact `Cargo.lock`, and supplies an offline Cargo
source replacement. Cargo target policy must disable build networking and every
build command must use `--locked`.
