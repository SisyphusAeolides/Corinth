# Corinth binary repositories

Corinth accepts binary packages through a signed Arach repository index. The
index is TOML payload signed by an Arach-HWD key whose scope is exactly
`package-index`; a hardware-profile key cannot authorize a native package
index.

The index format is version `1`:

```toml
format = 1
repository = "arach-native"
key_id = "native-index-2026"

[[package]]
name = "cosmic-session"
version = "1.0.0"
release = 1
scope = "system"
repository = "arach-native"
metadata_sha256 = "<64 hex characters>"
artifact_sha256 = "<64 hex characters>"
source_lock_sha256 = "<64 hex characters>"
url = "https://packages.arach.example/stable/x86-64/cosmic-session.pkg"
size = 123456
```

Corinth validates the complete record before it downloads anything: package
identity, authority/scope, HTTPS-only transport, bounded size, and all three
digests. The detached signature must identify the same `key_id` in the index.
An index may contain one exact record per package name; version selection is
therefore deterministic.

## CLI

```sh
corinth install cosmic-session \
  --index stable.index.toml \
  --signature stable.index.sig \
  --keyring /etc/arach/hwd/keys.toml \
  --artifacts /var/lib/corinth/artifacts \
  --state /var/lib/corinth/state \
  --allow-network
```

`--allow-network` is required only when the exact artifact is not already in
the private artifact cache. A cached artifact is rechecked for both size and
SHA-256 and can be installed offline. Fetching is atomic; a failed or partial
download never becomes an installed receipt.

Native system packages use the `arach-native` authority. Driver and firmware
records use `arach-hardware` and are refused by the ordinary binary command
unless the caller supplies a matching, signed Arach-HWD provisioning plan.
The plan must agree on package identity, scope, repository, metadata digest,
source-lock digest, and artifact digest.

The host-store records verified artifacts and their receipts in a private,
rollback-aware staging area. Arach's generation publisher/installer is the
component that activates those staged files in a bootable system; Corinth does
not treat an opaque, unverified archive as a live-root mutation.
