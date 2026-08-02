# Corinth binary repositories

Corinth accepts binary packages through a signed Arach repository index. The
index is TOML payload signed by an Arach-HWD key whose scope is exactly
`package-index`; a hardware-profile key cannot authorize a native package
index.

The current index format is version `3`:

```toml
format = 3
repository = "arach-native"
key_id = "native-index-2026"

[[package]]
name = "cosmic-session"
version = "1.0.0"
release = 1
sequence = 184
scope = "system"
repository = "arach-native"
metadata_sha256 = "<64 hex characters>"
artifact_sha256 = "<64 hex characters>"
source_lock_sha256 = "<64 hex characters>"
url = "https://packages.arach.example/stable/x86-64/cosmic-session.pkg"
size = 123456

[[package.requirements]]

[[package.requirements.alternatives]]
name = "wayland-api"
versions = ["1"]

[[package.provides]]
name = "desktop-session"
version = "1"

[[package.conflicts]]
name = "cosmic-session-legacy"
versions = []
```

Corinth validates the complete record before it downloads anything: package
identity, authority/scope, HTTPS-only transport, bounded size, and all three
digests. The detached signature must identify the same `key_id` in the index.
Version `3` may retain several exact versions of one package. Every record has
a nonzero publisher-assigned `sequence`; both `(name, version)` and
`(name, sequence)` must be unique. With no version selector Corinth chooses
the record with the greatest sequence. `PACKAGE@VERSION` pins one exact
version, independent of record order. Corinth does not infer precedence from
ecosystem-specific version strings, and an update cannot move below the
installed package sequence. Requirements are clauses of concrete-package or
virtual-capability alternatives. Version sets contain exact versions admitted
by the signed snapshot; an empty set accepts any retained version. Provides and
conflicts use the same bounded exact-constraint vocabulary.

Version `2` indexes remain readable as multi-version indexes but cannot carry
dependency metadata. Version `1` indexes also remain readable; their package
records omit `sequence`, which defaults to zero, and retain the original
one-record-per-name rule. New repository publications should use version `3`.
One release is currently admitted for each `(name, version)` identity; a
repository publishes a changed release by advancing both its package sequence
and provider generation, while retaining both releases requires distinct
version labels.

## CLI

Production deployments list native indexes in signed Corinth service metadata,
so the ordinary command is simply `corinth install cosmic-session`. The
service resolver authenticates all configured repositories, prefers native
records, pins updates to the installed provider/channel, and records a durable
provenance receipt. See [`PACKAGE_SERVICE.md`](PACKAGE_SERVICE.md).

The explicit index form remains available to image builders and diagnostics:

```sh
corinth install cosmic-session \
  --index stable.index.toml \
  --signature stable.index.sig \
  --keyring /etc/arach/hwd/keys.toml \
  --artifacts /var/lib/corinth/artifacts \
  --state /var/lib/corinth/state \
  --root / \
  --allow-network
```

The explicit index form is intentionally one-record-only. It rejects a
format-3 record carrying requirements, provides, or conflicts because it has no
signed service graph. Dependency-bearing system records must enter through the
ordinary service command; dependency-bearing driver or firmware records remain
unsupported until the HWD plan format carries an equivalent complete graph.

`--allow-network` is required only when the exact artifact is not already in
the private artifact cache. A cached artifact is rechecked for both size and
SHA-256 and can be installed offline. Fetching is atomic; a failed or partial
download never becomes an installed receipt. `--root` is explicit: without it,
Corinth only stages a verified artifact and receipt for an image builder. With
it, the payload is decoded and installed into that target root.

## Native payload format

The `artifact_sha256` bytes are a deterministic `ARCPKG01` container. The
little-endian header contains:

1. the eight-byte magic `ARCPKG01` and format `1`;
2. package-name and version lengths, release, and file count;
3. the 32-byte metadata and source-lock digests;
4. UTF-8 package name and version;
5. one record per regular file: path length, Unix mode, byte length, SHA-256,
   path bytes, and file bytes.

Paths are relative and cannot contain `..`, `.` components, backslashes, or
absolute prefixes. Symlinks, device nodes, hard links, and post-install
scripts have no representation. The complete payload is bounded, every file
hash is checked before mutation, and the target root refuses symlink parents.
The per-package receipt records owned paths and hashes. `update` can replace
only files still owned and unmodified by that package; `remove` refuses to
delete a modified file.

Native system packages use the `arach-native` authority. Driver and firmware
records use `arach-hardware` and are refused by the ordinary binary command
unless the caller supplies a matching, signed Arach-HWD provisioning plan.
The plan must agree on package identity, scope, repository, metadata digest,
source-lock digest, and artifact digest.

The host-store records verified artifacts and their receipts in a private,
rollback-aware staging area. This is the mode used by image composition. The
explicit `--root` mode is the live-root binary installer; it still does not
replace Arach's generation publisher or measured-boot activation, and it is
intentionally separate from driver/firmware authorization. Those records must
be installed through a matching, signed Arach-HWD plan.
