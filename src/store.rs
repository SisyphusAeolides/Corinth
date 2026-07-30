//! Crash-safe filesystem publication for canonical Corinth generations.

use crate::generation::{GenerationDigest, GenerationError, GenerationImage, NO_GENERATION};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{format, string::String, string::ToString, vec::Vec};

static TEMPORARY_SERIAL: AtomicU64 = AtomicU64::new(1);

pub struct FilesystemGenerationStore {
    root: PathBuf,
    generations: PathBuf,
}

impl FilesystemGenerationStore {
    pub fn open(root: &Path) -> Result<Self, StoreError> {
        if !root.is_absolute() || root == Path::new("/") {
            return Err(StoreError::UnsafeRoot);
        }
        if root.exists() {
            validate_private_directory(root)?;
        } else {
            let parent = root.parent().ok_or(StoreError::UnsafeRoot)?;
            let parent_metadata = fs::symlink_metadata(parent).map_err(StoreError::io)?;
            if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
                return Err(StoreError::UnsafeRoot);
            }
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).create(root).map_err(StoreError::io)?;
        }
        let generations = root.join("generations");
        if generations.exists() {
            validate_private_directory(&generations)?;
        } else {
            let mut builder = fs::DirBuilder::new();
            builder
                .mode(0o700)
                .create(&generations)
                .map_err(StoreError::io)?;
        }
        Ok(Self {
            root: root.to_path_buf(),
            generations,
        })
    }

    /// Read the active authority without creating or modifying store state.
    pub fn inspect_active(root: &Path) -> Result<Option<GenerationDigest>, StoreError> {
        match fs::symlink_metadata(root) {
            Ok(_) => validate_private_directory(root)?,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(StoreError::io(error)),
        }
        read_active_pointer(root)
    }

    pub fn active(&self) -> Result<Option<GenerationDigest>, StoreError> {
        read_active_pointer(&self.root)
    }

    pub fn publish(&self, image_bytes: &[u8]) -> Result<GenerationDigest, StoreError> {
        let _lock = StoreLock::acquire(&self.root.join("lock"))?;
        let image = GenerationImage::decode(image_bytes).map_err(StoreError::Generation)?;
        let active = self.active()?;
        let expected_parent = active.unwrap_or(NO_GENERATION);
        if image.parent() != expected_parent {
            return Err(StoreError::ParentMismatch);
        }
        if let Some(parent) = active {
            let parent_image = self.load_generation(parent)?;
            if parent_image.generation() >= image.generation() {
                return Err(StoreError::GenerationNotMonotonic);
            }
        } else if image.generation() == 0 {
            return Err(StoreError::GenerationNotMonotonic);
        }

        let digest: GenerationDigest = Sha256::digest(image_bytes).into();
        let generation_path = self.generations.join(format!("{}.gen", encode(digest)));
        if generation_path.exists() {
            if read_bounded_regular(
                &generation_path,
                crate::generation::MAX_GENERATION_BYTES as u64,
            )? != image_bytes
            {
                return Err(StoreError::DigestCollision);
            }
        } else {
            publish_immutable(&generation_path, image_bytes)?;
            sync_directory(&self.generations)?;
        }
        replace_pointer(&self.root, Some(digest))?;
        Ok(digest)
    }

    pub fn rollback(
        &self,
        expected: GenerationDigest,
    ) -> Result<Option<GenerationDigest>, StoreError> {
        let _lock = StoreLock::acquire(&self.root.join("lock"))?;
        if self.active()? != Some(expected) {
            return Err(StoreError::ActiveMismatch);
        }
        let image = self.load_generation(expected)?;
        let parent = image.parent();
        if parent == NO_GENERATION {
            replace_pointer(&self.root, None)?;
            Ok(None)
        } else {
            self.load_generation(parent)
                .map_err(|_| StoreError::ParentMissing)?;
            replace_pointer(&self.root, Some(parent))?;
            Ok(Some(parent))
        }
    }

    fn load_generation(&self, digest: GenerationDigest) -> Result<GenerationImage, StoreError> {
        let bytes = read_bounded_regular(
            &self.generations.join(format!("{}.gen", encode(digest))),
            crate::generation::MAX_GENERATION_BYTES as u64,
        )?;
        if GenerationDigest::from(Sha256::digest(&bytes)) != digest {
            return Err(StoreError::GenerationDigestMismatch);
        }
        GenerationImage::decode(&bytes).map_err(StoreError::Generation)
    }
}

struct StoreLock {
    file: File,
}

impl StoreLock {
    fn acquire(path: &Path) -> Result<Self, StoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(path)
            .map_err(StoreError::io)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(StoreError::io)?;
        // SAFETY: `file` owns a valid descriptor for the duration of this guard.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if result != 0 {
            return Err(StoreError::io(std::io::Error::last_os_error()));
        }
        Ok(Self { file })
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        // SAFETY: `self.file` remains open until after `drop` returns.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[derive(Debug)]
pub enum StoreError {
    UnsafeRoot,
    InsecurePermissions,
    Io(String),
    Generation(GenerationError),
    InvalidPointer,
    ParentMismatch,
    ParentMissing,
    ActiveMismatch,
    GenerationNotMonotonic,
    GenerationDigestMismatch,
    DigestCollision,
}

impl StoreError {
    fn io(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for StoreError {}

fn read_bounded_regular(path: &Path, limit: u64) -> Result<Vec<u8>, StoreError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(StoreError::io)?;
    let metadata = file.metadata().map_err(StoreError::io)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(StoreError::Io(
            "document is not a bounded regular file".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).map_err(StoreError::io)?;
    Ok(bytes)
}

fn validate_private_directory(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path).map_err(StoreError::io)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(StoreError::UnsafeRoot);
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StoreError::InsecurePermissions);
    }
    Ok(())
}

fn read_active_pointer(root: &Path) -> Result<Option<GenerationDigest>, StoreError> {
    let path = root.join("active");
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(StoreError::io(error)),
    }
    let bytes = read_bounded_regular(&path, 65)?;
    decode_pointer(&bytes).map(Some)
}

fn replace_pointer(root: &Path, digest: Option<GenerationDigest>) -> Result<(), StoreError> {
    let active = root.join("active");
    if let Some(digest) = digest {
        let mut bytes = encode(digest).into_bytes();
        bytes.push(b'\n');
        atomic_replace(&active, &bytes)?;
    } else if active.exists() {
        let retired = temporary(root, "retired");
        fs::rename(&active, &retired).map_err(StoreError::io)?;
        sync_directory(root)?;
        fs::remove_file(retired).map_err(StoreError::io)?;
        sync_directory(root)?;
    }
    Ok(())
}

fn atomic_create(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(StoreError::io)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(StoreError::io)
}

fn publish_immutable(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let parent = path.parent().ok_or(StoreError::UnsafeRoot)?;
    let temporary = temporary(parent, "generation");
    atomic_create(&temporary, bytes)?;
    if let Err(error) = fs::hard_link(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(StoreError::io(error));
    }
    fs::remove_file(&temporary).map_err(StoreError::io)?;
    sync_directory(parent)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let parent = path.parent().ok_or(StoreError::UnsafeRoot)?;
    let temporary = temporary(parent, "active");
    atomic_create(&temporary, bytes)?;
    fs::rename(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        StoreError::io(error)
    })?;
    sync_directory(parent)
}

fn temporary(parent: &Path, role: &str) -> PathBuf {
    let serial = TEMPORARY_SERIAL.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        ".corinth-{role}-{}-{serial}.tmp",
        std::process::id()
    ))
}

fn sync_directory(path: &Path) -> Result<(), StoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(StoreError::io)
}

fn decode_pointer(bytes: &[u8]) -> Result<GenerationDigest, StoreError> {
    if bytes.len() != 65 || bytes[64] != b'\n' {
        return Err(StoreError::InvalidPointer);
    }
    let mut digest = [0; 32];
    for (index, pair) in bytes[..64].chunks_exact(2).enumerate() {
        digest[index] = (hex(pair[0])? << 4) | hex(pair[1])?;
    }
    if digest == NO_GENERATION {
        return Err(StoreError::InvalidPointer);
    }
    Ok(digest)
}

fn hex(value: u8) -> Result<u8, StoreError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(StoreError::InvalidPointer),
    }
}

fn encode(digest: GenerationDigest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkg::{PackageLedger, ResolvedPackage};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SERIAL: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "corinth-store-test-{}-{}",
                std::process::id(),
                TEST_SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn next_image(parent: GenerationDigest, names: &[u64]) -> Vec<u8> {
        let mut ledger = PackageLedger::new();
        for name_hash in names {
            let mut transaction = ledger.begin(ledger.authority()).unwrap();
            transaction
                .install(ResolvedPackage {
                    name_hash: *name_hash,
                    version_idx: 1,
                })
                .unwrap();
            ledger.commit(transaction).unwrap();
        }
        let image = GenerationImage::from_ledger(&ledger, parent);
        let mut bytes = [0; crate::generation::MAX_GENERATION_BYTES];
        let length = image.encode(&mut bytes).unwrap();
        bytes[..length].to_vec()
    }

    #[test]
    fn publish_is_durable_and_rollback_restores_parent() {
        let root = TestRoot::new();
        let store = FilesystemGenerationStore::open(&root.0).unwrap();
        let first = store.publish(&next_image(NO_GENERATION, &[10])).unwrap();
        assert_eq!(store.active().unwrap(), Some(first));

        let store = FilesystemGenerationStore::open(&root.0).unwrap();

        let second = store.publish(&next_image(first, &[10, 20])).unwrap();
        assert_eq!(store.active().unwrap(), Some(second));
        assert_eq!(store.rollback(second).unwrap(), Some(first));
        assert_eq!(store.active().unwrap(), Some(first));
        assert_eq!(store.rollback(first).unwrap(), None);
        assert_eq!(store.active().unwrap(), None);
    }

    #[test]
    fn stale_parent_and_wrong_rollback_authority_fail() {
        let root = TestRoot::new();
        let store = FilesystemGenerationStore::open(&root.0).unwrap();
        let first = store.publish(&next_image(NO_GENERATION, &[10])).unwrap();
        assert!(matches!(
            store.publish(&next_image(NO_GENERATION, &[20])),
            Err(StoreError::ParentMismatch)
        ));
        assert!(matches!(
            store.rollback([9; 32]),
            Err(StoreError::ActiveMismatch)
        ));
        assert_eq!(store.active().unwrap(), Some(first));
    }

    #[test]
    fn parent_file_is_remeasured_before_publication() {
        let root = TestRoot::new();
        let store = FilesystemGenerationStore::open(&root.0).unwrap();
        let first = store.publish(&next_image(NO_GENERATION, &[10])).unwrap();
        let path = root
            .0
            .join("generations")
            .join(format!("{}.gen", encode(first)));
        let mut bytes = fs::read(&path).unwrap();
        bytes[20] ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(matches!(
            store.publish(&next_image(first, &[10, 20])),
            Err(StoreError::GenerationDigestMismatch)
        ));
        assert_eq!(store.active().unwrap(), Some(first));
    }

    #[test]
    fn store_rejects_root_and_symlink_roots() {
        assert!(matches!(
            FilesystemGenerationStore::open(Path::new("/")),
            Err(StoreError::UnsafeRoot)
        ));
        let root = TestRoot::new();
        let link = root.0.join("link");
        std::os::unix::fs::symlink(&root.0, &link).unwrap();
        assert!(matches!(
            FilesystemGenerationStore::open(&link),
            Err(StoreError::UnsafeRoot)
        ));
    }

    #[test]
    fn broken_active_symlink_is_not_treated_as_an_empty_store() {
        let root = TestRoot::new();
        let store = FilesystemGenerationStore::open(&root.0).unwrap();
        std::os::unix::fs::symlink(root.0.join("missing"), root.0.join("active")).unwrap();
        assert!(matches!(store.active(), Err(StoreError::Io(_))));
    }

    #[test]
    fn read_only_inspection_does_not_create_a_store() {
        let root = TestRoot::new();
        let absent = root.0.join("absent");
        assert_eq!(
            FilesystemGenerationStore::inspect_active(&absent).unwrap(),
            None
        );
        assert!(!absent.exists());

        let store = FilesystemGenerationStore::open(&absent).unwrap();
        let first = store.publish(&next_image(NO_GENERATION, &[10])).unwrap();
        assert_eq!(
            FilesystemGenerationStore::inspect_active(&absent).unwrap(),
            Some(first)
        );
    }

    #[test]
    fn insecure_existing_store_is_rejected_without_permission_mutation() {
        let root = TestRoot::new();
        let store_root = root.0.join("insecure");
        fs::create_dir(&store_root).unwrap();
        fs::set_permissions(&store_root, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(matches!(
            FilesystemGenerationStore::inspect_active(&store_root),
            Err(StoreError::InsecurePermissions)
        ));
        assert!(matches!(
            FilesystemGenerationStore::open(&store_root),
            Err(StoreError::InsecurePermissions)
        ));
        assert_eq!(
            fs::symlink_metadata(&store_root)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }
}
