//! Canonical durable-generation format shared by native and installer stores.

use crate::pkg::{
    MAX_INSTALLED_PACKAGES, PackageError, PackageLedger, ResolvedPackage, installed_state_digest,
};

pub const GENERATION_FORMAT: u16 = 1;
pub const GENERATION_MAGIC: &[u8; 8] = b"ARACHGEN";
pub const GENERATION_HEADER_BYTES: usize = 68;
pub const GENERATION_RECORD_BYTES: usize = 12;
pub const MAX_GENERATION_BYTES: usize =
    GENERATION_HEADER_BYTES + MAX_INSTALLED_PACKAGES * GENERATION_RECORD_BYTES;

pub type GenerationDigest = [u8; 32];
pub const NO_GENERATION: GenerationDigest = [0; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationImage {
    generation: u64,
    state_digest: u64,
    parent: GenerationDigest,
    packages: [ResolvedPackage; MAX_INSTALLED_PACKAGES],
    count: u16,
}

impl GenerationImage {
    pub fn from_ledger(ledger: &PackageLedger, parent: GenerationDigest) -> Self {
        let mut packages = [ResolvedPackage::default(); MAX_INSTALLED_PACKAGES];
        packages[..ledger.installed().len()].copy_from_slice(ledger.installed());
        let authority = ledger.authority();
        Self {
            generation: authority.generation(),
            state_digest: authority.state_digest(),
            parent,
            packages,
            count: ledger.installed().len() as u16,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn state_digest(&self) -> u64 {
        self.state_digest
    }

    pub fn parent(&self) -> GenerationDigest {
        self.parent
    }

    pub fn packages(&self) -> &[ResolvedPackage] {
        &self.packages[..usize::from(self.count)]
    }

    pub fn restore_ledger(&self) -> Result<PackageLedger, PackageError> {
        PackageLedger::restore(self.generation, self.packages())
    }

    pub fn encoded_len(&self) -> usize {
        GENERATION_HEADER_BYTES + self.packages().len() * GENERATION_RECORD_BYTES
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, GenerationError> {
        validate_packages(self.packages())?;
        let length = self.encoded_len();
        if output.len() < length {
            return Err(GenerationError::BufferTooSmall);
        }
        output[..length].fill(0);
        output[..8].copy_from_slice(GENERATION_MAGIC);
        output[8..10].copy_from_slice(&GENERATION_FORMAT.to_le_bytes());
        output[10..12].copy_from_slice(&(GENERATION_HEADER_BYTES as u16).to_le_bytes());
        output[12..20].copy_from_slice(&self.generation.to_le_bytes());
        output[20..28].copy_from_slice(&self.state_digest.to_le_bytes());
        output[28..60].copy_from_slice(&self.parent);
        output[60..62].copy_from_slice(&self.count.to_le_bytes());
        output[62..64].copy_from_slice(&(GENERATION_RECORD_BYTES as u16).to_le_bytes());
        output[64..68].copy_from_slice(&(length as u32).to_le_bytes());
        for (index, package) in self.packages().iter().enumerate() {
            let offset = GENERATION_HEADER_BYTES + index * GENERATION_RECORD_BYTES;
            output[offset..offset + 8].copy_from_slice(&package.name_hash.to_le_bytes());
            output[offset + 8..offset + 10].copy_from_slice(&package.version_idx.to_le_bytes());
        }
        Ok(length)
    }

    pub fn decode(input: &[u8]) -> Result<Self, GenerationError> {
        if input.len() < GENERATION_HEADER_BYTES || &input[..8] != GENERATION_MAGIC {
            return Err(GenerationError::InvalidHeader);
        }
        let format = read_u16(input, 8)?;
        let header = read_u16(input, 10)? as usize;
        let count = read_u16(input, 60)? as usize;
        let record = read_u16(input, 62)? as usize;
        let declared = read_u32(input, 64)? as usize;
        let expected = GENERATION_HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(GENERATION_RECORD_BYTES)
                    .ok_or(GenerationError::InvalidLength)?,
            )
            .ok_or(GenerationError::InvalidLength)?;
        if format != GENERATION_FORMAT
            || header != GENERATION_HEADER_BYTES
            || record != GENERATION_RECORD_BYTES
            || count > MAX_INSTALLED_PACKAGES
            || declared != expected
            || input.len() != expected
        {
            return Err(GenerationError::InvalidLength);
        }
        let mut packages = [ResolvedPackage::default(); MAX_INSTALLED_PACKAGES];
        for (index, package) in packages[..count].iter_mut().enumerate() {
            let offset = GENERATION_HEADER_BYTES + index * GENERATION_RECORD_BYTES;
            *package = ResolvedPackage {
                name_hash: read_u64(input, offset)?,
                version_idx: read_u16(input, offset + 8)?,
            };
            if input[offset + 10..offset + 12]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(GenerationError::NonCanonical);
            }
        }
        validate_packages(&packages[..count])?;
        let state_digest = read_u64(input, 20)?;
        if state_digest != installed_state_digest(&packages[..count]) {
            return Err(GenerationError::StateDigestMismatch);
        }
        Ok(Self {
            generation: read_u64(input, 12)?,
            state_digest,
            parent: input[28..60]
                .try_into()
                .map_err(|_| GenerationError::InvalidLength)?,
            packages,
            count: count as u16,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationError {
    BufferTooSmall,
    InvalidHeader,
    InvalidLength,
    InvalidPackage,
    StateDigestMismatch,
    NonCanonical,
}

fn validate_packages(packages: &[ResolvedPackage]) -> Result<(), GenerationError> {
    let mut previous = None;
    for package in packages {
        if package.name_hash == 0
            || package.version_idx == 0
            || previous.is_some_and(|value| value >= package.name_hash)
        {
            return Err(GenerationError::InvalidPackage);
        }
        previous = Some(package.name_hash);
    }
    Ok(())
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, GenerationError> {
    input
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(GenerationError::InvalidLength)
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, GenerationError> {
    input
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(GenerationError::InvalidLength)
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, GenerationError> {
    input
        .get(offset..offset + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(GenerationError::InvalidLength)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkg::PackageError;

    fn ledger() -> PackageLedger {
        let mut ledger = PackageLedger::new();
        let authority = ledger.authority();
        let mut transaction = ledger.begin(authority).unwrap();
        transaction
            .install(ResolvedPackage {
                name_hash: 10,
                version_idx: 1,
            })
            .unwrap();
        transaction
            .install(ResolvedPackage {
                name_hash: 20,
                version_idx: 2,
            })
            .unwrap();
        ledger.commit(transaction).unwrap();
        ledger
    }

    #[test]
    fn generation_round_trip_is_canonical() {
        let image = GenerationImage::from_ledger(&ledger(), [7; 32]);
        let mut bytes = [0; MAX_GENERATION_BYTES];
        let length = image.encode(&mut bytes).unwrap();
        let decoded = GenerationImage::decode(&bytes[..length]).unwrap();
        assert_eq!(decoded, image);
        let restored = decoded.restore_ledger().unwrap();
        assert_eq!(restored.authority().generation(), image.generation());
        assert_eq!(restored.installed(), image.packages());
        assert_eq!(
            length,
            GENERATION_HEADER_BYTES + 2 * GENERATION_RECORD_BYTES
        );
    }

    #[test]
    fn trailing_and_reserved_bytes_are_rejected() {
        let image = GenerationImage::from_ledger(&ledger(), NO_GENERATION);
        let mut bytes = [0; MAX_GENERATION_BYTES + 1];
        let length = image.encode(&mut bytes).unwrap();
        assert_eq!(
            GenerationImage::decode(&bytes[..length + 1]),
            Err(GenerationError::InvalidLength)
        );
        bytes[GENERATION_HEADER_BYTES + 10] = 1;
        assert_eq!(
            GenerationImage::decode(&bytes[..length]),
            Err(GenerationError::NonCanonical)
        );
    }

    #[test]
    fn forged_state_digest_is_rejected() {
        let image = GenerationImage::from_ledger(&ledger(), NO_GENERATION);
        let mut bytes = [0; MAX_GENERATION_BYTES];
        let length = image.encode(&mut bytes).unwrap();
        bytes[20] ^= 1;
        assert_eq!(
            GenerationImage::decode(&bytes[..length]),
            Err(GenerationError::StateDigestMismatch)
        );
    }

    #[test]
    fn ledger_rejects_duplicate_setup_used_by_generation() {
        let ledger = ledger();
        let mut transaction = ledger.begin(ledger.authority()).unwrap();
        assert_eq!(
            transaction.install(ResolvedPackage {
                name_hash: 10,
                version_idx: 1
            }),
            Err(PackageError::PackageAlreadyInstalled)
        );
    }
}
