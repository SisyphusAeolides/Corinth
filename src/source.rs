//! Typed package-source authority for native, Cargo, Git, and offline inputs.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    ArachNative,
    ArachHardware,
    CratesIo,
    Git,
    Local,
    Oci,
}

impl SourceKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::ArachNative => "arach-native",
            Self::ArachHardware => "arach-hardware",
            Self::CratesIo => "crates.io",
            Self::Git => "git",
            Self::Local => "local",
            Self::Oci => "oci",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "arach-native" => Some(Self::ArachNative),
            "arach-hardware" => Some(Self::ArachHardware),
            "crates.io" => Some(Self::CratesIo),
            "git" => Some(Self::Git),
            "local" => Some(Self::Local),
            "oci" => Some(Self::Oci),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallScope {
    BuildInput,
    User,
    System,
    Driver,
    Firmware,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceAuthority {
    pub kind: SourceKind,
    pub resolution_locked: bool,
    pub metadata_signed: bool,
    pub artifact_signed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedSource {
    pub kind: SourceKind,
    pub scope: InstallScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceError {
    ResolutionUnlocked,
    SignatureRequired,
    ScopeForbidden,
}

/// Admits a source without confusing source availability with system trust.
///
/// crates.io and Git are build inputs. Only signed Arach repository metadata
/// can authorize a system or hardware transaction.
pub fn admit_source(
    authority: SourceAuthority,
    scope: InstallScope,
) -> Result<AdmittedSource, SourceError> {
    if !authority.resolution_locked {
        return Err(SourceError::ResolutionUnlocked);
    }
    let signed = authority.metadata_signed && authority.artifact_signed;
    let allowed = match (authority.kind, scope) {
        (SourceKind::CratesIo, InstallScope::BuildInput | InstallScope::User)
        | (SourceKind::Git, InstallScope::BuildInput)
        | (SourceKind::Local, InstallScope::BuildInput) => true,
        (SourceKind::ArachNative, InstallScope::System | InstallScope::User)
        | (SourceKind::ArachHardware, InstallScope::Driver | InstallScope::Firmware)
        | (SourceKind::Oci, InstallScope::System) => {
            if !signed {
                return Err(SourceError::SignatureRequired);
            }
            true
        }
        _ => false,
    };
    if !allowed {
        return Err(SourceError::ScopeForbidden);
    }
    Ok(AdmittedSource {
        kind: authority.kind,
        scope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(kind: SourceKind) -> SourceAuthority {
        SourceAuthority {
            kind,
            resolution_locked: true,
            metadata_signed: true,
            artifact_signed: true,
        }
    }

    #[test]
    fn crates_io_is_a_source_or_user_scope_not_driver_authority() {
        assert!(admit_source(authority(SourceKind::CratesIo), InstallScope::BuildInput).is_ok());
        assert!(admit_source(authority(SourceKind::CratesIo), InstallScope::User).is_ok());
        assert_eq!(
            admit_source(authority(SourceKind::CratesIo), InstallScope::Driver),
            Err(SourceError::ScopeForbidden)
        );
    }

    #[test]
    fn hardware_repository_requires_both_signatures() {
        let mut source = authority(SourceKind::ArachHardware);
        source.artifact_signed = false;
        assert_eq!(
            admit_source(source, InstallScope::Driver),
            Err(SourceError::SignatureRequired)
        );
        source.artifact_signed = true;
        assert!(admit_source(source, InstallScope::Firmware).is_ok());
    }

    #[test]
    fn every_source_requires_a_resolution_lock() {
        let mut source = authority(SourceKind::ArachNative);
        source.resolution_locked = false;
        assert_eq!(
            admit_source(source, InstallScope::System),
            Err(SourceError::ResolutionUnlocked)
        );
    }
}
