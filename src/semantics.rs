//! Typed package semantics beyond dependency selection.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use core::fmt;

pub const PACKAGE_SEMANTICS_FORMAT: u32 = 1;
pub const MAX_REPLACEMENTS: usize = 64;
pub const MAX_FEATURES: usize = 64;
pub const MAX_OUTPUTS: usize = 64;
pub const MAX_FILES: usize = 4096;
pub const MAX_USERS: usize = 64;
pub const MAX_GROUPS: usize = 64;
pub const MAX_SERVICES: usize = 64;
pub const MAX_DESKTOP_REGISTRATIONS: usize = 64;
pub const MAX_TRIGGERS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(rename_all = "kebab-case"))]
pub enum OutputKind {
    Runtime,
    Development,
    Debug,
    Multilib,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct OptionalFeature {
    pub name: String,
    pub default_enabled: bool,
    pub dependencies: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct SplitOutput {
    pub name: String,
    pub kind: OutputKind,
    pub files: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(rename_all = "kebab-case"))]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    Hardlink,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(rename_all = "kebab-case"))]
pub enum ConfigMerge {
    PreserveLocal,
    ReplaceIfUnmodified,
    ThreeWayFailOnConflict,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(rename_all = "SCREAMING_SNAKE_CASE"))]
pub enum FileCapability {
    Chown,
    DacOverride,
    Fowner,
    Kill,
    Setgid,
    Setuid,
    NetBindService,
    NetAdmin,
    SysAdmin,
    SysBoot,
    SysChroot,
    SysTime,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct XattrDeclaration {
    pub name: String,
    pub value_sha256: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct AclDeclaration {
    pub principal: String,
    pub permissions: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct FileDeclaration {
    pub path: String,
    pub kind: FileKind,
    pub mode: u32,
    pub owner: String,
    pub group: String,
    pub target: Option<String>,
    pub config_merge: Option<ConfigMerge>,
    pub xattrs: Vec<XattrDeclaration>,
    pub acl: Vec<AclDeclaration>,
    pub capabilities: Vec<FileCapability>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct GroupDeclaration {
    pub name: String,
    pub system: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct UserDeclaration {
    pub name: String,
    pub primary_group: String,
    pub supplementary_groups: Vec<String>,
    pub home: String,
    pub shell: String,
    pub system: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(rename_all = "kebab-case"))]
pub enum RestartPolicy {
    Never,
    OnFailure,
    Always,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct ServiceDeclaration {
    pub name: String,
    pub executable: String,
    pub after: Vec<String>,
    pub restart: RestartPolicy,
    pub maximum_restarts: u8,
    pub backoff_ticks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct DesktopRegistration {
    pub desktop_file: String,
    pub executable: String,
    pub categories: Vec<String>,
    pub mime_types: Vec<String>,
    pub dbus_activatable: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(rename_all = "kebab-case"))]
pub enum TriggerKind {
    DesktopDatabase,
    FontCache,
    IconCache,
    MimeDatabase,
    SchemaCache,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct TriggerDeclaration {
    pub kind: TriggerKind,
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct PackageSemantics {
    pub format: u32,
    pub package: String,
    pub architecture: String,
    pub replacements: Vec<String>,
    pub optional_features: Vec<OptionalFeature>,
    pub outputs: Vec<SplitOutput>,
    pub files: Vec<FileDeclaration>,
    pub groups: Vec<GroupDeclaration>,
    pub users: Vec<UserDeclaration>,
    pub services: Vec<ServiceDeclaration>,
    pub desktop_registrations: Vec<DesktopRegistration>,
    pub triggers: Vec<TriggerDeclaration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticsError {
    InvalidHeader,
    Capacity,
    Duplicate,
    InvalidReplacement,
    InvalidFeature,
    InvalidOutput,
    InvalidFile,
    UnsafeLink,
    InvalidMetadata,
    InvalidAccount,
    InvalidService,
    InvalidDesktopRegistration,
    InvalidTrigger,
}

impl fmt::Display for SemanticsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidHeader => "invalid package semantics header",
            Self::Capacity => "package semantics exceed bounded capacity",
            Self::Duplicate => "package semantics contain a duplicate declaration",
            Self::InvalidReplacement => "invalid replacement declaration",
            Self::InvalidFeature => "invalid optional feature declaration",
            Self::InvalidOutput => "invalid split output declaration",
            Self::InvalidFile => "invalid packaged file declaration",
            Self::UnsafeLink => "unsafe packaged link declaration",
            Self::InvalidMetadata => "invalid ownership, xattr, ACL, or capability declaration",
            Self::InvalidAccount => "invalid package user or group declaration",
            Self::InvalidService => "invalid Push service declaration",
            Self::InvalidDesktopRegistration => "invalid desktop registration",
            Self::InvalidTrigger => "invalid controlled trigger declaration",
        };
        formatter.write_str(message)
    }
}

impl PackageSemantics {
    pub fn validate(&self) -> Result<(), SemanticsError> {
        if self.format != PACKAGE_SEMANTICS_FORMAT
            || !valid_name(&self.package)
            || !matches!(self.architecture.as_str(), "x86-64" | "aarch64" | "riscv64")
        {
            return Err(SemanticsError::InvalidHeader);
        }
        if self.replacements.len() > MAX_REPLACEMENTS
            || self.optional_features.len() > MAX_FEATURES
            || self.outputs.is_empty()
            || self.outputs.len() > MAX_OUTPUTS
            || self.files.is_empty()
            || self.files.len() > MAX_FILES
            || self.users.len() > MAX_USERS
            || self.groups.len() > MAX_GROUPS
            || self.services.len() > MAX_SERVICES
            || self.desktop_registrations.len() > MAX_DESKTOP_REGISTRATIONS
            || self.triggers.len() > MAX_TRIGGERS
        {
            return Err(SemanticsError::Capacity);
        }
        self.validate_replacements()?;
        self.validate_features()?;
        let files = self.validate_files()?;
        self.validate_outputs(&files)?;
        let groups = self.validate_accounts()?;
        self.validate_services(&files)?;
        self.validate_desktop_registrations(&files)?;
        self.validate_triggers()?;
        for file in self.files.iter().filter(|file| file.owner != "root") {
            if !self.users.iter().any(|user| user.name == file.owner) {
                return Err(SemanticsError::InvalidAccount);
            }
        }
        for file in &self.files {
            if file.group != "root" && !groups.contains(file.group.as_str()) {
                return Err(SemanticsError::InvalidAccount);
            }
        }
        Ok(())
    }

    fn validate_replacements(&self) -> Result<(), SemanticsError> {
        let mut replacements = BTreeSet::new();
        for replacement in &self.replacements {
            if replacement == &self.package
                || !valid_name(replacement)
                || !replacements.insert(replacement.as_str())
            {
                return Err(SemanticsError::InvalidReplacement);
            }
        }
        Ok(())
    }

    fn validate_features(&self) -> Result<(), SemanticsError> {
        let mut names = BTreeSet::new();
        for feature in &self.optional_features {
            if !valid_name(&feature.name)
                || !names.insert(feature.name.as_str())
                || feature.dependencies.len() > MAX_FEATURES
            {
                return Err(SemanticsError::InvalidFeature);
            }
            let mut dependencies = BTreeSet::new();
            for dependency in &feature.dependencies {
                if !valid_name(dependency) || !dependencies.insert(dependency.as_str()) {
                    return Err(SemanticsError::InvalidFeature);
                }
            }
        }
        Ok(())
    }

    fn validate_files(&self) -> Result<BTreeMap<&str, &FileDeclaration>, SemanticsError> {
        let mut files = BTreeMap::new();
        for file in &self.files {
            if !safe_relative(&file.path)
                || files.insert(file.path.as_str(), file).is_some()
                || file.mode & !0o7777 != 0
                || file.mode & 0o6000 != 0
                || !valid_account(&file.owner)
                || !valid_account(&file.group)
            {
                return Err(SemanticsError::InvalidFile);
            }
            match file.kind {
                FileKind::Regular | FileKind::Directory => {
                    if file.target.is_some() {
                        return Err(SemanticsError::InvalidFile);
                    }
                }
                FileKind::Symlink | FileKind::Hardlink => {
                    let Some(target) = file.target.as_deref() else {
                        return Err(SemanticsError::UnsafeLink);
                    };
                    if !safe_relative(target) || target == file.path {
                        return Err(SemanticsError::UnsafeLink);
                    }
                }
            }
            if file.config_merge.is_some() && file.kind != FileKind::Regular {
                return Err(SemanticsError::InvalidMetadata);
            }
            if !file.capabilities.is_empty()
                && (file.kind != FileKind::Regular || file.mode & 0o111 == 0)
            {
                return Err(SemanticsError::InvalidMetadata);
            }
            let mut capabilities = BTreeSet::new();
            if file
                .capabilities
                .iter()
                .any(|capability| !capabilities.insert(*capability))
            {
                return Err(SemanticsError::Duplicate);
            }
            let mut xattrs = BTreeSet::new();
            for xattr in &file.xattrs {
                if !valid_xattr(&xattr.name)
                    || xattr.name == "security.capability"
                    || !valid_digest(&xattr.value_sha256)
                    || !xattrs.insert(xattr.name.as_str())
                {
                    return Err(SemanticsError::InvalidMetadata);
                }
            }
            let mut acl = BTreeSet::new();
            for entry in &file.acl {
                if !valid_acl_principal(&entry.principal)
                    || !valid_acl_permissions(&entry.permissions)
                    || !acl.insert(entry.principal.as_str())
                {
                    return Err(SemanticsError::InvalidMetadata);
                }
            }
        }
        for file in &self.files {
            if file.kind == FileKind::Hardlink {
                let Some(target) = file.target.as_deref().and_then(|target| files.get(target)) else {
                    return Err(SemanticsError::UnsafeLink);
                };
                if target.kind != FileKind::Regular {
                    return Err(SemanticsError::UnsafeLink);
                }
            }
        }
        Ok(files)
    }

    fn validate_outputs(
        &self,
        files: &BTreeMap<&str, &FileDeclaration>,
    ) -> Result<(), SemanticsError> {
        let mut names = BTreeSet::new();
        let mut assigned = BTreeSet::new();
        for output in &self.outputs {
            if !valid_name(&output.name)
                || !names.insert(output.name.as_str())
                || output.files.is_empty()
                || output.files.len() > MAX_FILES
                || output.kind == OutputKind::Multilib && self.architecture != "x86-64"
            {
                return Err(SemanticsError::InvalidOutput);
            }
            for path in &output.files {
                if !files.contains_key(path.as_str()) || !assigned.insert(path.as_str()) {
                    return Err(SemanticsError::InvalidOutput);
                }
            }
        }
        if assigned.len() != files.len() {
            return Err(SemanticsError::InvalidOutput);
        }
        Ok(())
    }

    fn validate_accounts(&self) -> Result<BTreeSet<&str>, SemanticsError> {
        let mut groups = BTreeSet::new();
        for group in &self.groups {
            if !valid_account(&group.name) || !groups.insert(group.name.as_str()) {
                return Err(SemanticsError::InvalidAccount);
            }
        }
        let mut users = BTreeSet::new();
        for user in &self.users {
            if !valid_account(&user.name)
                || !users.insert(user.name.as_str())
                || !groups.contains(user.primary_group.as_str())
                || !safe_absolute(&user.home)
                || !safe_absolute(&user.shell)
            {
                return Err(SemanticsError::InvalidAccount);
            }
            let mut supplementary = BTreeSet::new();
            for group in &user.supplementary_groups {
                if !groups.contains(group.as_str()) || !supplementary.insert(group.as_str()) {
                    return Err(SemanticsError::InvalidAccount);
                }
            }
        }
        Ok(groups)
    }

    fn validate_services(
        &self,
        files: &BTreeMap<&str, &FileDeclaration>,
    ) -> Result<(), SemanticsError> {
        let mut names = BTreeSet::new();
        for service in &self.services {
            let executable = service.executable.strip_prefix('/').unwrap_or("");
            let Some(file) = files.get(executable) else {
                return Err(SemanticsError::InvalidService);
            };
            if !valid_name(&service.name)
                || !names.insert(service.name.as_str())
                || !safe_absolute(&service.executable)
                || file.kind != FileKind::Regular
                || file.mode & 0o111 == 0
                || service.after.len() > MAX_SERVICES
                || service.maximum_restarts > 32
                || service.backoff_ticks > 1_000_000
                || service.restart == RestartPolicy::Never
                    && (service.maximum_restarts != 0 || service.backoff_ticks != 0)
            {
                return Err(SemanticsError::InvalidService);
            }
            let mut after = BTreeSet::new();
            for dependency in &service.after {
                if dependency == &service.name
                    || !valid_name(dependency)
                    || !after.insert(dependency.as_str())
                {
                    return Err(SemanticsError::InvalidService);
                }
            }
        }
        Ok(())
    }

    fn validate_desktop_registrations(
        &self,
        files: &BTreeMap<&str, &FileDeclaration>,
    ) -> Result<(), SemanticsError> {
        let mut desktop_files = BTreeSet::new();
        for registration in &self.desktop_registrations {
            let desktop = registration.desktop_file.strip_prefix('/').unwrap_or("");
            let executable = registration.executable.strip_prefix('/').unwrap_or("");
            if !safe_absolute(&registration.desktop_file)
                || !registration.desktop_file.ends_with(".desktop")
                || !desktop_files.insert(registration.desktop_file.as_str())
                || files
                    .get(desktop)
                    .is_none_or(|file| file.kind != FileKind::Regular)
                || files.get(executable).is_none_or(|file| {
                    file.kind != FileKind::Regular || file.mode & 0o111 == 0
                })
            {
                return Err(SemanticsError::InvalidDesktopRegistration);
            }
            if !unique_nonempty(&registration.categories)
                || !unique_nonempty(&registration.mime_types)
            {
                return Err(SemanticsError::InvalidDesktopRegistration);
            }
        }
        Ok(())
    }

    fn validate_triggers(&self) -> Result<(), SemanticsError> {
        let mut kinds = BTreeSet::new();
        for trigger in &self.triggers {
            if !kinds.insert(trigger.kind)
                || trigger.paths.is_empty()
                || trigger.paths.len() > MAX_FILES
            {
                return Err(SemanticsError::InvalidTrigger);
            }
            let mut paths = BTreeSet::new();
            for path in &trigger.paths {
                if !safe_absolute(path) || !paths.insert(path.as_str()) {
                    return Err(SemanticsError::InvalidTrigger);
                }
            }
        }
        Ok(())
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'_' | b'.')
        })
}

fn valid_account(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn safe_absolute(value: &str) -> bool {
    value.starts_with('/') && safe_relative(value.trim_start_matches('/'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_xattr(value: &str) -> bool {
    value.len() <= 255
        && matches!(
            value.split_once('.'),
            Some(("user" | "trusted" | "security", suffix)) if !suffix.is_empty()
        )
}

fn valid_acl_principal(value: &str) -> bool {
    matches!(value, "user" | "group" | "mask" | "other")
        || value
            .strip_prefix("user:")
            .is_some_and(valid_account)
        || value
            .strip_prefix("group:")
            .is_some_and(valid_account)
}

fn valid_acl_permissions(value: &str) -> bool {
    value.len() == 3
        && value
            .bytes()
            .zip([b'r', b'w', b'x'])
            .all(|(actual, expected)| actual == expected || actual == b'-')
}

fn unique_nonempty(values: &[String]) -> bool {
    !values.is_empty()
        && values.iter().all(|value| !value.trim().is_empty())
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};

    fn regular(path: &str, mode: u32) -> FileDeclaration {
        FileDeclaration {
            path: path.to_string(),
            kind: FileKind::Regular,
            mode,
            owner: "root".to_string(),
            group: "root".to_string(),
            target: None,
            config_merge: None,
            xattrs: Vec::new(),
            acl: Vec::new(),
            capabilities: Vec::new(),
        }
    }

    fn manifest() -> PackageSemantics {
        let files = vec![
            regular("system/example", 0o755),
            regular("share/applications/example.desktop", 0o644),
            regular("etc/example.conf", 0o644),
        ];
        PackageSemantics {
            format: PACKAGE_SEMANTICS_FORMAT,
            package: "example".to_string(),
            architecture: "x86-64".to_string(),
            replacements: vec!["example-old".to_string()],
            optional_features: vec![OptionalFeature {
                name: "tls".to_string(),
                default_enabled: true,
                dependencies: vec!["openssl".to_string()],
            }],
            outputs: vec![SplitOutput {
                name: "example".to_string(),
                kind: OutputKind::Runtime,
                files: files.iter().map(|file| file.path.clone()).collect(),
            }],
            files,
            groups: Vec::new(),
            users: Vec::new(),
            services: vec![ServiceDeclaration {
                name: "example".to_string(),
                executable: "/system/example".to_string(),
                after: vec!["dbus-broker".to_string()],
                restart: RestartPolicy::OnFailure,
                maximum_restarts: 3,
                backoff_ticks: 8,
            }],
            desktop_registrations: vec![DesktopRegistration {
                desktop_file: "/share/applications/example.desktop".to_string(),
                executable: "/system/example".to_string(),
                categories: vec!["Utility".to_string()],
                mime_types: vec!["text/plain".to_string()],
                dbus_activatable: false,
            }],
            triggers: vec![TriggerDeclaration {
                kind: TriggerKind::DesktopDatabase,
                paths: vec!["/share/applications".to_string()],
            }],
        }
    }

    #[test]
    fn accepts_complete_typed_semantics() {
        let mut value = manifest();
        value.files[2].config_merge = Some(ConfigMerge::ThreeWayFailOnConflict);
        assert_eq!(value.validate(), Ok(()));
    }

    #[test]
    fn split_outputs_must_cover_each_file_once() {
        let mut value = manifest();
        value.outputs[0].files.pop();
        assert_eq!(value.validate(), Err(SemanticsError::InvalidOutput));
    }

    #[test]
    fn hardlinks_must_target_a_declared_regular_file() {
        let mut value = manifest();
        let mut link = regular("system/example-link", 0o755);
        link.kind = FileKind::Hardlink;
        link.target = Some("system/missing".to_string());
        value.outputs[0].files.push(link.path.clone());
        value.files.push(link);
        assert_eq!(value.validate(), Err(SemanticsError::UnsafeLink));
    }

    #[test]
    fn capabilities_require_an_executable_regular_file() {
        let mut value = manifest();
        value.files[2]
            .capabilities
            .push(FileCapability::NetBindService);
        assert_eq!(value.validate(), Err(SemanticsError::InvalidMetadata));
    }

    #[test]
    fn services_must_reference_packaged_executables() {
        let mut value = manifest();
        value.services[0].executable = "/system/missing".to_string();
        assert_eq!(value.validate(), Err(SemanticsError::InvalidService));
    }

    #[test]
    fn multilib_output_is_x86_64_only() {
        let mut value = manifest();
        value.architecture = "aarch64".to_string();
        value.outputs[0].kind = OutputKind::Multilib;
        assert_eq!(value.validate(), Err(SemanticsError::InvalidOutput));
    }
}
