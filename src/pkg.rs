use crate::alchemist::VariableRegistry;

pub const MAX_INSTALLED_PACKAGES: usize = 128;
const MAX_TRANSACTION_INTENTS: usize = MAX_INSTALLED_PACKAGES * 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageId<'a> {
    pub name: &'a str,
    pub version: &'a str,
}

/// The identity that crosses the resolver/installer boundary.
///
/// Entries are kept in ascending `name_hash` order. A ledger can contain at
/// most one version for a name, making its digest independent of resolver
/// insertion order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolvedPackage {
    pub name_hash: u64,
    pub version_idx: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionAuthority {
    generation: u64,
    state_digest: u64,
}

impl TransactionAuthority {
    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn state_digest(self) -> u64 {
        self.state_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionReceipt {
    pub previous: TransactionAuthority,
    pub current: TransactionAuthority,
    pub installed: u16,
    pub removed: u16,
    pub upgraded: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageError {
    StaleAuthority,
    GenerationExhausted,
    CapacityExhausted,
    PackageAlreadyInstalled,
    PackageNotInstalled,
    VersionPreconditionFailed,
    ContradictoryIntent,
    ContradictorySelection,
    InvalidResolverState,
    TransactionSealed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageLedger {
    packages: [ResolvedPackage; MAX_INSTALLED_PACKAGES],
    count: u16,
    generation: u64,
}

impl PackageLedger {
    pub const fn new() -> Self {
        Self {
            packages: [ResolvedPackage {
                name_hash: 0,
                version_idx: 0,
            }; MAX_INSTALLED_PACKAGES],
            count: 0,
            generation: 0,
        }
    }

    pub fn authority(&self) -> TransactionAuthority {
        TransactionAuthority {
            generation: self.generation,
            state_digest: state_digest(self.installed()),
        }
    }

    pub fn installed(&self) -> &[ResolvedPackage] {
        &self.packages[..usize::from(self.count)]
    }

    pub fn version_of(&self, name_hash: u64) -> Option<u16> {
        find_name(self.installed(), name_hash)
            .ok()
            .map(|index| self.packages[index].version_idx)
    }

    /// Opens an optimistic transaction only when both the monotonic generation
    /// and canonical state digest agree. A copied or corrupted authority cannot
    /// authorize a mutation of a different package state.
    pub fn begin(
        &self,
        authority: TransactionAuthority,
    ) -> Result<PackageTransaction, PackageError> {
        if authority != self.authority() {
            return Err(PackageError::StaleAuthority);
        }
        Ok(PackageTransaction {
            base: authority,
            packages: self.packages,
            count: self.count,
            touched_names: [0; MAX_TRANSACTION_INTENTS],
            touched_count: 0,
            sealed: false,
        })
    }

    /// Publishes the complete candidate image in one assignment. No package
    /// state is changed until authority and candidate invariants have passed.
    pub fn commit(
        &mut self,
        transaction: PackageTransaction,
    ) -> Result<TransactionReceipt, PackageError> {
        let previous = self.authority();
        if transaction.base != previous {
            return Err(PackageError::StaleAuthority);
        }
        if !canonical(transaction.installed()) {
            return Err(PackageError::ContradictorySelection);
        }

        let (installed, removed, upgraded) = delta(self.installed(), transaction.installed());
        if installed == 0 && removed == 0 && upgraded == 0 {
            return Ok(TransactionReceipt {
                previous,
                current: previous,
                installed: 0,
                removed: 0,
                upgraded: 0,
            });
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(PackageError::GenerationExhausted)?;

        self.packages = transaction.packages;
        self.count = transaction.count;
        self.generation = next_generation;
        Ok(TransactionReceipt {
            previous,
            current: self.authority(),
            installed,
            removed,
            upgraded,
        })
    }
}

impl Default for PackageLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageTransaction {
    base: TransactionAuthority,
    packages: [ResolvedPackage; MAX_INSTALLED_PACKAGES],
    count: u16,
    touched_names: [u64; MAX_TRANSACTION_INTENTS],
    touched_count: u16,
    sealed: bool,
}

impl PackageTransaction {
    pub fn installed(&self) -> &[ResolvedPackage] {
        &self.packages[..usize::from(self.count)]
    }

    pub fn install(&mut self, package: ResolvedPackage) -> Result<(), PackageError> {
        self.prepare_intent(package.name_hash)?;
        match find_name(self.installed(), package.name_hash) {
            Ok(_) => return Err(PackageError::PackageAlreadyInstalled),
            Err(index) => self.insert_at(index, package)?,
        }
        self.record_intent(package.name_hash);
        Ok(())
    }

    pub fn remove(&mut self, name_hash: u64, expected_version: u16) -> Result<(), PackageError> {
        self.prepare_intent(name_hash)?;
        let index = find_name(self.installed(), name_hash)
            .map_err(|_| PackageError::PackageNotInstalled)?;
        if self.packages[index].version_idx != expected_version {
            return Err(PackageError::VersionPreconditionFailed);
        }
        self.remove_at(index);
        self.record_intent(name_hash);
        Ok(())
    }

    pub fn upgrade(
        &mut self,
        name_hash: u64,
        expected_version: u16,
        replacement_version: u16,
    ) -> Result<(), PackageError> {
        self.prepare_intent(name_hash)?;
        let index = find_name(self.installed(), name_hash)
            .map_err(|_| PackageError::PackageNotInstalled)?;
        if self.packages[index].version_idx != expected_version {
            return Err(PackageError::VersionPreconditionFailed);
        }
        self.packages[index].version_idx = replacement_version;
        self.record_intent(name_hash);
        Ok(())
    }

    /// Reconciles the complete selected SAT model into a canonical candidate.
    /// Multiple selected versions for one package are rejected rather than
    /// silently allowing the registry's insertion order to choose a winner.
    pub fn reconcile_selection(&mut self, registry: &VariableRegistry) -> Result<(), PackageError> {
        if self.sealed {
            return Err(PackageError::TransactionSealed);
        }
        if self.touched_count != 0 {
            return Err(PackageError::ContradictoryIntent);
        }
        if usize::from(registry.count) > registry.vars.len() {
            return Err(PackageError::InvalidResolverState);
        }

        let checkpoint = *self;
        self.packages.fill(ResolvedPackage::default());
        self.count = 0;
        for selected in registry.vars[..usize::from(registry.count)]
            .iter()
            .filter(|package| package.selected)
        {
            let package = ResolvedPackage {
                name_hash: selected.name_hash,
                version_idx: selected.version_idx,
            };
            let index = match find_name(self.installed(), package.name_hash) {
                Ok(_) => {
                    *self = checkpoint;
                    return Err(PackageError::ContradictorySelection);
                }
                Err(index) => index,
            };
            if let Err(error) = self.insert_at(index, package) {
                *self = checkpoint;
                return Err(error);
            }
        }
        self.sealed = true;
        Ok(())
    }

    fn prepare_intent(&self, name_hash: u64) -> Result<(), PackageError> {
        if self.sealed {
            return Err(PackageError::TransactionSealed);
        }
        if self.touched_names[..usize::from(self.touched_count)].contains(&name_hash) {
            return Err(PackageError::ContradictoryIntent);
        }
        Ok(())
    }

    fn record_intent(&mut self, name_hash: u64) {
        self.touched_names[usize::from(self.touched_count)] = name_hash;
        self.touched_count += 1;
    }

    fn insert_at(&mut self, index: usize, package: ResolvedPackage) -> Result<(), PackageError> {
        let count = usize::from(self.count);
        if count == MAX_INSTALLED_PACKAGES {
            return Err(PackageError::CapacityExhausted);
        }
        self.packages.copy_within(index..count, index + 1);
        self.packages[index] = package;
        self.count += 1;
        Ok(())
    }

    fn remove_at(&mut self, index: usize) {
        let count = usize::from(self.count);
        self.packages.copy_within(index + 1..count, index);
        self.packages[count - 1] = ResolvedPackage::default();
        self.count -= 1;
    }
}

fn find_name(packages: &[ResolvedPackage], name_hash: u64) -> Result<usize, usize> {
    packages.binary_search_by_key(&name_hash, |package| package.name_hash)
}

fn canonical(packages: &[ResolvedPackage]) -> bool {
    packages
        .windows(2)
        .all(|pair| pair[0].name_hash < pair[1].name_hash)
}

fn state_digest(packages: &[ResolvedPackage]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64 ^ packages.len() as u64;
    for package in packages {
        digest ^= package.name_hash;
        digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
        digest ^= u64::from(package.version_idx);
        digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
    }
    digest
}

fn delta(before: &[ResolvedPackage], after: &[ResolvedPackage]) -> (u16, u16, u16) {
    let (mut left, mut right) = (0, 0);
    let (mut installed, mut removed, mut upgraded) = (0_u16, 0_u16, 0_u16);
    while left < before.len() || right < after.len() {
        if left == before.len() {
            installed += 1;
            right += 1;
        } else if right == after.len() || before[left].name_hash < after[right].name_hash {
            removed += 1;
            left += 1;
        } else if before[left].name_hash > after[right].name_hash {
            installed += 1;
            right += 1;
        } else {
            if before[left].version_idx != after[right].version_idx {
                upgraded += 1;
            }
            left += 1;
            right += 1;
        }
    }
    (installed, removed, upgraded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alchemist::{VariableRegistry, fnv1a};

    fn package(name: &str, version_idx: u16) -> ResolvedPackage {
        ResolvedPackage {
            name_hash: fnv1a(name),
            version_idx,
        }
    }

    fn commit_packages(ledger: &mut PackageLedger, packages: &[ResolvedPackage]) {
        let mut transaction = ledger.begin(ledger.authority()).unwrap();
        for package in packages {
            transaction.install(*package).unwrap();
        }
        ledger.commit(transaction).unwrap();
    }

    #[test]
    fn install_remove_and_upgrade_publish_one_generation() {
        let mut ledger = PackageLedger::new();
        commit_packages(&mut ledger, &[package("core", 1), package("shell", 3)]);
        let before = ledger.authority();
        let mut transaction = ledger.begin(before).unwrap();
        transaction.remove(fnv1a("shell"), 3).unwrap();
        transaction.upgrade(fnv1a("core"), 1, 2).unwrap();
        transaction.install(package("network", 4)).unwrap();

        let receipt = ledger.commit(transaction).unwrap();
        assert_eq!(receipt.previous, before);
        assert_eq!(receipt.current.generation, before.generation + 1);
        assert_eq!(
            (receipt.installed, receipt.removed, receipt.upgraded),
            (1, 1, 1)
        );
        assert_eq!(ledger.version_of(fnv1a("core")), Some(2));
        assert_eq!(ledger.version_of(fnv1a("network")), Some(4));
        assert_eq!(ledger.version_of(fnv1a("shell")), None);
    }

    #[test]
    fn stale_commit_cannot_overwrite_a_newer_exact_state() {
        let mut ledger = PackageLedger::new();
        let authority = ledger.authority();
        let mut first = ledger.begin(authority).unwrap();
        let mut stale = ledger.begin(authority).unwrap();
        first.install(package("core", 1)).unwrap();
        stale.install(package("intruder", 9)).unwrap();
        ledger.commit(first).unwrap();
        let exact_pre_failure = ledger;

        assert_eq!(ledger.commit(stale), Err(PackageError::StaleAuthority));
        assert_eq!(ledger, exact_pre_failure);
    }

    #[test]
    fn contradictory_authority_cannot_open_a_transaction() {
        let ledger = PackageLedger::new();
        let mut contradictory = ledger.authority();
        contradictory.state_digest ^= 1;

        assert_eq!(
            ledger.begin(contradictory),
            Err(PackageError::StaleAuthority),
        );
        assert_eq!(ledger, PackageLedger::new());
    }

    #[test]
    fn injected_generation_exhaustion_preserves_the_exact_ledger() {
        let mut ledger = PackageLedger::new();
        ledger.generation = u64::MAX;
        let mut transaction = ledger.begin(ledger.authority()).unwrap();
        transaction.install(package("core", 1)).unwrap();
        let exact_pre_failure = ledger;

        assert_eq!(
            ledger.commit(transaction),
            Err(PackageError::GenerationExhausted),
        );
        assert_eq!(ledger, exact_pre_failure);
    }

    #[test]
    fn contradictory_intent_failure_restores_the_exact_transaction_state() {
        let ledger = PackageLedger::new();
        let mut transaction = ledger.begin(ledger.authority()).unwrap();
        transaction.install(package("core", 1)).unwrap();
        let exact_pre_failure = transaction;

        assert_eq!(
            transaction.upgrade(fnv1a("core"), 1, 2),
            Err(PackageError::ContradictoryIntent),
        );
        assert_eq!(transaction, exact_pre_failure);
        assert_eq!(ledger, PackageLedger::new());
    }

    #[test]
    fn reconcile_capacity_failure_restores_every_candidate_byte() {
        let ledger = PackageLedger::new();
        let mut transaction = ledger.begin(ledger.authority()).unwrap();
        transaction.install(package("preserved", 7)).unwrap();
        let exact_pre_failure = transaction;
        let mut registry = VariableRegistry::new();
        for index in 0..=MAX_INSTALLED_PACKAGES {
            let variable = registry.intern(index as u64 + 1, index as u16).unwrap();
            registry.vars[usize::from(variable)].selected = true;
        }

        assert_eq!(
            transaction.reconcile_selection(&registry),
            Err(PackageError::ContradictoryIntent),
        );
        assert_eq!(transaction, exact_pre_failure);

        let mut fresh = ledger.begin(ledger.authority()).unwrap();
        let fresh_pre_failure = fresh;
        assert_eq!(
            fresh.reconcile_selection(&registry),
            Err(PackageError::CapacityExhausted),
        );
        assert_eq!(fresh, fresh_pre_failure);
        assert_eq!(ledger, PackageLedger::new());
    }

    #[test]
    fn direct_install_capacity_failure_preserves_the_exact_candidate() {
        let mut ledger = PackageLedger::new();
        let mut registry = VariableRegistry::new();
        for index in 0..MAX_INSTALLED_PACKAGES {
            let variable = registry.intern(index as u64 + 1, index as u16).unwrap();
            registry.vars[usize::from(variable)].selected = true;
        }
        let mut seed = ledger.begin(ledger.authority()).unwrap();
        seed.reconcile_selection(&registry).unwrap();
        ledger.commit(seed).unwrap();
        let exact_ledger = ledger;
        let mut transaction = ledger.begin(ledger.authority()).unwrap();
        let exact_candidate = transaction;

        assert_eq!(
            transaction.install(ResolvedPackage {
                name_hash: u64::MAX,
                version_idx: 9,
            }),
            Err(PackageError::CapacityExhausted),
        );
        assert_eq!(transaction, exact_candidate);
        assert_eq!(ledger, exact_ledger);
    }

    #[test]
    fn contradictory_solver_selection_is_rejected_without_partial_removal() {
        let mut ledger = PackageLedger::new();
        commit_packages(&mut ledger, &[package("preserved", 7)]);
        let exact_pre_failure = ledger;
        let mut registry = VariableRegistry::new();
        let first = registry.intern(fnv1a("core"), 1).unwrap();
        let second = registry.intern(fnv1a("core"), 2).unwrap();
        registry.vars[usize::from(first)].selected = true;
        registry.vars[usize::from(second)].selected = true;
        let mut transaction = ledger.begin(ledger.authority()).unwrap();
        let candidate_pre_failure = transaction;

        assert_eq!(
            transaction.reconcile_selection(&registry),
            Err(PackageError::ContradictorySelection),
        );
        assert_eq!(transaction, candidate_pre_failure);
        assert_eq!(ledger, exact_pre_failure);
    }

    #[test]
    fn malformed_resolver_bounds_are_failure_aware() {
        let ledger = PackageLedger::new();
        let mut registry = VariableRegistry::new();
        registry.count = u16::MAX;
        let mut transaction = ledger.begin(ledger.authority()).unwrap();
        let exact_pre_failure = transaction;

        assert_eq!(
            transaction.reconcile_selection(&registry),
            Err(PackageError::InvalidResolverState),
        );
        assert_eq!(transaction, exact_pre_failure);
        assert_eq!(ledger, PackageLedger::new());
    }

    #[test]
    fn solver_insertion_order_cannot_change_the_committed_image() {
        let mut forward = VariableRegistry::new();
        let mut reverse = VariableRegistry::new();
        for package in [package("a", 1), package("b", 2), package("c", 3)] {
            let id = forward
                .intern(package.name_hash, package.version_idx)
                .unwrap();
            forward.vars[usize::from(id)].selected = true;
        }
        for package in [package("c", 3), package("b", 2), package("a", 1)] {
            let id = reverse
                .intern(package.name_hash, package.version_idx)
                .unwrap();
            reverse.vars[usize::from(id)].selected = true;
        }
        let mut left = PackageLedger::new();
        let mut right = PackageLedger::new();
        let mut left_transaction = left.begin(left.authority()).unwrap();
        let mut right_transaction = right.begin(right.authority()).unwrap();
        left_transaction.reconcile_selection(&forward).unwrap();
        right_transaction.reconcile_selection(&reverse).unwrap();
        left.commit(left_transaction).unwrap();
        right.commit(right_transaction).unwrap();

        assert_eq!(left, right);
        assert_eq!(left.authority(), right.authority());
    }
}
