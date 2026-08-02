{-# OPTIONS --safe --without-K #-}

module CorinthAuthority where

open import Agda.Builtin.Nat using (Nat; zero; suc)

data Empty : Set where

Not : Set -> Set
Not proposition = proposition -> Empty

data Source : Set where
  arachNative arachHardware cratesIo git local oci : Source

data Scope : Set where
  buildInput user system driver firmware : Scope

data IngressState : Set where
  mutableReference resolvedCandidate authenticatedLock : IngressState

data Ingress : IngressState → Set where
  discovered : Source → Ingress mutableReference
  resolved : Source → Ingress resolvedCandidate
  signedLock : Source → Ingress authenticatedLock

data Resolves : Ingress mutableReference → Ingress resolvedCandidate → Set where
  exactIdentity : ∀ {source} → Resolves (discovered source) (resolved source)

data Translates : ∀ {state} → Ingress state → Set where
  canonicalize : ∀ {source} → Translates (signedLock source)

unsigned-cannot-translate : ∀ {source} → Translates (discovered source) → Empty
unsigned-cannot-translate ()

resolved-cannot-translate : ∀ {source} → Translates (resolved source) → Empty
resolved-cannot-translate ()

data Admitted : Source -> Scope -> Set where
  cargoBuild : Admitted cratesIo buildInput
  cargoUser : Admitted cratesIo user
  gitBuild : Admitted git buildInput
  localBuild : Admitted local buildInput
  nativeSystem : Admitted arachNative system
  nativeUser : Admitted arachNative user
  hardwareDriver : Admitted arachHardware driver
  hardwareFirmware : Admitted arachHardware firmware
  ociSystem : Admitted oci system

cratesCannotAuthorizeDriver : Not (Admitted cratesIo driver)
cratesCannotAuthorizeDriver ()

gitCannotAuthorizeSystem : Not (Admitted git system)
gitCannotAuthorizeSystem ()

nativeRepositoryCannotImpersonateHardwareIndex : Not (Admitted arachNative driver)
nativeRepositoryCannotImpersonateHardwareIndex ()

data Durability : Set where
  volatile synced : Durability

data Generation : Durability → Set where
  staged : Generation volatile
  durable : Generation synced

data Active : Set where
  published : Generation synced → Active

publish : Generation synced → Active
publish generation = published generation

data Publishes : Generation volatile → Active → Set where

volatile-cannot-publish : ∀ {generation active} → Publishes generation active → Empty
volatile-cannot-publish ()

data Route : Set where
  nativeRoute sourceRoute : Route

data ProviderTrust : Set where
  unverifiedProvider verifiedProvider : ProviderTrust

data Candidate : ProviderTrust → Set where
  unverifiedCandidate : Route → Candidate unverifiedProvider
  verifiedCandidate : Route → Candidate verifiedProvider

data Selectable : ∀ {trust} → Candidate trust → Set where
  selectVerified : ∀ {route} → Selectable (verifiedCandidate route)

unverified-cannot-select : ∀ {route} → Selectable (unverifiedCandidate route) → Empty
unverified-cannot-select ()

data NativeAvailability : Set where
  nativePresent nativeAbsent : NativeAvailability

data Resolution : NativeAvailability → Route → Set where
  preferNative : Resolution nativePresent nativeRoute
  sourceFallback : Resolution nativeAbsent sourceRoute

native-present-cannot-select-source : Resolution nativePresent sourceRoute → Empty
native-present-cannot-select-source ()

data AtLeast (installed : Nat) : Nat → Set where
  sameSequence : AtLeast installed installed
  laterSequence : ∀ {selected} → AtLeast installed selected → AtLeast installed (suc selected)

data UpdateSelection : Nat → Nat → Set where
  monotonicUpdate : ∀ {installed selected} → AtLeast installed selected → UpdateSelection installed selected

positive-at-least-zero-impossible : ∀ {installed} → AtLeast (suc installed) zero → Empty
positive-at-least-zero-impossible ()

positive-sequence-cannot-select-zero : ∀ {installed} → UpdateSelection (suc installed) zero → Empty
positive-sequence-cannot-select-zero (monotonicUpdate evidence) = positive-at-least-zero-impossible evidence

data Ownership : Set where
  noOwner oldOwner newOwner : Ownership

data Operation : Set where
  installing updating removing : Operation

data Recovers : Operation → Ownership → Set where
  installAbsent : Recovers installing noOwner
  installCommitted : Recovers installing newOwner
  updateOld : Recovers updating oldOwner
  updateNew : Recovers updating newOwner
  removeOld : Recovers removing oldOwner
  removeCommitted : Recovers removing noOwner

update-cannot-recover-absent : Recovers updating noOwner → Empty
update-cannot-recover-absent ()

data GraphNode : Set where
  dependencyNode rootNode : GraphNode

data Requires : GraphNode → GraphNode → Set where
  rootRequiresDependency : Requires rootNode dependencyNode

data Precedes : GraphNode → GraphNode → Set where
  dependencyBeforeRoot : Precedes dependencyNode rootNode

required-dependency-precedes-root :
  Requires rootNode dependencyNode → Precedes dependencyNode rootNode
required-dependency-precedes-root rootRequiresDependency = dependencyBeforeRoot

root-cannot-precede-dependency : Precedes rootNode dependencyNode → Empty
root-cannot-precede-dependency ()

data GraphOperation : Set where
  graphInstall graphUpdate : GraphOperation

data GraphProgress : Set where
  noNewOwners partialNewOwners allNewOwners foreignOwners : GraphProgress

data RootOwnership : Set where
  rootAbsent rootStillOld rootNowNew : RootOwnership

data GraphOutcome : Set where
  restoreOldGraph commitNewGraph : GraphOutcome

data GraphRecovers : GraphOperation → GraphProgress → RootOwnership → GraphOutcome → Set where
  emptyInstallRollsBack :
    GraphRecovers graphInstall noNewOwners rootAbsent restoreOldGraph
  partialInstallRollsBack :
    GraphRecovers graphInstall partialNewOwners rootAbsent restoreOldGraph
  completeInstallRollsForward :
    GraphRecovers graphInstall allNewOwners rootNowNew commitNewGraph
  partialUpdateRollsBack :
    GraphRecovers graphUpdate partialNewOwners rootStillOld restoreOldGraph
  completeUpdateRollsForward :
    GraphRecovers graphUpdate allNewOwners rootNowNew commitNewGraph

update-new-partial-cannot-recover :
  ∀ {outcome} → GraphRecovers graphUpdate partialNewOwners rootNowNew outcome → Empty
update-new-partial-cannot-recover ()

foreign-graph-cannot-recover :
  ∀ {operation root outcome} → GraphRecovers operation foreignOwners root outcome → Empty
foreign-graph-cannot-recover ()

complete-graph-cannot-roll-back :
  ∀ {operation} → GraphRecovers operation allNewOwners rootNowNew restoreOldGraph → Empty
complete-graph-cannot-roll-back ()
