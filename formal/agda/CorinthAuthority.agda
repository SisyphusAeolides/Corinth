{-# OPTIONS --safe --without-K #-}

module CorinthAuthority where

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
