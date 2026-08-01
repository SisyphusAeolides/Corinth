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
