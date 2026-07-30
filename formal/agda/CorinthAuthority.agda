{-# OPTIONS --safe --without-K #-}

module CorinthAuthority where

data Empty : Set where

Not : Set -> Set
Not proposition = proposition -> Empty

data Source : Set where
  arachNative arachHardware cratesIo git local oci : Source

data Scope : Set where
  buildInput user system driver firmware : Scope

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
