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
