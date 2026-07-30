module CorinthSource

%default total

public export
data Source = ArachNative | ArachHardware | CratesIo | Git | Local | Oci

public export
data Scope = BuildInput | User | System | Driver | Firmware

public export
record Authority where
  constructor MkAuthority
  source : Source
  locked : Bool
  metadataSigned : Bool
  artifactSigned : Bool

public export
data Admitted : Source -> Scope -> Type where
  CargoBuild : Admitted CratesIo BuildInput
  CargoUser : Admitted CratesIo User
  GitBuild : Admitted Git BuildInput
  LocalBuild : Admitted Local BuildInput
  NativeSystem : Admitted ArachNative System
  NativeUser : Admitted ArachNative User
  HardwareDriver : Admitted ArachHardware Driver
  HardwareFirmware : Admitted ArachHardware Firmware
  OciSystem : Admitted Oci System

public export
admit : (authority : Authority) -> (scope : Scope) ->
  Maybe (Admitted authority.source scope)
admit (MkAuthority source False metadata artifact) scope = Nothing
admit (MkAuthority CratesIo True metadata artifact) BuildInput = Just CargoBuild
admit (MkAuthority CratesIo True metadata artifact) User = Just CargoUser
admit (MkAuthority Git True metadata artifact) BuildInput = Just GitBuild
admit (MkAuthority Local True metadata artifact) BuildInput = Just LocalBuild
admit (MkAuthority ArachNative True True True) System = Just NativeSystem
admit (MkAuthority ArachNative True True True) User = Just NativeUser
admit (MkAuthority ArachHardware True True True) Driver = Just HardwareDriver
admit (MkAuthority ArachHardware True True True) Firmware = Just HardwareFirmware
admit (MkAuthority Oci True True True) System = Just OciSystem
admit authority scope = Nothing

public export
data Durability = Volatile | Synced

public export
data Generation : Durability -> Type where
  Staged : Generation Volatile
  Durable : Generation Synced

public export
data Active : Type where
  Published : Generation Synced -> Active

public export
publish : Generation Synced -> Active
publish generation = Published generation

public export
data Publishes : Generation durability -> Active -> Type where
  Commit : Publishes Durable (Published Durable)

public export
volatileCannotPublish : Publishes Staged active -> Void
volatileCannotPublish value impossible
