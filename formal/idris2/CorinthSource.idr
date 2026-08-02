module CorinthSource

%default total

public export
data Source = ArachNative | ArachHardware | CratesIo | Git | Local | Oci

public export
data Scope = BuildInput | User | System | Driver | Firmware

public export
data IngressState = MutableReference | ResolvedCandidate | AuthenticatedLock

public export
data Ingress : IngressState -> Type where
  Discovered : Source -> Ingress MutableReference
  Resolved : Source -> Ingress ResolvedCandidate
  SignedLock : Source -> Ingress AuthenticatedLock

public export
data Resolves : Ingress MutableReference -> Ingress ResolvedCandidate -> Type where
  ExactIdentity : Resolves (Discovered source) (Resolved source)

public export
data Translates : Ingress state -> Type where
  Canonicalize : Translates (SignedLock source)

public export
unsignedCannotTranslate : Translates (Discovered source) -> Void
unsignedCannotTranslate value impossible

public export
resolvedCannotTranslate : Translates (Resolved source) -> Void
resolvedCannotTranslate value impossible

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

public export
data Route = NativeRoute | SourceRoute

public export
data ProviderTrust = UnverifiedProvider | VerifiedProvider

public export
data Candidate : ProviderTrust -> Type where
  UnverifiedCandidate : Route -> Candidate UnverifiedProvider
  VerifiedCandidate : Route -> Candidate VerifiedProvider

public export
data Selectable : Candidate trust -> Type where
  SelectVerified : Selectable (VerifiedCandidate route)

public export
unverifiedCannotSelect : Selectable (UnverifiedCandidate route) -> Void
unverifiedCannotSelect value impossible

public export
data NativeAvailability = NativePresent | NativeAbsent

public export
data Resolution : NativeAvailability -> Route -> Type where
  PreferNative : Resolution NativePresent NativeRoute
  SourceFallback : Resolution NativeAbsent SourceRoute

public export
nativePresentCannotSelectSource : Resolution NativePresent SourceRoute -> Void
nativePresentCannotSelectSource value impossible

public export
data AtLeast : Nat -> Nat -> Type where
  SameSequence : AtLeast current current
  LaterSequence : AtLeast installed selected -> AtLeast installed (S selected)

public export
data UpdateSelection : Nat -> Nat -> Type where
  MonotonicUpdate : AtLeast installed selected -> UpdateSelection installed selected

public export
positiveAtLeastZeroImpossible : AtLeast (S installed) Z -> Void
positiveAtLeastZeroImpossible value impossible

public export
positiveSequenceCannotSelectZero : UpdateSelection (S installed) Z -> Void
positiveSequenceCannotSelectZero (MonotonicUpdate evidence) =
  positiveAtLeastZeroImpossible evidence

public export
data Ownership = NoOwner | OldOwner | NewOwner

public export
data Operation = Installing | Updating | Removing

public export
data Recovers : Operation -> Ownership -> Type where
  InstallAbsent : Recovers Installing NoOwner
  InstallCommitted : Recovers Installing NewOwner
  UpdateOld : Recovers Updating OldOwner
  UpdateNew : Recovers Updating NewOwner
  RemoveOld : Recovers Removing OldOwner
  RemoveCommitted : Recovers Removing NoOwner

public export
updateCannotRecoverAbsent : Recovers Updating NoOwner -> Void
updateCannotRecoverAbsent value impossible

public export
data GraphNode = DependencyNode | RootNode

public export
data Requires : GraphNode -> GraphNode -> Type where
  RootRequiresDependency : Requires RootNode DependencyNode

public export
data Precedes : GraphNode -> GraphNode -> Type where
  DependencyBeforeRoot : Precedes DependencyNode RootNode

public export
requiredDependencyPrecedesRoot :
  Requires RootNode DependencyNode -> Precedes DependencyNode RootNode
requiredDependencyPrecedesRoot RootRequiresDependency = DependencyBeforeRoot

public export
rootCannotPrecedeDependency : Precedes RootNode DependencyNode -> Void
rootCannotPrecedeDependency value impossible

public export
data GraphOperation = GraphInstall | GraphUpdate

public export
data GraphProgress = NoNewOwners | PartialNewOwners | AllNewOwners | ForeignOwners

public export
data RootOwnership = RootAbsent | RootStillOld | RootNowNew

public export
data GraphOutcome = RestoreOldGraph | CommitNewGraph

public export
data GraphRecovers : GraphOperation -> GraphProgress -> RootOwnership -> GraphOutcome -> Type where
  EmptyInstallRollsBack :
    GraphRecovers GraphInstall NoNewOwners RootAbsent RestoreOldGraph
  PartialInstallRollsBack :
    GraphRecovers GraphInstall PartialNewOwners RootAbsent RestoreOldGraph
  CompleteInstallRollsForward :
    GraphRecovers GraphInstall AllNewOwners RootNowNew CommitNewGraph
  PartialUpdateRollsBack :
    GraphRecovers GraphUpdate PartialNewOwners RootStillOld RestoreOldGraph
  CompleteUpdateRollsForward :
    GraphRecovers GraphUpdate AllNewOwners RootNowNew CommitNewGraph

public export
updateNewPartialCannotRecover :
  GraphRecovers GraphUpdate PartialNewOwners RootNowNew outcome -> Void
updateNewPartialCannotRecover value impossible

public export
foreignGraphCannotRecover :
  GraphRecovers operation ForeignOwners root outcome -> Void
foreignGraphCannotRecover value impossible

public export
completeGraphCannotRollBack :
  GraphRecovers operation AllNewOwners RootNowNew RestoreOldGraph -> Void
completeGraphCannotRollBack value impossible

public export
data BuildInputTrust = SignedNativeInput | SourceBuildInput

public export
data BuildPlane = BuildSandbox | TargetRoot

public export
data BuildVisible : BuildInputTrust -> BuildPlane -> Type where
  ReadOnlyNativeBuildMount : BuildVisible SignedNativeInput BuildSandbox

public export
sourceCannotEnterBuildClosure : BuildVisible SourceBuildInput plane -> Void
sourceCannotEnterBuildClosure value impossible

public export
buildDependencyCannotPublishToTarget :
  BuildVisible SignedNativeInput TargetRoot -> Void
buildDependencyCannotPublishToTarget value impossible
