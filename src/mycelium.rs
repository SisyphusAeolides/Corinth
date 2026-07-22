use crate::dna::{GeneError, GeneSequence, OptimizationFocus, ValidatedGeneSequence};

pub const MAXIMUM_PEERS: usize = 128;
pub const FRAGMENT_BYTES: usize = 4096;
pub const MAXIMUM_FRAGMENTS: usize = 256;
pub const MAXIMUM_PROOF_DEPTH: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MyceliumNode {
    pub ipv6_address: u128,
    pub node_id: [u8; 32],
    pub trust_score: i32,
    pub latency_milliseconds: u16,
    pub active: bool,
}

impl MyceliumNode {
    const EMPTY: Self = Self {
        ipv6_address: 0,
        node_id: [0; 32],
        trust_score: 0,
        latency_milliseconds: 0,
        active: false,
    };
}

#[derive(Clone, Copy)]
pub struct MerkleProof {
    pub depth: u8,
    pub sibling_on_left: u32,
    pub siblings: [[u8; 32]; MAXIMUM_PROOF_DEPTH],
}

impl MerkleProof {
    pub const EMPTY: Self = Self {
        depth: 0,
        sibling_on_left: 0,
        siblings: [[0; 32]; MAXIMUM_PROOF_DEPTH],
    };
}

#[derive(Clone, Copy)]
pub struct DnaFragment {
    pub index: u32,
    pub payload_length: u16,
    pub payload: [u8; FRAGMENT_BYTES],
    pub proof: MerkleProof,
}

impl DnaFragment {
    pub const EMPTY: Self = Self {
        index: 0,
        payload_length: 0,
        payload: [0; FRAGMENT_BYTES],
        proof: MerkleProof::EMPTY,
    };
}

pub trait PeerAuthenticator {
    fn authenticate(&self, node: &MyceliumNode) -> bool;
}

pub trait FragmentTransport {
    fn fetch(
        &mut self,
        peer: MyceliumNode,
        root: [u8; 32],
        index: u32,
        destination: &mut DnaFragment,
    ) -> Result<(), MyceliumError>;
}

/// Cryptographic implementation supplied by the measured userland runtime.
pub trait FragmentVerifier {
    fn verify(&self, root: [u8; 32], fragment: &DnaFragment) -> bool;
}

pub struct Assimilation {
    root: [u8; 32],
    expected_fragments: u16,
    final_fragment_bytes: u16,
    received: [u64; MAXIMUM_FRAGMENTS / 64],
    received_count: u16,
}

impl Assimilation {
    pub fn new(
        root: [u8; 32],
        expected_fragments: u16,
        final_fragment_bytes: u16,
    ) -> Result<Self, MyceliumError> {
        if root == [0; 32]
            || expected_fragments == 0
            || usize::from(expected_fragments) > MAXIMUM_FRAGMENTS
            || final_fragment_bytes == 0
            || usize::from(final_fragment_bytes) > FRAGMENT_BYTES
        {
            return Err(MyceliumError::InvalidAssimilation);
        }
        Ok(Self {
            root,
            expected_fragments,
            final_fragment_bytes,
            received: [0; MAXIMUM_FRAGMENTS / 64],
            received_count: 0,
        })
    }

    pub const fn assembled_bytes(&self) -> usize {
        (self.expected_fragments as usize - 1) * FRAGMENT_BYTES + self.final_fragment_bytes as usize
    }

    pub const fn is_complete(&self) -> bool {
        self.received_count == self.expected_fragments
    }

    fn first_missing(&self) -> Option<u32> {
        (0..u32::from(self.expected_fragments)).find(|index| !self.contains(*index))
    }

    fn contains(&self, index: u32) -> bool {
        let index = index as usize;
        self.received[index / 64] & (1_u64 << (index % 64)) != 0
    }

    fn insert(&mut self, index: u32) {
        let index = index as usize;
        self.received[index / 64] |= 1_u64 << (index % 64);
        self.received_count += 1;
    }
}

pub struct MyceliumSwarm {
    peers: [MyceliumNode; MAXIMUM_PEERS],
    peer_count: usize,
}

impl MyceliumSwarm {
    pub const fn new() -> Self {
        Self {
            peers: [MyceliumNode::EMPTY; MAXIMUM_PEERS],
            peer_count: 0,
        }
    }

    pub fn admit_peer<A: PeerAuthenticator>(
        &mut self,
        mut node: MyceliumNode,
        authenticator: &A,
    ) -> Result<(), MyceliumError> {
        if node.ipv6_address == 0
            || node.node_id == [0; 32]
            || self.peers[..self.peer_count]
                .iter()
                .any(|peer| peer.ipv6_address == node.ipv6_address || peer.node_id == node.node_id)
        {
            return Err(MyceliumError::InvalidPeer);
        }
        if !authenticator.authenticate(&node) {
            return Err(MyceliumError::UnauthenticatedPeer);
        }
        let slot = self
            .peers
            .get_mut(self.peer_count)
            .ok_or(MyceliumError::PeerCapacityExceeded)?;
        node.active = true;
        *slot = node;
        self.peer_count += 1;
        Ok(())
    }

    /// Fetches and verifies at most one missing fragment.
    pub fn poll<T: FragmentTransport, V: FragmentVerifier>(
        &mut self,
        assimilation: &mut Assimilation,
        output: &mut [u8],
        transport: &mut T,
        verifier: &V,
    ) -> Result<AssimilationProgress, MyceliumError> {
        if output.len() < assimilation.assembled_bytes() {
            return Err(MyceliumError::OutputTooSmall);
        }
        if assimilation.is_complete() {
            return Ok(AssimilationProgress::Complete);
        }
        let index = assimilation
            .first_missing()
            .ok_or(MyceliumError::InvalidAssimilation)?;
        let peer_index = self.select_apex_peer().ok_or(MyceliumError::NoActivePeer)?;
        let peer = self.peers[peer_index];
        let mut fragment = DnaFragment::EMPTY;
        transport.fetch(peer, assimilation.root, index, &mut fragment)?;
        let expected_length = if index + 1 == u32::from(assimilation.expected_fragments) {
            usize::from(assimilation.final_fragment_bytes)
        } else {
            FRAGMENT_BYTES
        };
        if fragment.index != index
            || usize::from(fragment.payload_length) != expected_length
            || usize::from(fragment.proof.depth) > MAXIMUM_PROOF_DEPTH
            || !verifier.verify(assimilation.root, &fragment)
        {
            self.peers[peer_index].active = false;
            self.peers[peer_index].trust_score = i32::MIN;
            return Err(MyceliumError::ByzantineFragment);
        }
        let offset = index as usize * FRAGMENT_BYTES;
        output[offset..offset + expected_length]
            .copy_from_slice(&fragment.payload[..expected_length]);
        assimilation.insert(index);
        self.peers[peer_index].trust_score = self.peers[peer_index].trust_score.saturating_add(1);
        if assimilation.is_complete() {
            Ok(AssimilationProgress::Complete)
        } else {
            Ok(AssimilationProgress::FragmentAccepted { index })
        }
    }

    pub fn finish<'artifact>(
        &self,
        assimilation: &Assimilation,
        package_name: &'artifact str,
        output: &'artifact [u8],
        causal_dependencies: &'artifact [&'artifact str],
        allowed_mutations: &'artifact [OptimizationFocus],
    ) -> Result<ValidatedGeneSequence<'artifact>, MyceliumError> {
        if !assimilation.is_complete() || output.len() < assimilation.assembled_bytes() {
            return Err(MyceliumError::Incomplete);
        }
        let version_hash = u64::from_be_bytes(
            assimilation.root[..8]
                .try_into()
                .expect("Merkle root prefix is eight bytes"),
        );
        GeneSequence {
            package_name,
            version_hash,
            ir_payload: &output[..assimilation.assembled_bytes()],
            causal_dependencies,
            allowed_mutations,
        }
        .validate()
        .map_err(MyceliumError::Gene)
    }

    fn select_apex_peer(&self) -> Option<usize> {
        let mut selected = None;
        let mut best_score = i64::MIN;
        for (index, peer) in self.peers[..self.peer_count].iter().enumerate() {
            if !peer.active {
                continue;
            }
            let score = i64::from(peer.trust_score) - i64::from(peer.latency_milliseconds);
            if selected.is_none() || score > best_score {
                selected = Some(index);
                best_score = score;
            }
        }
        selected
    }
}

impl Default for MyceliumSwarm {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssimilationProgress {
    FragmentAccepted { index: u32 },
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MyceliumError {
    InvalidPeer,
    UnauthenticatedPeer,
    PeerCapacityExceeded,
    InvalidAssimilation,
    NoActivePeer,
    OutputTooSmall,
    TransportUnavailable,
    ByzantineFragment,
    Incomplete,
    Gene(GeneError),
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Auth;
    impl PeerAuthenticator for Auth {
        fn authenticate(&self, _: &MyceliumNode) -> bool {
            true
        }
    }

    struct Transport;
    impl FragmentTransport for Transport {
        fn fetch(
            &mut self,
            _peer: MyceliumNode,
            _root: [u8; 32],
            index: u32,
            destination: &mut DnaFragment,
        ) -> Result<(), MyceliumError> {
            destination.index = index;
            destination.payload_length = 4;
            destination.payload[..4].copy_from_slice(b"DNA!");
            Ok(())
        }
    }

    struct Verify;
    impl FragmentVerifier for Verify {
        fn verify(&self, _: [u8; 32], fragment: &DnaFragment) -> bool {
            fragment.payload[..4] == *b"DNA!"
        }
    }

    #[test]
    fn assimilates_one_verified_fragment_without_allocation() {
        let mut swarm = MyceliumSwarm::new();
        swarm
            .admit_peer(
                MyceliumNode {
                    ipv6_address: 1,
                    node_id: [7; 32],
                    trust_score: 10,
                    latency_milliseconds: 2,
                    active: false,
                },
                &Auth,
            )
            .unwrap();
        let mut assimilation = Assimilation::new([9; 32], 1, 4).unwrap();
        let mut output = [0_u8; 4];
        assert_eq!(
            swarm
                .poll(&mut assimilation, &mut output, &mut Transport, &Verify)
                .unwrap(),
            AssimilationProgress::Complete
        );
        let mutations = [OptimizationFocus::MaximumThroughput];
        let gene = swarm
            .finish(&assimilation, "package", &output, &[], &mutations)
            .unwrap();
        assert_eq!(gene.sequence().ir_payload, b"DNA!");
    }
}
