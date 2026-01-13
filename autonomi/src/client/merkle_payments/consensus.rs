// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Consensus-based merkle candidate selection.
//!
//! This module implements the consensus mechanism for selecting merkle payment candidates.
//!
//! Key concepts:
//! - **Storing nodes**: K closest nodes to a CHUNK address - they store data and validate merkle proofs
//! - **Merkle candidates**: 16 nodes closest to a MIDPOINT address - they receive merkle payments
//!
//! The consensus approach:
//! 1. For each midpoint, identify chunks that map to it
//! 2. Get storing nodes for those chunks (K closest to chunk addresses)
//! 3. Probe storing nodes by attempting upload with arbitrary candidates
//! 4. Storing nodes reject with TopologyVerificationFailed, revealing their view of closest peers to midpoint
//! 5. Build consensus by selecting candidates that appear in majority of views
//! 6. Use consensus candidates for the actual payment

use crate::Client;
use crate::networking::NetworkError;
use ant_evm::merkle_payments::{
    CANDIDATES_PER_POOL, MerkleBranch, MerklePaymentCandidateNode, MerklePaymentCandidatePool,
    MerklePaymentProof, MerkleTree, MidpointProof,
};
use ant_protocol::storage::{ChunkAddress, DataTypes, RecordKind, try_serialize_record};
use ant_protocol::{CLOSE_GROUP_SIZE, NetworkAddress};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use libp2p::PeerId;
use libp2p::kad::{PeerInfo, Record};
use std::collections::HashMap;
use std::num::NonZero;
use tracing::{debug, info, warn};
use xor_name::XorName;

/// Errors that can occur during consensus-based merkle candidate selection
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),
    #[error("Not enough topology responses: got {got}, needed at least {needed}")]
    InsufficientResponses { got: usize, needed: usize },
    #[error(
        "Could not reach consensus: only {found} candidates appear in majority of views (need {needed})"
    )]
    NoConsensus { found: usize, needed: usize },
    #[error("Failed to get quotes for consensus candidates: {0}")]
    QuoteFailed(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Merkle tree error: {0}")]
    MerkleTree(String),
}

/// Information about a node's view of network topology for a midpoint
#[derive(Debug, Clone)]
pub struct TopologyView {
    /// The storing node that provided this view (close to chunk address)
    pub from_node: PeerId,
    /// The storing node's view of closest peers to the midpoint (merkle candidates)
    pub closest_peers: Vec<PeerId>,
}

/// Result of consensus building for a single midpoint
#[derive(Debug, Clone)]
pub struct ConsensusResult {
    /// The midpoint address this consensus is for
    pub midpoint_address: XorName,
    /// The consensus candidates (PeerIds that appeared in majority of views)
    pub candidates: Vec<PeerId>,
    /// Number of topology views collected
    pub views_collected: usize,
}

/// Calculate which midpoint index a leaf/chunk belongs to.
///
/// The merkle tree is divided into midpoints at level depth/2.
/// Each midpoint covers `leaves_per_midpoint = tree_size / num_midpoints` leaves.
fn leaf_to_midpoint_index(leaf_index: usize, depth: u8) -> usize {
    let num_midpoints = ant_evm::merkle_payments::expected_reward_pools(depth);
    let tree_size = 1usize << depth; // 2^depth
    let leaves_per_midpoint = tree_size / num_midpoints;
    leaf_index / leaves_per_midpoint
}

impl Client {
    /// Probe storing nodes from ALL chunks that map to a midpoint.
    ///
    /// This collects topology views from ALL storing nodes across ALL chunks
    /// that map to the same midpoint, deduplicating nodes to avoid redundant probes.
    ///
    /// # Arguments
    /// * `chunk_addresses` - All chunk addresses that map to this midpoint
    /// * `midpoint_proof` - The midpoint proof for the merkle tree
    /// * `data_type` - The data type being uploaded
    /// * `data_size` - The data size for quotes
    ///
    /// # Returns
    /// * Vector of TopologyView from all unique storing nodes
    pub(crate) async fn probe_all_storing_nodes_for_topology(
        &self,
        chunk_addresses: &[XorName],
        midpoint_proof: &MidpointProof,
        data_type: DataTypes,
        data_size: usize,
    ) -> Result<Vec<TopologyView>, ConsensusError> {
        let midpoint_address = midpoint_proof.address();
        let merkle_payment_timestamp = midpoint_proof.merkle_payment_timestamp;

        info!(
            "Probing storing nodes from {} chunks for midpoint {midpoint_address:?}",
            chunk_addresses.len()
        );

        // Step 1: Collect storing nodes from ALL chunks, deduplicating by PeerId
        let mut all_storing_nodes: HashMap<PeerId, PeerInfo> = HashMap::new();

        for chunk_address in chunk_addresses {
            let chunk_network_addr =
                NetworkAddress::ChunkAddress(ChunkAddress::new(*chunk_address));
            let storing_nodes = self
                .network
                .get_closest_n_peers(
                    chunk_network_addr.clone(),
                    NonZero::new(CLOSE_GROUP_SIZE + 2).expect("CLOSE_GROUP_SIZE is non-zero"),
                )
                .await?;

            for peer_info in storing_nodes {
                all_storing_nodes
                    .entry(peer_info.peer_id)
                    .or_insert(peer_info);
            }
        }

        let storing_nodes: Vec<PeerInfo> = all_storing_nodes.into_values().collect();

        if storing_nodes.is_empty() {
            return Err(ConsensusError::InsufficientResponses { got: 0, needed: 1 });
        }

        info!(
            "Found {} unique storing nodes across {} chunks for midpoint {midpoint_address:?}",
            storing_nodes.len(),
            chunk_addresses.len()
        );

        // todo: remove later
        println!(
            "Found {} unique storing nodes across {} chunks for midpoint {midpoint_address:?}",
            storing_nodes.len(),
            chunk_addresses.len()
        );

        // Step 2: Re-use storing nodes as probe candidates
        let midpoint_closest: Vec<PeerInfo> = storing_nodes
            .iter()
            .take(CANDIDATES_PER_POOL)
            .cloned()
            .collect();

        // Step 3: Create probe candidate nodes by getting actual quotes from nodes close to midpoint
        let probe_candidates = self
            .create_probe_candidates(
                &midpoint_closest,
                midpoint_address,
                data_type,
                data_size,
                merkle_payment_timestamp,
            )
            .await?;

        // Step 4: Create probe merkle proof with the probe candidates
        let probe_pool = MerklePaymentCandidatePool {
            midpoint_proof: midpoint_proof.clone(),
            candidate_nodes: probe_candidates,
        };

        // Use first chunk address for the probe record
        let probe_chunk_address = chunk_addresses[0];
        let probe_chunk_network_addr =
            NetworkAddress::ChunkAddress(ChunkAddress::new(probe_chunk_address));
        let dummy_data = vec![0u8; 32];
        let probe_proof = MerklePaymentProof {
            address: probe_chunk_address,
            data_proof: create_dummy_merkle_branch(probe_chunk_address)?,
            winner_pool: probe_pool,
        };

        let record_kind = RecordKind::DataWithMerklePayment(data_type);
        let record = Record {
            key: probe_chunk_network_addr.to_record_key(),
            value: try_serialize_record(&(probe_proof.clone(), dummy_data), record_kind)
                .map_err(|e| {
                    ConsensusError::Serialization(format!("Failed to serialize probe: {e:?}"))
                })?
                .to_vec(),
            publisher: None,
            expires: None,
        };

        // Step 5: Probe ALL unique storing nodes in parallel
        let mut topology_views = Vec::new();
        let mut tasks = FuturesUnordered::new();

        for peer_info in storing_nodes {
            let peer_id = peer_info.peer_id;
            let network = self.network.clone();
            let record = record.clone();

            tasks.push(async move {
                let result = network.probe_for_topology(record, peer_info).await;
                (peer_id, result)
            });
        }

        // Collect topology views from TopologyVerificationFailed errors
        while let Some((peer_id, result)) = tasks.next().await {
            match result {
                Ok(node_peers) => {
                    debug!(
                        "Got topology view from storing node {peer_id:?} with {} peers",
                        node_peers.len()
                    );
                    topology_views.push(TopologyView {
                        from_node: peer_id,
                        closest_peers: node_peers,
                    });
                }
                Err(e) => {
                    warn!("Failed to probe storing node {peer_id:?}: {e}");
                    // Continue with other nodes
                }
            }
        }

        info!(
            "Collected {} topology views from storing nodes for midpoint {midpoint_address:?}",
            topology_views.len()
        );

        if topology_views.is_empty() {
            return Err(ConsensusError::InsufficientResponses { got: 0, needed: 1 });
        }

        Ok(topology_views)
    }

    /// Build consensus candidates from multiple topology views.
    ///
    /// This implements majority voting: a peer is selected if it appears in more than
    /// 50% of the topology views.
    ///
    /// # Arguments
    /// * `views` - Topology views from multiple storing nodes
    ///
    /// # Returns
    /// * Vector of CANDIDATES_PER_POOL PeerIds that appear in majority of views
    pub(crate) fn build_consensus_candidates(
        &self,
        views: &[TopologyView],
    ) -> Result<Vec<PeerId>, ConsensusError> {
        if views.is_empty() {
            return Err(ConsensusError::InsufficientResponses { got: 0, needed: 1 });
        }

        // Count occurrences of each peer across all views
        let mut peer_counts: HashMap<PeerId, usize> = HashMap::new();
        for view in views {
            for peer in &view.closest_peers {
                *peer_counts.entry(*peer).or_insert(0) += 1;
            }
        }

        // Calculate majority threshold (> 50% of views)
        let majority_threshold = views.len() / 2;

        // Filter peers that appear in majority of views and sort by count (descending)
        let mut candidates: Vec<(PeerId, usize)> = peer_counts
            .into_iter()
            .filter(|(_, count)| *count > majority_threshold)
            .collect();

        candidates.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by count descending

        // Take top CANDIDATES_PER_POOL candidates
        let selected: Vec<PeerId> = candidates
            .into_iter()
            .take(CANDIDATES_PER_POOL)
            .map(|(peer_id, _)| peer_id)
            .collect();

        if selected.len() < CANDIDATES_PER_POOL {
            warn!(
                "Only {} candidates reached consensus (need {})",
                selected.len(),
                CANDIDATES_PER_POOL
            );
            return Err(ConsensusError::NoConsensus {
                found: selected.len(),
                needed: CANDIDATES_PER_POOL,
            });
        }

        debug!(
            "Built consensus with {} candidates from {} views",
            selected.len(),
            views.len()
        );

        Ok(selected)
    }

    /// Get merkle candidate quotes from specific peer IDs.
    ///
    /// This is used after consensus to get actual signed quotes from the consensus candidates.
    pub(crate) async fn get_quotes_from_consensus_candidates(
        &self,
        peer_ids: &[PeerId],
        midpoint_address: XorName,
        data_type: DataTypes,
        data_size: usize,
        merkle_payment_timestamp: u64,
    ) -> Result<[MerklePaymentCandidateNode; CANDIDATES_PER_POOL], ConsensusError> {
        let network_addr = NetworkAddress::ChunkAddress(ChunkAddress::new(midpoint_address));

        // Get PeerInfo for each consensus candidate
        let mut peer_infos = Vec::with_capacity(peer_ids.len());
        for peer_id in peer_ids {
            if let Some(peer_info) = self.network.get_peer_info(*peer_id).await {
                peer_infos.push(peer_info);
            } else {
                warn!("Could not find peer info for consensus candidate {peer_id:?}");
            }
        }

        if peer_infos.len() < CANDIDATES_PER_POOL {
            return Err(ConsensusError::QuoteFailed(format!(
                "Only found {} peer infos out of {} consensus candidates",
                peer_infos.len(),
                peer_ids.len()
            )));
        }

        // Request quotes from consensus candidates in parallel
        let mut tasks = FuturesUnordered::new();
        let data_type_index = data_type.get_index();

        for peer_info in peer_infos {
            let network = self.network.clone();
            let network_addr = network_addr.clone();
            let peer_id = peer_info.peer_id;

            tasks.push(async move {
                let result = network
                    .get_merkle_candidate_quote(
                        network_addr,
                        peer_info,
                        data_type_index,
                        data_size,
                        merkle_payment_timestamp,
                    )
                    .await;
                (peer_id, result)
            });
        }

        // Collect successful responses
        let mut candidates: Vec<MerklePaymentCandidateNode> = Vec::new();
        while let Some((peer_id, result)) = tasks.next().await {
            match result {
                Ok(candidate) => {
                    candidates.push(candidate);
                    if candidates.len() >= CANDIDATES_PER_POOL {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Failed to get quote from consensus candidate {peer_id:?}: {e}");
                }
            }
        }

        if candidates.len() < CANDIDATES_PER_POOL {
            return Err(ConsensusError::QuoteFailed(format!(
                "Only got {} quotes from consensus candidates (need {})",
                candidates.len(),
                CANDIDATES_PER_POOL
            )));
        }

        candidates.try_into().map_err(|v: Vec<_>| {
            ConsensusError::QuoteFailed(format!(
                "Wrong number of candidates: {} (need {})",
                v.len(),
                CANDIDATES_PER_POOL
            ))
        })
    }

    /// Create probe candidate nodes for initial topology discovery.
    async fn create_probe_candidates(
        &self,
        peers: &[PeerInfo],
        midpoint_address: XorName,
        data_type: DataTypes,
        data_size: usize,
        merkle_payment_timestamp: u64,
    ) -> Result<[MerklePaymentCandidateNode; CANDIDATES_PER_POOL], ConsensusError> {
        let network_addr = NetworkAddress::ChunkAddress(ChunkAddress::new(midpoint_address));
        let data_type_index = data_type.get_index();

        let mut tasks = FuturesUnordered::new();

        for peer_info in peers.iter().take(CANDIDATES_PER_POOL + 4) {
            let network = self.network.clone();
            let network_addr = network_addr.clone();
            let peer_info = peer_info.clone();
            let peer_id = peer_info.peer_id;

            tasks.push(async move {
                let result = network
                    .get_merkle_candidate_quote(
                        network_addr,
                        peer_info,
                        data_type_index,
                        data_size,
                        merkle_payment_timestamp,
                    )
                    .await;
                (peer_id, result)
            });
        }

        let mut candidates: Vec<MerklePaymentCandidateNode> = Vec::new();
        while let Some((peer_id, result)) = tasks.next().await {
            match result {
                Ok(candidate) => {
                    candidates.push(candidate);
                    if candidates.len() >= CANDIDATES_PER_POOL {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Failed to get probe quote from {peer_id:?}: {e}");
                }
            }
        }

        if candidates.len() < CANDIDATES_PER_POOL {
            return Err(ConsensusError::InsufficientResponses {
                got: candidates.len(),
                needed: CANDIDATES_PER_POOL,
            });
        }

        candidates
            .try_into()
            .map_err(|v: Vec<_>| ConsensusError::InsufficientResponses {
                got: v.len(),
                needed: CANDIDATES_PER_POOL,
            })
    }

    /// Build a consensus-based candidate pool for a single midpoint.
    ///
    /// This is the main entry point for consensus-based candidate selection.
    /// It probes ALL storing nodes from ALL chunks that map to this midpoint,
    /// builds consensus from their views, and returns a candidate pool.
    ///
    /// # Arguments
    /// * `midpoint_proof` - The midpoint proof
    /// * `midpoint_index` - Index of this midpoint
    /// * `addresses` - All chunk addresses in the batch
    /// * `depth` - Tree depth
    /// * `data_type` - The data type being uploaded
    /// * `data_size` - The data size
    ///
    /// # Returns
    /// * MerklePaymentCandidatePool with consensus-selected candidates
    pub(crate) async fn build_consensus_candidate_pool(
        &self,
        midpoint_proof: MidpointProof,
        midpoint_index: usize,
        addresses: &[XorName],
        depth: u8,
        data_type: DataTypes,
        data_size: usize,
    ) -> Result<MerklePaymentCandidatePool, ConsensusError> {
        let midpoint_address = midpoint_proof.address();
        let merkle_payment_timestamp = midpoint_proof.merkle_payment_timestamp;

        info!(
            "Building consensus candidate pool for midpoint {midpoint_index} ({midpoint_address:?})"
        );

        // Find all chunks that map to this midpoint
        let chunks_for_midpoint: Vec<XorName> = addresses
            .iter()
            .enumerate()
            .filter(|(i, _)| leaf_to_midpoint_index(*i, depth) == midpoint_index)
            .map(|(_, addr)| *addr)
            .collect();

        if chunks_for_midpoint.is_empty() {
            return Err(ConsensusError::InsufficientResponses { got: 0, needed: 1 });
        }

        info!(
            "Midpoint {midpoint_index} has {} chunks to probe storing nodes from",
            chunks_for_midpoint.len()
        );

        // Step 1: Probe storing nodes from ALL chunks that map to this midpoint
        // Collect topology views from all storing nodes
        let topology_views = self
            .probe_all_storing_nodes_for_topology(
                &chunks_for_midpoint,
                &midpoint_proof,
                data_type,
                data_size,
            )
            .await?;

        // Step 2: Build consensus from topology views
        let consensus_candidates = self.build_consensus_candidates(&topology_views)?;

        // Step 3: Get actual signed quotes from consensus candidates
        let candidate_nodes = self
            .get_quotes_from_consensus_candidates(
                &consensus_candidates,
                midpoint_address,
                data_type,
                data_size,
                merkle_payment_timestamp,
            )
            .await?;

        // Step 4: Build the pool
        let pool = MerklePaymentCandidatePool {
            midpoint_proof,
            candidate_nodes,
        };

        info!(
            "Built consensus candidate pool for midpoint {midpoint_index} with {} candidates",
            CANDIDATES_PER_POOL
        );

        Ok(pool)
    }

    /// Build consensus-based candidate pools for all midpoints (in parallel).
    ///
    /// # Arguments
    /// * `midpoint_proofs` - The midpoint proofs from the merkle tree
    /// * `addresses` - All chunk addresses in the batch
    /// * `depth` - Tree depth
    /// * `data_type` - Data type for all items in batch
    /// * `data_size` - The per-record data size
    ///
    /// # Returns
    /// * Vector of MerklePaymentCandidatePool, one for each midpoint
    pub(crate) async fn build_consensus_candidate_pools(
        &self,
        midpoint_proofs: Vec<MidpointProof>,
        addresses: &[XorName],
        depth: u8,
        data_type: DataTypes,
        data_size: usize,
    ) -> Result<Vec<MerklePaymentCandidatePool>, ConsensusError> {
        info!(
            "Building consensus candidate pools for {} midpoints from {} addresses",
            midpoint_proofs.len(),
            addresses.len()
        );

        // Build all pools in parallel
        let pool_futures =
            midpoint_proofs
                .into_iter()
                .enumerate()
                .map(|(midpoint_index, proof)| {
                    let client = self.clone();
                    let addresses = addresses.to_vec();
                    async move {
                        client
                            .build_consensus_candidate_pool(
                                proof,
                                midpoint_index,
                                &addresses,
                                depth,
                                data_type,
                                data_size,
                            )
                            .await
                    }
                });

        let pools: Vec<MerklePaymentCandidatePool> =
            futures::future::try_join_all(pool_futures).await?;

        info!("Built {} consensus candidate pools", pools.len());

        Ok(pools)
    }
}

/// Create a dummy merkle branch for probing.
fn create_dummy_merkle_branch(address: XorName) -> Result<MerkleBranch, ConsensusError> {
    let addresses = vec![address, XorName::from_content(b"dummy_padding")];

    let tree = MerkleTree::from_xornames(addresses.clone())
        .map_err(|e| ConsensusError::MerkleTree(format!("Failed to create dummy tree: {e}")))?;

    tree.generate_address_proof(0, addresses[0])
        .map_err(|e| ConsensusError::MerkleTree(format!("Failed to generate dummy proof: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_to_midpoint_mapping() {
        // For depth 4: 16 leaves, 4 midpoints (2^ceil(4/2) = 4), 4 leaves per midpoint
        assert_eq!(leaf_to_midpoint_index(0, 4), 0);
        assert_eq!(leaf_to_midpoint_index(3, 4), 0);
        assert_eq!(leaf_to_midpoint_index(4, 4), 1);
        assert_eq!(leaf_to_midpoint_index(7, 4), 1);
        assert_eq!(leaf_to_midpoint_index(8, 4), 2);
        assert_eq!(leaf_to_midpoint_index(15, 4), 3);

        // For depth 8: 256 leaves, 16 midpoints, 16 leaves per midpoint
        assert_eq!(leaf_to_midpoint_index(0, 8), 0);
        assert_eq!(leaf_to_midpoint_index(15, 8), 0);
        assert_eq!(leaf_to_midpoint_index(16, 8), 1);
        assert_eq!(leaf_to_midpoint_index(255, 8), 15);
    }

    #[test]
    fn test_build_consensus_from_views() {
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();
        let peer4 = PeerId::random();

        // Views where peer1, peer2, peer3 appear in all views, peer4 only in one
        let views = vec![
            TopologyView {
                from_node: PeerId::random(),
                closest_peers: vec![peer1, peer2, peer3],
            },
            TopologyView {
                from_node: PeerId::random(),
                closest_peers: vec![peer1, peer2, peer3],
            },
            TopologyView {
                from_node: PeerId::random(),
                closest_peers: vec![peer1, peer2, peer3, peer4],
            },
        ];

        let mut peer_counts: HashMap<PeerId, usize> = HashMap::new();
        for view in &views {
            for peer in &view.closest_peers {
                *peer_counts.entry(*peer).or_insert(0) += 1;
            }
        }

        let majority_threshold = views.len() / 2; // 1 for 3 views

        let candidates: Vec<PeerId> = peer_counts
            .into_iter()
            .filter(|(_, count)| *count > majority_threshold)
            .map(|(peer_id, _)| peer_id)
            .collect();

        assert!(candidates.contains(&peer1));
        assert!(candidates.contains(&peer2));
        assert!(candidates.contains(&peer3));
        // peer4 appears in 1 view, which is NOT > 1
        assert!(!candidates.contains(&peer4));
    }

    #[test]
    fn test_consensus_with_disagreement() {
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();

        let views = vec![
            TopologyView {
                from_node: PeerId::random(),
                closest_peers: vec![peer1, peer2, peer_a],
            },
            TopologyView {
                from_node: PeerId::random(),
                closest_peers: vec![peer1, peer3, peer_b],
            },
            TopologyView {
                from_node: PeerId::random(),
                closest_peers: vec![peer2, peer3, peer_a],
            },
            TopologyView {
                from_node: PeerId::random(),
                closest_peers: vec![peer1, peer2, peer3],
            },
        ];

        let mut peer_counts: HashMap<PeerId, usize> = HashMap::new();
        for view in &views {
            for peer in &view.closest_peers {
                *peer_counts.entry(*peer).or_insert(0) += 1;
            }
        }

        let majority_threshold = views.len() / 2; // 2 for 4 views

        assert_eq!(peer_counts.get(&peer1), Some(&3));
        assert_eq!(peer_counts.get(&peer2), Some(&3));
        assert_eq!(peer_counts.get(&peer3), Some(&3));
        assert_eq!(peer_counts.get(&peer_a), Some(&2));
        assert_eq!(peer_counts.get(&peer_b), Some(&1));

        let passing: Vec<PeerId> = peer_counts
            .into_iter()
            .filter(|(_, count)| *count > majority_threshold)
            .map(|(peer_id, _)| peer_id)
            .collect();

        assert_eq!(passing.len(), 3);
        assert!(passing.contains(&peer1));
        assert!(passing.contains(&peer2));
        assert!(passing.contains(&peer3));
    }
}
