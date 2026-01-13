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
    CANDIDATES_PER_POOL, MerklePaymentCandidateNode, MerklePaymentCandidatePool,
    MerklePaymentProof, MerkleTree, MidpointProof,
};
use ant_evm::{AttoTokens, EvmWallet};
use ant_protocol::storage::{Chunk, ChunkAddress, DataTypes, RecordKind, try_serialize_record};
use ant_protocol::{CLOSE_GROUP_SIZE, NetworkAddress};
use evmlib::merkle_batch_payment::PoolCommitment;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use libp2p::PeerId;
use libp2p::kad::{PeerInfo, Record};
use std::collections::HashMap;
use std::num::{NonZero, NonZeroUsize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
    #[error("Wallet error: {0}")]
    Wallet(String),
    #[error("Failed to get timestamp: {0}")]
    Timestamp(#[from] std::time::SystemTimeError),
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
    /// that map to the same midpoint. Each storing node is probed with a record
    /// containing actual chunk data and a PAID merkle proof.
    ///
    /// The probing payment is a small merkle tree payment that allows nodes to
    /// validate the proof and return their topology view (via TopologyVerificationFailed).
    ///
    /// # Arguments
    /// * `chunks` - All chunks that map to this midpoint (with actual data)
    /// * `midpoint_proof` - The midpoint proof for the main merkle tree
    /// * `data_type` - The data type being uploaded
    /// * `data_size` - The data size for quotes
    /// * `wallet` - The wallet to pay for probing
    ///
    /// # Returns
    /// * (topology_views, probe_cost) - Topology views from storing nodes and cost of probing
    pub(crate) async fn probe_all_storing_nodes_for_topology(
        &self,
        chunks: &[Chunk],
        midpoint_proof: &MidpointProof,
        data_type: DataTypes,
        data_size: usize,
        wallet: &EvmWallet,
    ) -> Result<(Vec<TopologyView>, AttoTokens), ConsensusError> {
        let midpoint_address = midpoint_proof.address();

        info!(
            "Probing storing nodes from {} chunks for midpoint {midpoint_address:?}",
            chunks.len()
        );

        // Step 1: Collect storing nodes from ALL chunks, tracking which chunk they're responsible for
        // HashMap from PeerId -> (PeerInfo, chunk they're responsible for, leaf_index)
        let mut storing_node_to_chunk: HashMap<PeerId, (PeerInfo, Chunk, usize)> = HashMap::new();

        for (leaf_index, chunk) in chunks.iter().enumerate() {
            let chunk_network_addr = NetworkAddress::ChunkAddress(*chunk.address());
            let storing_nodes = self
                .network
                .get_closest_n_peers(
                    chunk_network_addr.clone(),
                    NonZero::new(CANDIDATES_PER_POOL + 4).expect("CLOSE_GROUP_SIZE is non-zero"),
                )
                .await?;

            for peer_info in storing_nodes {
                // Only insert if not already present (keep the first chunk they were found for)
                storing_node_to_chunk.entry(peer_info.peer_id).or_insert((
                    peer_info,
                    chunk.clone(),
                    leaf_index,
                ));
            }
        }

        if storing_node_to_chunk.is_empty() {
            return Err(ConsensusError::InsufficientResponses { got: 0, needed: 1 });
        }

        info!(
            "Found {} unique storing nodes across {} chunks for midpoint {midpoint_address:?}",
            storing_node_to_chunk.len(),
            chunks.len()
        );

        // Step 2: Build a probe merkle tree from the chunks
        let addresses: Vec<XorName> = chunks.iter().map(|c| *c.name()).collect();

        // Pad to minimum 2 leaves if only 1 chunk
        let (addresses, _chunks_padded) = if addresses.len() == 1 {
            (
                vec![addresses[0], addresses[0]],
                vec![chunks[0].clone(), chunks[0].clone()],
            )
        } else {
            (addresses, chunks.to_vec())
        };

        let probe_tree = MerkleTree::from_xornames(addresses.clone())
            .map_err(|e| ConsensusError::MerkleTree(format!("Failed to build probe tree: {e}")))?;
        let probe_depth = probe_tree.depth();

        // Step 3: Get timestamp and initial candidate pools for probe tree
        let probe_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
            - Duration::from_mins(10).as_secs();
        let probe_midpoint_proofs = probe_tree.reward_candidates(probe_timestamp).map_err(|e| {
            ConsensusError::MerkleTree(format!("Failed to get probe midpoint proofs: {e}"))
        })?;

        // Step 4: Get initial candidate pools using non-consensus approach
        let mut probe_candidate_pools = Vec::with_capacity(probe_midpoint_proofs.len());
        for probe_mp in &probe_midpoint_proofs {
            let pool = self
                .build_initial_candidate_pool(probe_mp.clone(), data_type, data_size)
                .await?;
            probe_candidate_pools.push(pool);
        }

        // Step 5: Pay for the probe tree
        let pool_commitments: Vec<PoolCommitment> = probe_candidate_pools
            .iter()
            .map(|pool| pool.to_commitment())
            .collect();

        debug!(
            "Paying for probe tree with {} pools",
            pool_commitments.len()
        );
        let lock_guard = wallet.lock().await;
        let (winner_pool_hash, probe_amount) = wallet
            .pay_for_merkle_tree(probe_depth, pool_commitments, probe_timestamp)
            .await
            .map_err(|e| ConsensusError::Wallet(format!("Failed to pay for probe tree: {e}")))?;
        let probe_cost = AttoTokens::from_atto(probe_amount);
        drop(lock_guard);

        info!("Probe payment submitted, winner pool: {winner_pool_hash:?}, cost: {probe_cost}");

        // Step 6: Find winner pool and generate proofs
        let winner_pool = probe_candidate_pools
            .into_iter()
            .find(|pool| pool.hash() == winner_pool_hash)
            .ok_or_else(|| {
                ConsensusError::Wallet(format!(
                    "Probe payment returned invalid pool hash: {}",
                    hex::encode(winner_pool_hash)
                ))
            })?;

        // Generate proofs for each chunk
        let mut chunk_proofs: HashMap<XorName, MerklePaymentProof> = HashMap::new();
        for (i, address) in addresses.iter().enumerate() {
            let address_proof = probe_tree
                .generate_address_proof(i, *address)
                .map_err(|e| {
                    ConsensusError::MerkleTree(format!(
                        "Failed to generate probe address proof: {e}"
                    ))
                })?;
            let payment_proof = MerklePaymentProof {
                address: *address,
                data_proof: address_proof,
                winner_pool: winner_pool.clone(),
            };
            chunk_proofs.insert(*address, payment_proof);
        }

        // Step 7: Probe each storing node with paid proofs
        let mut topology_views = Vec::new();
        let mut tasks = FuturesUnordered::new();
        let record_kind = RecordKind::DataWithMerklePayment(data_type);

        for (peer_id, (peer_info, chunk, _leaf_index)) in storing_node_to_chunk {
            let chunk_address = *chunk.name();
            let chunk_network_addr = NetworkAddress::ChunkAddress(*chunk.address());

            // Use the paid proof for this chunk
            let probe_proof = chunk_proofs.get(&chunk_address).cloned().ok_or_else(|| {
                ConsensusError::Serialization(format!(
                    "Missing probe proof for chunk {chunk_address:?}"
                ))
            })?;

            let record = Record {
                key: chunk_network_addr.to_record_key(),
                value: try_serialize_record(&(probe_proof, chunk), record_kind)
                    .map_err(|e| {
                        ConsensusError::Serialization(format!("Failed to serialize probe: {e:?}"))
                    })?
                    .to_vec(),
                publisher: None,
                expires: None,
            };

            let network = self.network.clone();
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

        Ok((topology_views, probe_cost))
    }

    /// Build an initial (non-consensus) candidate pool for a midpoint.
    ///
    /// This is used for probe payments before we have consensus.
    async fn build_initial_candidate_pool(
        &self,
        midpoint_proof: MidpointProof,
        data_type: DataTypes,
        data_size: usize,
    ) -> Result<MerklePaymentCandidatePool, ConsensusError> {
        let midpoint_address = midpoint_proof.address();
        let merkle_payment_timestamp = midpoint_proof.merkle_payment_timestamp;

        let midpoint_network_addr =
            NetworkAddress::ChunkAddress(ChunkAddress::new(midpoint_address));

        let closest = self
            .network
            .get_closest_n_peers(
                midpoint_network_addr.clone(),
                NonZeroUsize::new(CANDIDATES_PER_POOL).expect("CANDIDATES_PER_POOL is non-zero"),
            )
            .await?;

        if closest.len() < CANDIDATES_PER_POOL {
            return Err(ConsensusError::InsufficientResponses {
                got: closest.len(),
                needed: CANDIDATES_PER_POOL,
            });
        }

        // Get quotes from closest nodes
        let candidates = self
            .create_probe_candidates(
                &closest,
                midpoint_address,
                data_type,
                data_size,
                merkle_payment_timestamp,
            )
            .await?;

        Ok(MerklePaymentCandidatePool {
            midpoint_proof,
            candidate_nodes: candidates,
        })
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
    /// * `chunks` - All chunks in the batch (with actual data for probing)
    /// * `depth` - Tree depth
    /// * `data_type` - The data type being uploaded
    /// * `data_size` - The data size
    /// * `wallet` - The wallet for paying for probes
    ///
    /// # Returns
    /// * (MerklePaymentCandidatePool, probe_cost) - Pool with consensus candidates and probe cost
    pub(crate) async fn build_consensus_candidate_pool(
        &self,
        midpoint_proof: MidpointProof,
        midpoint_index: usize,
        chunks: &[Chunk],
        depth: u8,
        data_type: DataTypes,
        data_size: usize,
        wallet: &EvmWallet,
    ) -> Result<(MerklePaymentCandidatePool, AttoTokens), ConsensusError> {
        let midpoint_address = midpoint_proof.address();
        let merkle_payment_timestamp = midpoint_proof.merkle_payment_timestamp;

        info!(
            "Building consensus candidate pool for midpoint {midpoint_index} ({midpoint_address:?})"
        );

        // Find all chunks that map to this midpoint
        let chunks_for_midpoint: Vec<Chunk> = chunks
            .iter()
            .enumerate()
            .filter(|(i, _)| leaf_to_midpoint_index(*i, depth) == midpoint_index)
            .map(|(_, chunk)| chunk.clone())
            .collect();

        if chunks_for_midpoint.is_empty() {
            return Err(ConsensusError::InsufficientResponses { got: 0, needed: 1 });
        }

        info!(
            "Midpoint {midpoint_index} has {} chunks to probe storing nodes from",
            chunks_for_midpoint.len()
        );

        // Step 1: Probe storing nodes from ALL chunks that map to this midpoint
        // Collect topology views from all storing nodes (this pays for probing)
        let (topology_views, probe_cost) = self
            .probe_all_storing_nodes_for_topology(
                &chunks_for_midpoint,
                &midpoint_proof,
                data_type,
                data_size,
                wallet,
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
            "Built consensus candidate pool for midpoint {midpoint_index} with {} candidates, probe cost: {probe_cost}",
            CANDIDATES_PER_POOL
        );

        Ok((pool, probe_cost))
    }

    /// Build consensus-based candidate pools for all midpoints (sequentially to avoid wallet contention).
    ///
    /// Note: Probing requires on-chain payments, so we process midpoints sequentially
    /// to avoid wallet locking issues. The wallet uses an async mutex internally.
    ///
    /// # Arguments
    /// * `midpoint_proofs` - The midpoint proofs from the merkle tree
    /// * `chunks` - All chunks in the batch (with actual data for probing)
    /// * `depth` - Tree depth
    /// * `data_type` - Data type for all items in batch
    /// * `data_size` - The per-record data size
    /// * `wallet` - The wallet for paying for probes
    ///
    /// # Returns
    /// * (pools, total_probe_cost) - Vector of pools and total cost for probing
    pub(crate) async fn build_consensus_candidate_pools(
        &self,
        midpoint_proofs: Vec<MidpointProof>,
        chunks: &[Chunk],
        depth: u8,
        data_type: DataTypes,
        data_size: usize,
        wallet: &EvmWallet,
    ) -> Result<(Vec<MerklePaymentCandidatePool>, AttoTokens), ConsensusError> {
        info!(
            "Building consensus candidate pools for {} midpoints from {} chunks",
            midpoint_proofs.len(),
            chunks.len()
        );

        // Build pools sequentially to avoid wallet contention
        // Each probe payment requires the wallet lock
        let mut pools = Vec::with_capacity(midpoint_proofs.len());
        let mut total_probe_cost = AttoTokens::zero();

        for (midpoint_index, proof) in midpoint_proofs.into_iter().enumerate() {
            let (pool, probe_cost) = self
                .build_consensus_candidate_pool(
                    proof,
                    midpoint_index,
                    chunks,
                    depth,
                    data_type,
                    data_size,
                    wallet,
                )
                .await?;
            pools.push(pool);
            total_probe_cost = AttoTokens::from_atto(
                total_probe_cost
                    .as_atto()
                    .saturating_add(probe_cost.as_atto()),
            );
        }

        info!(
            "Built {} consensus candidate pools, total probe cost: {total_probe_cost}",
            pools.len()
        );

        Ok((pools, total_probe_cost))
    }
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
