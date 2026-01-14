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
use std::collections::{HashMap, HashSet};
use std::num::{NonZero, NonZeroUsize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};
use xor_name::XorName;

/// A constant that defines the minimum number of common Merkle pool candidates required.
const MIN_COMMON_MERKLE_CANDIDATES: usize = 8;

/// Minimum number of nodes that must accept a chunk during probing for it to be considered already uploaded.
/// This ensures data redundancy - we want at least a quorum of nodes to have the chunk.
const MIN_NODES_ACCEPT_CHUNK: usize = 3;

/// Errors that can occur during consensus-based merkle candidate selection
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),
    #[error("Not enough topology responses: got {got}, needed at least {needed} ({context})")]
    InsufficientResponses {
        got: usize,
        needed: usize,
        context: String,
    },
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
    /// The chunk address this view is for
    pub chunk_address: XorName,
    /// The storing node that provided this view (close to chunk address)
    pub from_node: PeerId,
    /// The storing node's view of closest peers to the midpoint (merkle candidates)
    pub merkle_candidates: Vec<PeerId>,
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
    /// * (topology_views, accepted_chunks, acceptance_counts, probe_cost) - Topology views, chunks accepted by at least MIN_NODES_ACCEPT_CHUNK nodes, all acceptance counts, and cost of probing
    pub(crate) async fn probe_all_storing_nodes_for_topology(
        &self,
        chunks: &[Chunk],
        midpoint_proof: &MidpointProof,
        data_type: DataTypes,
        data_size: usize,
        wallet: &EvmWallet,
    ) -> Result<
        (
            Vec<TopologyView>,
            HashSet<XorName>,
            HashMap<XorName, usize>,
            AttoTokens,
        ),
        ConsensusError,
    > {
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
                    NonZero::new(CLOSE_GROUP_SIZE + 2).expect("CLOSE_GROUP_SIZE is non-zero"),
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
            return Err(ConsensusError::InsufficientResponses {
                got: 0,
                needed: 1,
                context: format!(
                    "probe_all_storing_nodes_for_topology: no storing nodes found across {} chunks for midpoint {:?}",
                    chunks.len(),
                    midpoint_address
                ),
            });
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
        let mut chunk_acceptance_counts: HashMap<XorName, usize> = HashMap::new();
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
                let result = network
                    .probe_for_topology(chunk_address, record, peer_info)
                    .await;
                (peer_id, chunk_address, result)
            });
        }

        // Collect topology views and track chunk acceptances
        while let Some((peer_id, chunk_address, result)) = tasks.next().await {
            match result {
                Ok((chunk_addr, node_peers, accepted)) => {
                    if accepted {
                        // Chunk was accepted during probing - increment acceptance count
                        let count = chunk_acceptance_counts.entry(chunk_addr).or_insert(0);
                        *count += 1;
                        debug!(
                            "Chunk {chunk_address:?} was accepted during probing by {peer_id:?} (count: {count})"
                        );
                    } else {
                        // Normal topology view response
                        debug!(
                            "Got topology view from storing node {peer_id:?} with {} peers",
                            node_peers.len()
                        );
                        topology_views.push(TopologyView {
                            chunk_address,
                            from_node: peer_id,
                            merkle_candidates: node_peers,
                        });
                    }
                }
                Err(e) => {
                    warn!("Failed to probe storing node {peer_id:?}: {e}");
                    // Continue with other nodes
                }
            }
        }

        // Identify chunks that were accepted by at least MIN_NODES_ACCEPT_CHUNK nodes
        // These will be skipped entirely during upload
        let accepted_chunks: HashSet<XorName> = chunk_acceptance_counts
            .iter()
            .filter_map(|(chunk_addr, count)| {
                if *count >= MIN_NODES_ACCEPT_CHUNK {
                    info!(
                        "Chunk {chunk_addr:?} was accepted by {count} nodes (>= {MIN_NODES_ACCEPT_CHUNK}) - will skip upload"
                    );
                    Some(*chunk_addr)
                } else {
                    debug!(
                        "Chunk {chunk_addr:?} was accepted by only {count} nodes (< {MIN_NODES_ACCEPT_CHUNK}) - needs consensus for {} more",
                        MIN_NODES_ACCEPT_CHUNK - count
                    );
                    None
                }
            })
            .collect();

        info!(
            "Collected {} topology views and {} accepted chunks (>= {MIN_NODES_ACCEPT_CHUNK} acceptances) from storing nodes for midpoint {midpoint_address:?}",
            topology_views.len(),
            accepted_chunks.len()
        );

        if topology_views.is_empty() && accepted_chunks.is_empty() {
            return Err(ConsensusError::InsufficientResponses {
                got: 0,
                needed: 1,
                context: format!(
                    "probe_all_storing_nodes_for_topology: all topology probes failed for midpoint {:?}",
                    midpoint_address
                ),
            });
        }

        Ok((
            topology_views,
            accepted_chunks,
            chunk_acceptance_counts,
            probe_cost,
        ))
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
                NonZeroUsize::new(CANDIDATES_PER_POOL + 4)
                    .expect("CANDIDATES_PER_POOL is non-zero"),
            )
            .await?;

        if closest.len() < CANDIDATES_PER_POOL {
            return Err(ConsensusError::InsufficientResponses {
                got: closest.len(),
                needed: CANDIDATES_PER_POOL,
                context: format!(
                    "build_initial_candidate_pool: not enough closest peers for midpoint {:?}",
                    midpoint_address
                ),
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
    /// For every chunk, we select N topology views (where N = 3 - acceptance_count) that have
    /// at least 8 merkle candidates in common with all selected views from other chunks.
    /// This allows chunks with partial replication to need fewer consensus views.
    ///
    /// # Algorithm
    /// 1. Group views by chunk address
    /// 2. For each group, generate all N-view combinations with >= 8 common candidates (N based on acceptance count)
    /// 3. Cross-check combinations between groups to find a valid global selection
    /// 4. If common candidates < 16, pad with most frequent peers from the combinations
    ///
    /// # Arguments
    /// * `views` - Topology views from multiple storing nodes
    /// * `acceptance_counts` - Number of nodes that already accepted each chunk during probing
    ///
    /// # Returns
    /// * Vector of CANDIDATES_PER_POOL PeerIds and hashmap of the selected storing nodes per chunk address
    pub(crate) fn build_consensus_candidates(
        &self,
        views: &[TopologyView],
        acceptance_counts: &HashMap<XorName, usize>,
    ) -> Result<(Vec<PeerId>, HashMap<XorName, Vec<PeerId>>), ConsensusError> {
        if views.is_empty() {
            return Err(ConsensusError::InsufficientResponses {
                got: 0,
                needed: 1,
                context: "build_consensus_candidates: no topology views provided".to_string(),
            });
        }

        // Step 1: Group views by chunk address and determine required views per chunk
        let mut views_by_chunk: HashMap<XorName, Vec<&TopologyView>> = HashMap::new();
        let mut required_views_per_chunk: HashMap<XorName, usize> = HashMap::new();

        for view in views {
            views_by_chunk
                .entry(view.chunk_address)
                .or_default()
                .push(view);

            // Calculate required views: 3 - nodes that already accepted this chunk
            let acceptance_count = acceptance_counts
                .get(&view.chunk_address)
                .copied()
                .unwrap_or(0);
            let required = MIN_NODES_ACCEPT_CHUNK.saturating_sub(acceptance_count);
            required_views_per_chunk.insert(view.chunk_address, required);
        }

        debug!(
            "Grouped {} views into {} chunk address groups",
            views.len(),
            views_by_chunk.len()
        );

        // Step 2: For each group, generate valid N-view combinations (>= 8 common candidates)
        // where N = 3 - acceptance_count for that chunk
        // Store as: chunk_address -> Vec<(view_indices, common_candidates_set)>
        let mut valid_combinations: HashMap<XorName, Vec<(Vec<usize>, HashSet<PeerId>)>> =
            HashMap::new();

        for (chunk_addr, chunk_views) in &views_by_chunk {
            let required_views = *required_views_per_chunk
                .get(chunk_addr)
                .unwrap_or(&MIN_NODES_ACCEPT_CHUNK);
            let acceptance_count = acceptance_counts.get(chunk_addr).copied().unwrap_or(0);

            let combinations = Self::generate_valid_combinations(chunk_views, required_views);
            if combinations.is_empty() {
                warn!(
                    "No valid {required_views}-view combinations for chunk {chunk_addr:?} with {} views ({acceptance_count} already accepted)",
                    chunk_views.len()
                );
            } else {
                debug!(
                    "Chunk {chunk_addr:?}: {} valid {required_views}-view combinations from {} views ({acceptance_count} already accepted)",
                    combinations.len(),
                    chunk_views.len()
                );
            }
            valid_combinations.insert(*chunk_addr, combinations);
        }

        // Step 3: Cross-check combinations between groups
        let chunk_addrs: Vec<XorName> = valid_combinations.keys().copied().collect();

        let (global_common, selected_indices) =
            Self::find_cross_group_consensus(&chunk_addrs, &valid_combinations)?;

        debug!(
            "Found cross-group consensus with {} common candidates",
            global_common.len()
        );

        // Step 4: Build the selected storing nodes map
        let mut selected_storing_nodes: HashMap<XorName, Vec<PeerId>> = HashMap::new();
        for (chunk_addr, combo_idx) in &selected_indices {
            if let Some(chunk_views) = views_by_chunk.get(chunk_addr) {
                if let Some(combinations) = valid_combinations.get(chunk_addr) {
                    if let Some((view_indices, _)) = combinations.get(*combo_idx) {
                        let storing_nodes: Vec<PeerId> = view_indices
                            .iter()
                            .filter_map(|&i| chunk_views.get(i).map(|v| v.from_node))
                            .collect();
                        selected_storing_nodes.insert(*chunk_addr, storing_nodes);
                    }
                }
            }
        }

        // Step 5: If common candidates < 16, pad with most frequent peers
        let final_candidates = if global_common.len() >= CANDIDATES_PER_POOL {
            global_common
                .into_iter()
                .take(CANDIDATES_PER_POOL)
                .collect()
        } else {
            Self::pad_candidates_by_frequency(global_common, &selected_indices, &valid_combinations)
        };

        if final_candidates.len() < CANDIDATES_PER_POOL {
            return Err(ConsensusError::NoConsensus {
                found: final_candidates.len(),
                needed: CANDIDATES_PER_POOL,
            });
        }

        info!(
            "Built consensus with {} candidates from {} chunk groups",
            final_candidates.len(),
            selected_storing_nodes.len()
        );

        #[cfg(feature = "loud")]
        println!(
            "✓ Consensus found: {} merkle candidates agreed upon by storing nodes for {} chunks",
            final_candidates.len(),
            selected_storing_nodes.len()
        );

        Ok((final_candidates, selected_storing_nodes))
    }

    /// Generate all valid N-view combinations for a chunk's views.
    /// A combination is valid if the N views share at least 8 merkle candidates.
    ///
    /// # Arguments
    /// * `views` - The topology views for this chunk
    /// * `required_views` - Number of views required (typically 3 - acceptance_count)
    fn generate_valid_combinations(
        views: &[&TopologyView],
        required_views: usize,
    ) -> Vec<(Vec<usize>, HashSet<PeerId>)> {
        let mut valid = Vec::new();
        let n = views.len();

        // If we need 0 or 1 views, any single view is valid
        if required_views <= 1 {
            for i in 0..n {
                let indices = vec![i];
                let common = Self::intersect_views(views, &indices);
                if !common.is_empty() {
                    valid.push((indices, common));
                }
            }
            return valid;
        }

        if n < required_views {
            // Not enough views to form a valid combination - return empty
            // This is expected when most probes fail; consensus cannot be reached
            return valid;
        }

        // Generate all C(n, required_views) combinations
        let indices_vec: Vec<usize> = (0..n).collect();
        Self::generate_combinations(&indices_vec, required_views, &mut |combo| {
            let common = Self::intersect_views(views, combo);
            if common.len() >= MIN_COMMON_MERKLE_CANDIDATES {
                valid.push((combo.to_vec(), common));
            }
        });

        valid
    }

    /// Helper to generate all combinations of size k from items
    fn generate_combinations<F>(items: &[usize], k: usize, callback: &mut F)
    where
        F: FnMut(&[usize]),
    {
        let mut combo = vec![0; k];
        Self::generate_combinations_recursive(items, k, 0, 0, &mut combo, callback);
    }

    fn generate_combinations_recursive<F>(
        items: &[usize],
        k: usize,
        start: usize,
        depth: usize,
        combo: &mut [usize],
        callback: &mut F,
    ) where
        F: FnMut(&[usize]),
    {
        if depth == k {
            callback(combo);
            return;
        }

        for i in start..items.len() {
            combo[depth] = items[i];
            Self::generate_combinations_recursive(items, k, i + 1, depth + 1, combo, callback);
        }
    }

    /// Compute intersection of merkle candidates for selected view indices
    fn intersect_views(views: &[&TopologyView], indices: &[usize]) -> HashSet<PeerId> {
        if indices.is_empty() {
            return HashSet::new();
        }

        let mut result: HashSet<PeerId> = views
            .get(indices[0])
            .map(|v| v.merkle_candidates.iter().copied().collect())
            .unwrap_or_default();

        for &idx in &indices[1..] {
            if let Some(view) = views.get(idx) {
                let candidates: HashSet<PeerId> = view.merkle_candidates.iter().copied().collect();
                result = result.intersection(&candidates).copied().collect();
            }
        }

        result
    }

    /// Find a valid selection of combinations across all groups.
    /// Returns the global common candidates and the selected combination index per chunk.
    fn find_cross_group_consensus(
        chunk_addrs: &[XorName],
        valid_combinations: &HashMap<XorName, Vec<(Vec<usize>, HashSet<PeerId>)>>,
    ) -> Result<(HashSet<PeerId>, Vec<(XorName, usize)>), ConsensusError> {
        const MIN_COMMON: usize = 8;

        if chunk_addrs.is_empty() {
            return Err(ConsensusError::InsufficientResponses {
                got: 0,
                needed: 1,
                context: "find_cross_group_consensus: no chunk groups".to_string(),
            });
        }

        // Handle single chunk case
        if chunk_addrs.len() == 1 {
            let addr = chunk_addrs[0];
            if let Some(combos) = valid_combinations.get(&addr) {
                if let Some((_, common)) = combos.first() {
                    return Ok((common.clone(), vec![(addr, 0)]));
                }
            }
            return Err(ConsensusError::NoConsensus {
                found: 0,
                needed: MIN_COMMON,
            });
        }

        // Use backtracking to find valid cross-group selection
        let mut selected: Vec<(XorName, usize)> = Vec::with_capacity(chunk_addrs.len());
        let mut current_common: Option<HashSet<PeerId>> = None;

        if Self::backtrack_find_consensus(
            chunk_addrs,
            valid_combinations,
            0,
            &mut selected,
            &mut current_common,
            MIN_COMMON,
        ) {
            Ok((current_common.unwrap_or_default(), selected))
        } else {
            // Fallback: use first valid combination from each group, accept smaller intersection
            let mut fallback_common: Option<HashSet<PeerId>> = None;
            let mut fallback_selected = Vec::new();

            for addr in chunk_addrs {
                if let Some(combos) = valid_combinations.get(addr) {
                    if let Some((_, common)) = combos.first() {
                        fallback_selected.push((*addr, 0));
                        fallback_common = Some(match fallback_common {
                            Some(existing) => existing.intersection(common).copied().collect(),
                            None => common.clone(),
                        });
                    }
                }
            }

            if let Some(common) = fallback_common {
                if !common.is_empty() {
                    warn!(
                        "Using fallback consensus with {} common candidates (less than ideal {})",
                        common.len(),
                        MIN_COMMON
                    );
                    return Ok((common, fallback_selected));
                }
            }

            Err(ConsensusError::NoConsensus {
                found: 0,
                needed: MIN_COMMON,
            })
        }
    }

    /// Backtracking algorithm to find valid combination selection across groups
    fn backtrack_find_consensus(
        chunk_addrs: &[XorName],
        valid_combinations: &HashMap<XorName, Vec<(Vec<usize>, HashSet<PeerId>)>>,
        depth: usize,
        selected: &mut Vec<(XorName, usize)>,
        current_common: &mut Option<HashSet<PeerId>>,
        min_common: usize,
    ) -> bool {
        if depth >= chunk_addrs.len() {
            // All groups processed, check if we have enough common candidates
            return current_common
                .as_ref()
                .is_some_and(|c| c.len() >= min_common);
        }

        let addr = chunk_addrs[depth];
        let combos = match valid_combinations.get(&addr) {
            Some(c) if !c.is_empty() => c,
            _ => {
                // No valid combinations for this chunk, skip it
                return Self::backtrack_find_consensus(
                    chunk_addrs,
                    valid_combinations,
                    depth + 1,
                    selected,
                    current_common,
                    min_common,
                );
            }
        };

        for (combo_idx, (_, common)) in combos.iter().enumerate() {
            // Compute new intersection
            let new_common = match current_common {
                Some(existing) => existing.intersection(common).copied().collect(),
                None => common.clone(),
            };

            // Prune: if intersection already too small, skip this branch
            if new_common.len() < min_common && depth < chunk_addrs.len() - 1 {
                continue;
            }

            // Try this combination
            selected.push((addr, combo_idx));
            let old_common = current_common.take();
            *current_common = Some(new_common);

            if Self::backtrack_find_consensus(
                chunk_addrs,
                valid_combinations,
                depth + 1,
                selected,
                current_common,
                min_common,
            ) {
                return true;
            }

            // Backtrack
            selected.pop();
            *current_common = old_common;
        }

        false
    }

    /// Pad candidates with most frequent peers from selected combinations until we reach 16.
    fn pad_candidates_by_frequency(
        mut candidates: HashSet<PeerId>,
        selected_indices: &[(XorName, usize)],
        valid_combinations: &HashMap<XorName, Vec<(Vec<usize>, HashSet<PeerId>)>>,
    ) -> Vec<PeerId> {
        // Count frequency of peers across selected combinations
        let mut frequency: HashMap<PeerId, usize> = HashMap::new();

        for (addr, combo_idx) in selected_indices {
            if let Some(combos) = valid_combinations.get(addr) {
                if let Some((_, common)) = combos.get(*combo_idx) {
                    for peer in common {
                        *frequency.entry(*peer).or_insert(0) += 1;
                    }
                }
            }
        }

        // Sort by frequency (descending), then add to candidates
        let mut freq_vec: Vec<(PeerId, usize)> = frequency.into_iter().collect();
        freq_vec.sort_by(|a, b| b.1.cmp(&a.1));

        for (peer, _) in freq_vec {
            if candidates.len() >= CANDIDATES_PER_POOL {
                break;
            }
            candidates.insert(peer);
        }

        candidates.into_iter().take(CANDIDATES_PER_POOL).collect()
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
                context: format!(
                    "create_probe_candidates: not enough successful quote responses for midpoint {:?}",
                    midpoint_address
                ),
            });
        }

        candidates
            .try_into()
            .map_err(|v: Vec<_>| ConsensusError::InsufficientResponses {
                got: v.len(),
                needed: CANDIDATES_PER_POOL,
                context: format!(
                    "create_probe_candidates: try_into failed for midpoint {:?}",
                    midpoint_address
                ),
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
    /// * (MerklePaymentCandidatePool, storing_nodes, accepted_chunks, probe_cost) - Pool with consensus candidates, storing nodes per chunk, chunks accepted during probing, and probe cost
    pub(crate) async fn build_consensus_candidate_pool(
        &self,
        midpoint_proof: MidpointProof,
        midpoint_index: usize,
        chunks: &[Chunk],
        depth: u8,
        data_type: DataTypes,
        data_size: usize,
        wallet: &EvmWallet,
    ) -> Result<
        (
            MerklePaymentCandidatePool,
            HashMap<XorName, Vec<PeerId>>,
            HashSet<XorName>,
            AttoTokens,
        ),
        ConsensusError,
    > {
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
            return Err(ConsensusError::InsufficientResponses {
                got: 0,
                needed: 1,
                context: format!(
                    "build_consensus_candidate_pool: no chunks map to midpoint index {} ({:?})",
                    midpoint_index, midpoint_address
                ),
            });
        }

        info!(
            "Midpoint {midpoint_index} has {} chunks to probe storing nodes from",
            chunks_for_midpoint.len()
        );

        // Step 1: Probe storing nodes from ALL chunks that map to this midpoint
        // Collect topology views from all storing nodes (this pays for probing)
        let (topology_views, accepted_chunks, acceptance_counts, probe_cost) = self
            .probe_all_storing_nodes_for_topology(
                &chunks_for_midpoint,
                &midpoint_proof,
                data_type,
                data_size,
                wallet,
            )
            .await?;

        // If all chunks were accepted during probing, we can skip consensus building
        if !accepted_chunks.is_empty() {
            info!(
                "Midpoint {midpoint_index}: {} chunks accepted during probing, will be skipped in upload phase",
                accepted_chunks.len()
            );
        }

        // Step 2: Filter out topology views for chunks that were already accepted by enough nodes (>= 3)
        // Chunks with 1-2 acceptances still need consensus to reach the quorum of 3
        let original_view_count = topology_views.len();
        let filtered_topology_views: Vec<TopologyView> = topology_views
            .into_iter()
            .filter(|view| {
                if accepted_chunks.contains(&view.chunk_address) {
                    let count = acceptance_counts.get(&view.chunk_address).copied().unwrap_or(0);
                    debug!(
                        "Filtering out topology view for chunk {:?} - already accepted by {count} nodes (>= {MIN_NODES_ACCEPT_CHUNK})",
                        view.chunk_address
                    );
                    false
                } else {
                    true
                }
            })
            .collect();

        let filtered_count = filtered_topology_views.len();
        if filtered_count < original_view_count {
            info!(
                "Filtered topology views: {} remaining after removing {} views for fully-replicated chunks",
                filtered_count,
                original_view_count - filtered_count
            );
        }

        // Build a filtered acceptance_counts that only includes chunks with < 3 acceptances
        let partial_acceptance_counts: HashMap<XorName, usize> = acceptance_counts
            .iter()
            .filter(|&(_, &count)| count < MIN_NODES_ACCEPT_CHUNK)
            .map(|(&k, &v)| (k, v))
            .collect();

        // Step 3: Build consensus from filtered topology views (skip if we have no views)
        let (consensus_candidates, storing_nodes) = if filtered_topology_views.is_empty() {
            // All chunks were accepted, no topology views to build consensus from
            // Return empty consensus data - we won't need to upload anything
            info!(
                "No topology views remaining after filtering - all chunks were accepted during probing"
            );
            #[cfg(feature = "loud")]
            println!(
                "✓ Midpoint {midpoint_index}: All {} chunks already replicated during probing",
                accepted_chunks.len()
            );
            (Vec::new(), HashMap::new())
        } else {
            let result = self
                .build_consensus_candidates(&filtered_topology_views, &partial_acceptance_counts)?;
            #[cfg(feature = "loud")]
            {
                let chunks_with_partial = partial_acceptance_counts.len();
                if chunks_with_partial > 0 {
                    println!(
                        "✓ Midpoint {midpoint_index}: Consensus found for {} chunks ({} already replicated, {} partially replicated)",
                        result.1.len(),
                        accepted_chunks.len(),
                        chunks_with_partial
                    );
                } else {
                    println!(
                        "✓ Midpoint {midpoint_index}: Consensus found for {} chunks ({} already replicated)",
                        result.1.len(),
                        accepted_chunks.len()
                    );
                }
            }
            result
        };

        // Step 4: Get actual signed quotes from consensus candidates
        // We need consensus candidates even if some chunks were accepted during probing,
        // because the merkle tree payment requires valid candidate pools
        let candidate_nodes = if filtered_topology_views.is_empty() {
            // All chunks were accepted during probing - we still need to build a minimal candidate pool
            // Use a simple non-consensus approach to get candidates for the midpoint
            warn!(
                "All chunks accepted during probing, falling back to non-consensus candidate selection"
            );
            let midpoint_network_addr =
                NetworkAddress::ChunkAddress(ChunkAddress::new(midpoint_address));
            let closest = self
                .network
                .get_closest_n_peers(
                    midpoint_network_addr.clone(),
                    std::num::NonZeroUsize::new(CANDIDATES_PER_POOL)
                        .expect("CANDIDATES_PER_POOL is non-zero"),
                )
                .await?;
            self.create_probe_candidates(
                &closest,
                midpoint_address,
                data_type,
                data_size,
                merkle_payment_timestamp,
            )
            .await?
        } else {
            self.get_quotes_from_consensus_candidates(
                &consensus_candidates,
                midpoint_address,
                data_type,
                data_size,
                merkle_payment_timestamp,
            )
            .await?
        };

        // Step 5: Build the pool
        let pool = MerklePaymentCandidatePool {
            midpoint_proof,
            candidate_nodes,
        };

        info!(
            "Built consensus candidate pool for midpoint {midpoint_index} with {} candidates, {} accepted chunks, probe cost: {probe_cost}",
            CANDIDATES_PER_POOL,
            accepted_chunks.len()
        );

        Ok((pool, storing_nodes, accepted_chunks, probe_cost))
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
    /// * (pools, storing_nodes, accepted_chunks, total_probe_cost) - Vector of pools, storing nodes per chunk address, chunks accepted during probing, and total cost for probing
    pub(crate) async fn build_consensus_candidate_pools(
        &self,
        midpoint_proofs: Vec<MidpointProof>,
        chunks: &[Chunk],
        depth: u8,
        data_type: DataTypes,
        data_size: usize,
        wallet: &EvmWallet,
    ) -> Result<
        (
            Vec<MerklePaymentCandidatePool>,
            HashMap<XorName, Vec<PeerId>>,
            HashSet<XorName>,
            AttoTokens,
        ),
        ConsensusError,
    > {
        info!(
            "Building consensus candidate pools for {} midpoints from {} chunks",
            midpoint_proofs.len(),
            chunks.len()
        );

        // Build pools sequentially to avoid wallet contention
        // Each probe payment requires the wallet lock
        let mut pools = Vec::with_capacity(midpoint_proofs.len());
        let mut all_storing_nodes: HashMap<XorName, Vec<PeerId>> = HashMap::new();
        let mut all_accepted_chunks: HashSet<XorName> = HashSet::new();
        let mut total_probe_cost = AttoTokens::zero();

        for (midpoint_index, proof) in midpoint_proofs.into_iter().enumerate() {
            let (pool, storing_nodes, accepted_chunks, probe_cost) = self
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
            all_storing_nodes.extend(storing_nodes);
            all_accepted_chunks.extend(accepted_chunks);
            total_probe_cost = AttoTokens::from_atto(
                total_probe_cost
                    .as_atto()
                    .saturating_add(probe_cost.as_atto()),
            );
        }

        info!(
            "Built {} consensus candidate pools with {} chunks accepted during probing, total probe cost: {total_probe_cost}",
            pools.len(),
            all_accepted_chunks.len()
        );

        #[cfg(feature = "loud")]
        {
            let chunks_needing_consensus = all_storing_nodes.len();
            let chunks_already_replicated = all_accepted_chunks.len();
            let total_chunks = chunks_needing_consensus + chunks_already_replicated;
            println!(
                "📊 Consensus Summary: {}/{} chunks need upload, {} already replicated",
                chunks_needing_consensus, total_chunks, chunks_already_replicated
            );
        }

        Ok((
            pools,
            all_storing_nodes,
            all_accepted_chunks,
            total_probe_cost,
        ))
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
    fn test_intersect_views() {
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();
        let peer4 = PeerId::random();

        let chunk_addr = XorName::random(&mut rand::thread_rng());
        let views = vec![
            TopologyView {
                chunk_address: chunk_addr,
                from_node: PeerId::random(),
                merkle_candidates: vec![peer1, peer2, peer3],
            },
            TopologyView {
                chunk_address: chunk_addr,
                from_node: PeerId::random(),
                merkle_candidates: vec![peer1, peer2, peer3, peer4],
            },
            TopologyView {
                chunk_address: chunk_addr,
                from_node: PeerId::random(),
                merkle_candidates: vec![peer1, peer2, peer3],
            },
        ];

        let view_refs: Vec<&TopologyView> = views.iter().collect();
        let intersection = Client::intersect_views(&view_refs, &[0, 1, 2]);

        // All three share peer1, peer2, peer3
        assert!(intersection.contains(&peer1));
        assert!(intersection.contains(&peer2));
        assert!(intersection.contains(&peer3));
        // peer4 only in view 1
        assert!(!intersection.contains(&peer4));
        assert_eq!(intersection.len(), 3);
    }

    #[test]
    fn test_generate_valid_combinations() {
        // Create 8 common peers (minimum required)
        let common_peers: Vec<PeerId> = (0..8).map(|_| PeerId::random()).collect();
        let extra_peer = PeerId::random();

        let chunk_addr = XorName::random(&mut rand::thread_rng());

        // All views share the 8 common peers
        let views = vec![
            TopologyView {
                chunk_address: chunk_addr,
                from_node: PeerId::random(),
                merkle_candidates: common_peers.clone(),
            },
            TopologyView {
                chunk_address: chunk_addr,
                from_node: PeerId::random(),
                merkle_candidates: common_peers.clone(),
            },
            TopologyView {
                chunk_address: chunk_addr,
                from_node: PeerId::random(),
                merkle_candidates: [common_peers.clone(), vec![extra_peer]].concat(),
            },
        ];

        let view_refs: Vec<&TopologyView> = views.iter().collect();
        let combinations = Client::generate_valid_combinations(&view_refs, 3);

        // Should have exactly 1 combination (C(3,3) = 1)
        assert_eq!(combinations.len(), 1);

        // The combination should have exactly 8 common candidates
        let (indices, common) = &combinations[0];
        assert_eq!(indices.len(), 3);
        assert_eq!(common.len(), 8);
        for peer in &common_peers {
            assert!(common.contains(peer));
        }
    }

    #[test]
    fn test_generate_valid_combinations_insufficient_common() {
        // Create only 5 common peers (less than 8 required)
        let common_peers: Vec<PeerId> = (0..5).map(|_| PeerId::random()).collect();
        let extra1 = PeerId::random();
        let extra2 = PeerId::random();
        let extra3 = PeerId::random();

        let chunk_addr = XorName::random(&mut rand::thread_rng());

        // Views don't share enough peers
        let views = vec![
            TopologyView {
                chunk_address: chunk_addr,
                from_node: PeerId::random(),
                merkle_candidates: [common_peers.clone(), vec![extra1]].concat(),
            },
            TopologyView {
                chunk_address: chunk_addr,
                from_node: PeerId::random(),
                merkle_candidates: [common_peers.clone(), vec![extra2]].concat(),
            },
            TopologyView {
                chunk_address: chunk_addr,
                from_node: PeerId::random(),
                merkle_candidates: [common_peers.clone(), vec![extra3]].concat(),
            },
        ];

        let view_refs: Vec<&TopologyView> = views.iter().collect();
        let combinations = Client::generate_valid_combinations(&view_refs, 3);

        // Should have no valid combinations (only 5 common, need 8)
        assert!(combinations.is_empty());
    }

    #[test]
    fn test_cross_group_consensus_single_chunk() {
        let common_peers: Vec<PeerId> = (0..10).map(|_| PeerId::random()).collect();
        let chunk_addr = XorName::random(&mut rand::thread_rng());

        let views = vec![
            TopologyView {
                chunk_address: chunk_addr,
                from_node: PeerId::random(),
                merkle_candidates: common_peers.clone(),
            },
            TopologyView {
                chunk_address: chunk_addr,
                from_node: PeerId::random(),
                merkle_candidates: common_peers.clone(),
            },
            TopologyView {
                chunk_address: chunk_addr,
                from_node: PeerId::random(),
                merkle_candidates: common_peers.clone(),
            },
        ];

        let view_refs: Vec<&TopologyView> = views.iter().collect();
        let combinations = Client::generate_valid_combinations(&view_refs, 3);

        let mut valid_combinations: HashMap<XorName, Vec<(Vec<usize>, HashSet<PeerId>)>> =
            HashMap::new();
        valid_combinations.insert(chunk_addr, combinations);

        let result = Client::find_cross_group_consensus(&[chunk_addr], &valid_combinations);
        assert!(result.is_ok());

        let (common, selected) = result.unwrap();
        assert_eq!(common.len(), 10);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].0, chunk_addr);
    }

    #[test]
    fn test_cross_group_consensus_multiple_chunks() {
        // Create peers that are common across all chunks
        let global_common: Vec<PeerId> = (0..10).map(|_| PeerId::random()).collect();

        let chunk1 = XorName::random(&mut rand::thread_rng());
        let chunk2 = XorName::random(&mut rand::thread_rng());

        // Both chunks have views with the same common peers
        let views1: Vec<TopologyView> = (0..3)
            .map(|_| TopologyView {
                chunk_address: chunk1,
                from_node: PeerId::random(),
                merkle_candidates: global_common.clone(),
            })
            .collect();

        let views2: Vec<TopologyView> = (0..3)
            .map(|_| TopologyView {
                chunk_address: chunk2,
                from_node: PeerId::random(),
                merkle_candidates: global_common.clone(),
            })
            .collect();

        let view_refs1: Vec<&TopologyView> = views1.iter().collect();
        let view_refs2: Vec<&TopologyView> = views2.iter().collect();

        let mut valid_combinations: HashMap<XorName, Vec<(Vec<usize>, HashSet<PeerId>)>> =
            HashMap::new();
        valid_combinations.insert(chunk1, Client::generate_valid_combinations(&view_refs1, 3));
        valid_combinations.insert(chunk2, Client::generate_valid_combinations(&view_refs2, 3));

        let result = Client::find_cross_group_consensus(&[chunk1, chunk2], &valid_combinations);
        assert!(result.is_ok());

        let (common, selected) = result.unwrap();
        assert_eq!(common.len(), 10);
        assert_eq!(selected.len(), 2);
    }
}
