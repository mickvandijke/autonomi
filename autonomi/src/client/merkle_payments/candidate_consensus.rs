// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Merkle candidate consensus module
//!
//! This module implements a network-consensus based approach to selecting merkle payment candidates.
//!
//! ## Key Concepts - TWO SEPARATE GROUPS
//!
//! ```text
//! STORING NODES                          MERKLE CANDIDATES
//! ─────────────                          ─────────────────
//! Closest to: chunk/pointer address      Closest to: midpoint address
//! Role: Store the data                   Role: Receive payment
//! Location: Near data address            Location: Near midpoint (different!)
//! ```
//!
//! These are **completely different nodes** in **different parts of the address space**.
//!
//! ## Merkle Tree Structure
//!
//! ```text
//! Chunk A (leaf) ─┐
//! Chunk B (leaf) ─┼─→ Midpoint M ─→ Merkle Candidates (close to M)
//! Chunk C (leaf) ─┘
//! ```
//!
//! ## Per-Leaf Requirement
//!
//! Each chunk needs 3 storing nodes (close to chunk address).
//! These 3 must have **mutual membership** in their close groups.
//!
//! ## Per-Midpoint Requirement
//!
//! ALL storing nodes from ALL chunks that share midpoint M must agree on merkle candidates.
//! If chunks A, B, C share midpoint M:
//! - A's 3 storing nodes + B's 3 storing nodes + C's 3 storing nodes
//! - = 9 storing nodes total, all must agree on merkle candidates for M
//!
//! ## How Validation Works
//!
//! 1. Client builds merkle tree from chunk addresses → gets midpoint address(es)
//! 2. Client pays merkle candidates (nodes closest to midpoint)
//! 3. Client uploads data to storing nodes (nodes closest to chunk address)
//! 4. **Storing nodes validate**: "Were the correct merkle candidates paid?"
//!    - They do a network lookup for peers closest to the midpoint
//!    - They check if >50% of paid nodes match their view
//!
//! ## The Problem
//!
//! The client needs to pay merkle candidates that ALL storing nodes will accept. But:
//! 1. Different storing nodes may have different views of who is closest to the midpoint
//! 2. `GetClosestPeers` only returns results from a node's **local routing table**
//! 3. Merkle validation uses an **actual network lookup** (`get_closest_peers_with_retries`)
//! 4. These can give different results!
//!
//! ## The Solution
//!
//! There is no direct API to get a node's network-lookup-based view of closest peers.
//! The workaround is to trigger the `TopologyVerificationFailed` error, which contains
//! `node_peers` - the result of the storing node's network lookup for who it thinks
//! the merkle candidates should be.
//!
//! ### Approach
//!
//! 1. Query ALL closest nodes to each chunk for BOTH:
//!    - Their close group view (for mutual membership check)
//!    - Their merkle candidate view (for consensus check)
//! 2. Find all valid triplets (mutual membership) per chunk
//! 3. Search for a combination of triplets (one per chunk) where ALL storing nodes
//!    agree on at least CANDIDATES_PER_POOL merkle candidates
//! 4. If initial payment was wrong, collect TopologyVerificationFailed errors and retry

use crate::Client;
use crate::networking::NetworkError;
use ant_evm::merkle_payments::CANDIDATES_PER_POOL;
use ant_protocol::NetworkAddress;
use ant_protocol::storage::ChunkAddress;
use libp2p::{Multiaddr, PeerId};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, trace, warn};
use xor_name::XorName;

/// Number of storing nodes to query per chunk when looking for mutual triplets
const STORING_NODES_TO_QUERY_PER_CHUNK: usize = 20;

/// Minimum overlap required between storing node views to consider them in consensus
const MIN_OVERLAP_THRESHOLD: usize = CANDIDATES_PER_POOL;

/// A triplet of storing nodes for a single chunk that have mutual membership.
///
/// These 3 nodes are all close to the chunk address and all have each other
/// in their close groups.
#[derive(Debug, Clone)]
pub struct ChunkStoringTriplet {
    /// The chunk address these storing nodes are responsible for
    pub chunk_address: XorName,
    /// Three storing nodes with mutual membership
    pub storing_nodes: [PeerId; 3],
    /// The storing nodes' addresses for connection
    pub storing_node_addrs: HashMap<PeerId, Vec<Multiaddr>>,
}

/// A storing node's view of both its close group and merkle candidates.
#[derive(Debug, Clone)]
pub struct StoringNodeMerkleView {
    /// The storing node that provided this view
    pub storing_node_id: PeerId,
    /// The storing node's addresses for connection
    pub storing_node_addrs: Vec<Multiaddr>,
    /// The chunk this storing node is responsible for
    pub chunk_address: XorName,
    /// The storing node's view of its close group (other storing nodes near the chunk)
    /// Used to verify mutual membership among storing nodes
    pub close_group_view: Vec<PeerId>,
    /// The storing node's view of who the MERKLE CANDIDATES should be
    /// (nodes closest to the midpoint address - a DIFFERENT set of nodes!)
    pub merkle_candidates_view: Vec<PeerId>,
}

/// Information extracted from a TopologyVerificationFailed error
#[derive(Debug, Clone)]
pub struct TopologyErrorInfo {
    /// The node that rejected the upload
    pub rejecting_node: PeerId,
    /// The midpoint address (target of the reward pool)
    pub target_address: NetworkAddress,
    /// How many paid nodes were in the rejecting node's closest list
    pub valid_count: usize,
    /// Total number of paid nodes
    pub total_paid: usize,
    /// How many closest peers the rejecting node has
    pub closest_count: usize,
    /// The rejecting node's view of closest peers to the midpoint (from network lookup)
    /// THIS IS THE KEY DATA - it's what the node uses for merkle validation
    pub node_peers: Vec<PeerId>,
    /// The peers that were paid (client's view)
    pub paid_peers: Vec<PeerId>,
}

impl TopologyErrorInfo {
    /// Extract topology error info from a NetworkError
    pub fn from_network_error(error: &NetworkError) -> Option<Self> {
        match error {
            NetworkError::TopologyVerificationFailed {
                rejecting_node,
                target_address,
                valid_count,
                total_paid,
                closest_count,
                node_peers,
                paid_peers,
            } => Some(Self {
                rejecting_node: *rejecting_node,
                target_address: target_address.clone(),
                valid_count: *valid_count,
                total_paid: *total_paid,
                closest_count: *closest_count,
                node_peers: node_peers.clone(),
                paid_peers: paid_peers.clone(),
            }),
            _ => None,
        }
    }
}

/// Collection of topology errors for consensus analysis
#[derive(Debug, Clone, Default)]
pub struct TopologyErrorCollection {
    /// Errors indexed by rejecting node
    pub errors: HashMap<PeerId, TopologyErrorInfo>,
}

impl TopologyErrorCollection {
    /// Create a new empty collection
    pub fn new() -> Self {
        Self {
            errors: HashMap::new(),
        }
    }

    /// Add an error to the collection
    pub fn add(&mut self, error: TopologyErrorInfo) {
        self.errors.insert(error.rejecting_node, error);
    }

    /// Add from a NetworkError if it's a topology error
    pub fn add_from_network_error(&mut self, error: &NetworkError) {
        if let Some(info) = TopologyErrorInfo::from_network_error(error) {
            self.add(info);
        }
    }

    /// Get the number of collected errors
    pub fn len(&self) -> usize {
        self.errors.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Result of consensus for a single midpoint.
///
/// Contains storing node triplets for each chunk and the consensus merkle candidates.
#[derive(Debug, Clone)]
pub struct MidpointConsensus {
    /// The midpoint address
    pub midpoint_address: XorName,
    /// Storing node triplets for each chunk that maps to this midpoint
    pub chunk_triplets: Vec<ChunkStoringTriplet>,
    /// All storing nodes across all chunks (flattened from chunk_triplets)
    pub all_storing_nodes: Vec<PeerId>,
    /// The consensus merkle candidates - agreed upon by all storing nodes
    pub consensus_merkle_candidates: Vec<PeerId>,
}

/// Format candidates per storing node for error display
fn format_candidates_per_node(candidates: &HashMap<PeerId, Vec<PeerId>>) -> String {
    let mut lines = Vec::new();
    for (storing_node, candidates) in candidates {
        let candidate_strs: Vec<String> = candidates.iter().map(|p| format!("{p}")).collect();
        lines.push(format!("  {storing_node}: [{}]", candidate_strs.join(", ")));
    }
    lines.join("\n")
}

/// Errors that can occur during candidate consensus
#[derive(Debug, thiserror::Error)]
pub enum CandidateConsensusError {
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),
    #[error(
        "No mutual triplet found for chunk {chunk_address:?}: queried {queried} peers but couldn't find 3 with mutual close group membership"
    )]
    NoMutualTripletForChunk {
        chunk_address: XorName,
        queried: usize,
    },
    #[error("Insufficient candidate overlap across storing nodes: only {overlap} common candidates, need at least {required}\nCandidates per storing node:\n{}", format_candidates_per_node(.candidates_per_node))]
    InsufficientOverlap {
        overlap: usize,
        required: usize,
        candidates_per_node: HashMap<PeerId, Vec<PeerId>>,
    },
    #[error("Not enough storing node views: got {got}, needed at least {needed}")]
    InsufficientStoringNodeViews { got: usize, needed: usize },
    #[error("Not enough topology errors: got {got}, needed at least 3")]
    InsufficientTopologyErrors { got: usize },
}

/// A valid triplet with indices into the chunk's node list
#[derive(Debug, Clone)]
struct ValidTriplet {
    /// Indices into the chunk's views list
    indices: [usize; 3],
    /// The three peer IDs
    peer_ids: [PeerId; 3],
}

impl Client {
    /// Query all closest nodes to a chunk for their close group AND merkle candidate views.
    ///
    /// This gathers all the data needed to find valid triplets and check consensus.
    ///
    /// # Arguments
    /// * `chunk_address` - The chunk address to query nodes for
    /// * `midpoint_address` - The midpoint address to query merkle candidates for
    ///
    /// # Returns
    /// * Vector of `StoringNodeMerkleView` with both close group and merkle candidate views populated
    pub async fn query_all_node_views_for_chunk(
        &self,
        chunk_address: XorName,
        midpoint_address: XorName,
    ) -> Result<Vec<StoringNodeMerkleView>, CandidateConsensusError> {
        let chunk_network_addr = NetworkAddress::ChunkAddress(ChunkAddress::new(chunk_address));
        let midpoint_network_addr =
            NetworkAddress::ChunkAddress(ChunkAddress::new(midpoint_address));

        // Get candidate storing nodes close to the chunk address
        let candidate_nodes = self
            .network
            .get_closest_peers(
                chunk_network_addr.clone(),
                Some(STORING_NODES_TO_QUERY_PER_CHUNK),
            )
            .await?;

        debug!(
            "Got {} candidate storing nodes for chunk {:?}",
            candidate_nodes.len(),
            chunk_address
        );

        // Query each candidate for BOTH their close group view AND merkle candidate view
        let mut query_tasks = Vec::new();

        for peer_info in candidate_nodes.iter() {
            let network = self.network.clone();
            let chunk_addr = chunk_network_addr.clone();
            let midpoint_addr = midpoint_network_addr.clone();
            let peer = peer_info.clone();

            query_tasks.push(async move {
                // Query close group (nodes near this chunk)
                let close_group_result = network
                    .get_closest_peers_from_peer(
                        chunk_addr,
                        peer.clone(),
                        Some(STORING_NODES_TO_QUERY_PER_CHUNK),
                    )
                    .await;

                // Query merkle candidates (nodes near the midpoint)
                let merkle_candidates_result = network
                    .get_closest_peers_from_peer(
                        midpoint_addr,
                        peer.clone(),
                        Some(CANDIDATES_PER_POOL + 4),
                    )
                    .await;

                (peer, close_group_result, merkle_candidates_result)
            });
        }

        let results = futures::future::join_all(query_tasks).await;

        let mut views: Vec<StoringNodeMerkleView> = Vec::new();

        for (peer_info, close_group_result, merkle_candidates_result) in results {
            let close_group_view: Vec<PeerId> = match close_group_result {
                Ok(list) => list
                    .iter()
                    .filter_map(|(addr, _)| addr.as_peer_id())
                    .collect(),
                Err(e) => {
                    warn!(
                        "Failed to get close group from {:?}: {}",
                        peer_info.peer_id, e
                    );
                    continue;
                }
            };

            let merkle_candidates_view: Vec<PeerId> = match merkle_candidates_result {
                Ok(list) => list
                    .iter()
                    .filter_map(|(addr, _)| addr.as_peer_id())
                    .collect(),
                Err(e) => {
                    warn!(
                        "Failed to get merkle candidates from {:?}: {}",
                        peer_info.peer_id, e
                    );
                    continue;
                }
            };

            trace!(
                "Node {:?}: {} close group peers, {} merkle candidates",
                peer_info.peer_id,
                close_group_view.len(),
                merkle_candidates_view.len()
            );

            views.push(StoringNodeMerkleView {
                storing_node_id: peer_info.peer_id,
                storing_node_addrs: peer_info.addrs.clone(),
                chunk_address,
                close_group_view,
                merkle_candidates_view,
            });
        }

        Ok(views)
    }

    /// Find all valid triplets (with mutual membership) from a list of node views.
    ///
    /// # Arguments
    /// * `views` - The node views to search through
    ///
    /// # Returns
    /// * Vector of valid triplets (indices into the views list)
    fn find_all_valid_triplets(&self, views: &[StoringNodeMerkleView]) -> Vec<ValidTriplet> {
        // Build adjacency map for mutual membership check
        let mut has_in_close_group: HashMap<PeerId, HashSet<PeerId>> = HashMap::new();
        for view in views {
            let close_group_set: HashSet<PeerId> = view.close_group_view.iter().cloned().collect();
            has_in_close_group.insert(view.storing_node_id, close_group_set);
        }

        let mut valid_triplets = Vec::new();

        for i in 0..views.len() {
            for j in (i + 1)..views.len() {
                for k in (j + 1)..views.len() {
                    let a = views[i].storing_node_id;
                    let b = views[j].storing_node_id;
                    let c = views[k].storing_node_id;

                    let a_close = has_in_close_group.get(&a).cloned().unwrap_or_default();
                    let b_close = has_in_close_group.get(&b).cloned().unwrap_or_default();
                    let c_close = has_in_close_group.get(&c).cloned().unwrap_or_default();

                    let a_has_bc = a_close.contains(&b) && a_close.contains(&c);
                    let b_has_ac = b_close.contains(&a) && b_close.contains(&c);
                    let c_has_ab = c_close.contains(&a) && c_close.contains(&b);

                    if a_has_bc && b_has_ac && c_has_ab {
                        valid_triplets.push(ValidTriplet {
                            indices: [i, j, k],
                            peer_ids: [a, b, c],
                        });
                    }
                }
            }
        }

        valid_triplets
    }

    /// Find 3 storing nodes with mutual membership for a single chunk.
    ///
    /// Queries nodes close to the chunk address and finds a triplet where
    /// all 3 have each other in their close groups.
    ///
    /// # Arguments
    /// * `chunk_address` - The chunk address to find storing nodes for
    ///
    /// # Returns
    /// * `ChunkStoringTriplet` containing 3 mutually-connected storing nodes
    #[deprecated(note = "Use query_all_node_views_for_chunk and find_all_valid_triplets instead")]
    pub async fn find_storing_triplet_for_chunk(
        &self,
        chunk_address: XorName,
    ) -> Result<(ChunkStoringTriplet, Vec<StoringNodeMerkleView>), CandidateConsensusError> {
        // This is the old implementation kept for backward compatibility
        let chunk_network_addr = NetworkAddress::ChunkAddress(ChunkAddress::new(chunk_address));

        let candidate_nodes = self
            .network
            .get_closest_peers(
                chunk_network_addr.clone(),
                Some(STORING_NODES_TO_QUERY_PER_CHUNK),
            )
            .await?;

        let mut views: Vec<StoringNodeMerkleView> = Vec::new();
        let mut query_tasks = Vec::new();

        for peer_info in candidate_nodes.iter() {
            let network = self.network.clone();
            let addr = chunk_network_addr.clone();
            let peer = peer_info.clone();

            query_tasks.push(async move {
                let close_group_result = network
                    .get_closest_peers_from_peer(
                        addr,
                        peer.clone(),
                        Some(STORING_NODES_TO_QUERY_PER_CHUNK),
                    )
                    .await;
                (peer, close_group_result)
            });
        }

        let results = futures::future::join_all(query_tasks).await;

        for (peer_info, close_group_result) in results {
            match close_group_result {
                Ok(close_group_list) => {
                    let close_group_view: Vec<PeerId> = close_group_list
                        .iter()
                        .filter_map(|(addr, _)| addr.as_peer_id())
                        .collect();

                    views.push(StoringNodeMerkleView {
                        storing_node_id: peer_info.peer_id,
                        storing_node_addrs: peer_info.addrs.clone(),
                        chunk_address,
                        close_group_view,
                        merkle_candidates_view: vec![],
                    });
                }
                Err(e) => {
                    warn!(
                        "Failed to get close group from {:?}: {}",
                        peer_info.peer_id, e
                    );
                }
            }
        }

        let valid_triplets = self.find_all_valid_triplets(&views);

        if let Some(triplet) = valid_triplets.first() {
            let [a, b, c] = triplet.peer_ids;
            let view_map: HashMap<PeerId, &StoringNodeMerkleView> =
                views.iter().map(|v| (v.storing_node_id, v)).collect();

            let mut storing_node_addrs = HashMap::new();
            if let Some(v) = view_map.get(&a) {
                storing_node_addrs.insert(a, v.storing_node_addrs.clone());
            }
            if let Some(v) = view_map.get(&b) {
                storing_node_addrs.insert(b, v.storing_node_addrs.clone());
            }
            if let Some(v) = view_map.get(&c) {
                storing_node_addrs.insert(c, v.storing_node_addrs.clone());
            }

            let chunk_triplet = ChunkStoringTriplet {
                chunk_address,
                storing_nodes: [a, b, c],
                storing_node_addrs,
            };

            let triplet_views: Vec<StoringNodeMerkleView> = views
                .into_iter()
                .filter(|v| {
                    v.storing_node_id == a || v.storing_node_id == b || v.storing_node_id == c
                })
                .collect();

            return Ok((chunk_triplet, triplet_views));
        }

        Err(CandidateConsensusError::NoMutualTripletForChunk {
            chunk_address,
            queried: views.len(),
        })
    }

    /// Query storing nodes for their view of merkle candidates at a midpoint.
    ///
    /// # Arguments
    /// * `storing_nodes` - List of (PeerId, addrs) to query
    /// * `midpoint_address` - The midpoint address to query candidates for
    ///
    /// # Returns
    /// * Map from PeerId to their merkle candidates view
    pub async fn query_merkle_candidates_views(
        &self,
        storing_nodes: &[(PeerId, Vec<Multiaddr>)],
        midpoint_address: XorName,
    ) -> Result<HashMap<PeerId, Vec<PeerId>>, CandidateConsensusError> {
        let midpoint_network_addr =
            NetworkAddress::ChunkAddress(ChunkAddress::new(midpoint_address));

        let mut query_tasks = Vec::new();

        for (peer_id, addrs) in storing_nodes {
            let network = self.network.clone();
            let addr = midpoint_network_addr.clone();
            let peer_info = crate::networking::PeerInfo {
                peer_id: *peer_id,
                addrs: addrs.clone(),
            };

            query_tasks.push(async move {
                let result = network
                    .get_closest_peers_from_peer(addr, peer_info.clone(), Some(CANDIDATES_PER_POOL))
                    .await;
                (peer_info.peer_id, result)
            });
        }

        let results = futures::future::join_all(query_tasks).await;

        let mut merkle_views: HashMap<PeerId, Vec<PeerId>> = HashMap::new();

        for (peer_id, result) in results {
            match result {
                Ok(candidates_list) => {
                    let candidates: Vec<PeerId> = candidates_list
                        .iter()
                        .filter_map(|(addr, _)| addr.as_peer_id())
                        .collect();

                    trace!(
                        "Storing node {:?} reports {} merkle candidates",
                        peer_id,
                        candidates.len()
                    );

                    merkle_views.insert(peer_id, candidates);
                }
                Err(e) => {
                    warn!(
                        "Failed to get merkle candidates view from {:?}: {}",
                        peer_id, e
                    );
                }
            }
        }

        Ok(merkle_views)
    }

    /// Find consensus merkle candidates across all storing nodes.
    ///
    /// Takes the intersection of all storing nodes' views of merkle candidates.
    ///
    /// # Arguments
    /// * `merkle_views` - Map from storing node to their merkle candidates view
    ///
    /// # Returns
    /// * Vector of consensus merkle candidates (intersection of all views)
    pub fn find_merkle_candidate_intersection(
        &self,
        merkle_views: &HashMap<PeerId, Vec<PeerId>>,
    ) -> Result<Vec<PeerId>, CandidateConsensusError> {
        if merkle_views.is_empty() {
            return Err(CandidateConsensusError::InsufficientStoringNodeViews {
                got: 0,
                needed: 1,
            });
        }

        let mut views_iter = merkle_views.values();
        let first_view: HashSet<PeerId> = views_iter
            .next()
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default();

        let intersection: HashSet<PeerId> = views_iter.fold(first_view, |acc, view| {
            let view_set: HashSet<PeerId> = view.iter().cloned().collect();
            acc.intersection(&view_set).cloned().collect()
        });

        if intersection.len() < MIN_OVERLAP_THRESHOLD {
            return Err(CandidateConsensusError::InsufficientOverlap {
                overlap: intersection.len(),
                required: MIN_OVERLAP_THRESHOLD,
                candidates_per_node: merkle_views.clone(),
            });
        }

        Ok(intersection.into_iter().collect())
    }

    /// Get merkle candidates consensus for a set of chunks sharing a midpoint.
    ///
    /// This is the main entry point for the consensus algorithm:
    /// 1. Query ALL closest nodes to each chunk for their merkle candidate views (upfront)
    /// 2. Find all valid triplets (mutual membership) per chunk
    /// 3. Search for a combination of triplets where ALL storing nodes agree on CANDIDATES_PER_POOL merkle candidates
    ///
    /// **WARNING**: This uses `GetClosestPeers` which returns results from nodes' local routing
    /// tables. This may give different results than the actual network lookup that nodes use
    /// for merkle payment validation. For accurate results, use `find_consensus_from_topology_errors`
    /// with collected `TopologyVerificationFailed` errors.
    ///
    /// # Arguments
    /// * `chunk_addresses` - Chunk addresses that map to the same midpoint
    /// * `midpoint_address` - The merkle tree midpoint address
    ///
    /// # Returns
    /// * `MidpointConsensus` containing triplets for each chunk and consensus merkle candidates
    pub async fn get_midpoint_consensus(
        &self,
        chunk_addresses: Vec<XorName>,
        midpoint_address: XorName,
    ) -> Result<MidpointConsensus, CandidateConsensusError> {
        info!(
            "Getting midpoint consensus: {} chunks → midpoint {:?}",
            chunk_addresses.len(),
            midpoint_address
        );

        // Step 1: Query ALL closest nodes to each chunk for their views (upfront)
        let mut chunk_views: Vec<(XorName, Vec<StoringNodeMerkleView>)> = Vec::new();
        let mut chunk_valid_triplets: Vec<(XorName, Vec<ValidTriplet>)> = Vec::new();

        for chunk_addr in &chunk_addresses {
            let views = self
                .query_all_node_views_for_chunk(*chunk_addr, midpoint_address)
                .await?;

            debug!(
                "Chunk {:?}: got {} node views with merkle candidate data",
                chunk_addr,
                views.len()
            );

            let valid_triplets = self.find_all_valid_triplets(&views);

            if valid_triplets.is_empty() {
                return Err(CandidateConsensusError::NoMutualTripletForChunk {
                    chunk_address: *chunk_addr,
                    queried: views.len(),
                });
            }

            debug!(
                "Chunk {:?}: found {} valid triplets with mutual membership",
                chunk_addr,
                valid_triplets.len()
            );

            chunk_views.push((*chunk_addr, views));
            chunk_valid_triplets.push((*chunk_addr, valid_triplets));
        }

        // Step 2: Find a combination of triplets where all agree on CANDIDATES_PER_POOL merkle candidates
        // Use recursive search to find valid combination
        let selected_triplets = self.find_consensus_triplet_combination(
            &chunk_views,
            &chunk_valid_triplets,
            0,
            Vec::new(),
        )?;

        // Step 3: Build the result
        let mut chunk_triplets: Vec<ChunkStoringTriplet> = Vec::new();
        let mut all_storing_nodes: Vec<PeerId> = Vec::new();

        for (chunk_idx, triplet_idx) in selected_triplets.iter().enumerate() {
            let (chunk_addr, views) = &chunk_views[chunk_idx];
            let (_, valid_triplets) = &chunk_valid_triplets[chunk_idx];
            let triplet = &valid_triplets[*triplet_idx];

            let mut storing_node_addrs = HashMap::new();
            for &idx in &triplet.indices {
                let view = &views[idx];
                storing_node_addrs.insert(view.storing_node_id, view.storing_node_addrs.clone());
                all_storing_nodes.push(view.storing_node_id);
            }

            chunk_triplets.push(ChunkStoringTriplet {
                chunk_address: *chunk_addr,
                storing_nodes: triplet.peer_ids,
                storing_node_addrs,
            });
        }

        // Calculate consensus candidates from selected triplets
        let mut all_merkle_views: HashMap<PeerId, Vec<PeerId>> = HashMap::new();
        for (chunk_idx, triplet_idx) in selected_triplets.iter().enumerate() {
            let (_, views) = &chunk_views[chunk_idx];
            let (_, valid_triplets) = &chunk_valid_triplets[chunk_idx];
            let triplet = &valid_triplets[*triplet_idx];

            for &idx in &triplet.indices {
                let view = &views[idx];
                all_merkle_views.insert(view.storing_node_id, view.merkle_candidates_view.clone());
            }
        }

        let consensus_merkle_candidates =
            self.find_merkle_candidate_intersection(&all_merkle_views)?;

        info!(
            "Midpoint consensus: {} storing nodes agree on {} merkle candidates",
            all_storing_nodes.len(),
            consensus_merkle_candidates.len()
        );

        Ok(MidpointConsensus {
            midpoint_address,
            chunk_triplets,
            all_storing_nodes,
            consensus_merkle_candidates,
        })
    }

    /// Recursively find a combination of triplets (one per chunk) where all agree on enough merkle candidates.
    ///
    /// # Arguments
    /// * `chunk_views` - Views for each chunk
    /// * `chunk_valid_triplets` - Valid triplets for each chunk
    /// * `chunk_idx` - Current chunk index being processed
    /// * `current_selection` - Currently selected triplet indices
    ///
    /// # Returns
    /// * Vector of triplet indices (one per chunk) or error if no valid combination found
    fn find_consensus_triplet_combination(
        &self,
        chunk_views: &[(XorName, Vec<StoringNodeMerkleView>)],
        chunk_valid_triplets: &[(XorName, Vec<ValidTriplet>)],
        chunk_idx: usize,
        current_selection: Vec<usize>,
    ) -> Result<Vec<usize>, CandidateConsensusError> {
        // Base case: all chunks have been assigned a triplet
        if chunk_idx >= chunk_valid_triplets.len() {
            // Check if this combination has enough consensus
            let consensus_size = self.calculate_consensus_size(
                chunk_views,
                chunk_valid_triplets,
                &current_selection,
            );
            if consensus_size >= CANDIDATES_PER_POOL {
                return Ok(current_selection);
            }
            return Err(CandidateConsensusError::InsufficientOverlap {
                overlap: consensus_size,
                required: CANDIDATES_PER_POOL,
                candidates_per_node: self.get_candidates_per_node_from_selection(
                    chunk_views,
                    chunk_valid_triplets,
                    &current_selection,
                ),
            });
        }

        let (chunk_addr, valid_triplets) = &chunk_valid_triplets[chunk_idx];

        // Try each valid triplet for this chunk
        for triplet_idx in 0..valid_triplets.len() {
            let mut new_selection = current_selection.clone();
            new_selection.push(triplet_idx);

            // Early pruning: check if current partial selection already has too little overlap
            let partial_consensus =
                self.calculate_consensus_size(chunk_views, chunk_valid_triplets, &new_selection);
            if partial_consensus < CANDIDATES_PER_POOL {
                trace!(
                    "Pruning: chunk {:?} triplet {} gives only {} overlap",
                    chunk_addr, triplet_idx, partial_consensus
                );
                continue;
            }

            // Recurse to next chunk
            match self.find_consensus_triplet_combination(
                chunk_views,
                chunk_valid_triplets,
                chunk_idx + 1,
                new_selection,
            ) {
                Ok(result) => return Ok(result),
                Err(_) => continue, // Try next triplet
            }
        }

        // No valid combination found with any triplet for this chunk
        // Show ALL queried nodes' candidates for debugging
        Err(CandidateConsensusError::InsufficientOverlap {
            overlap: 0,
            required: CANDIDATES_PER_POOL,
            candidates_per_node: self.get_all_candidates_per_node(chunk_views),
        })
    }

    /// Calculate the consensus size (intersection) for a given selection of triplets.
    fn calculate_consensus_size(
        &self,
        chunk_views: &[(XorName, Vec<StoringNodeMerkleView>)],
        chunk_valid_triplets: &[(XorName, Vec<ValidTriplet>)],
        selection: &[usize],
    ) -> usize {
        if selection.is_empty() {
            return CANDIDATES_PER_POOL + 1; // No selection yet, assume full overlap
        }

        let mut intersection: Option<HashSet<PeerId>> = None;

        for (chunk_idx, &triplet_idx) in selection.iter().enumerate() {
            let (_, views) = &chunk_views[chunk_idx];
            let (_, valid_triplets) = &chunk_valid_triplets[chunk_idx];
            let triplet = &valid_triplets[triplet_idx];

            for &view_idx in &triplet.indices {
                let view = &views[view_idx];
                let view_set: HashSet<PeerId> =
                    view.merkle_candidates_view.iter().cloned().collect();

                intersection = Some(match intersection {
                    None => view_set,
                    Some(acc) => acc.intersection(&view_set).cloned().collect(),
                });
            }
        }

        intersection.map(|s| s.len()).unwrap_or(0)
    }

    /// Extract candidates per storing node from a selection of triplets.
    fn get_candidates_per_node_from_selection(
        &self,
        chunk_views: &[(XorName, Vec<StoringNodeMerkleView>)],
        chunk_valid_triplets: &[(XorName, Vec<ValidTriplet>)],
        selection: &[usize],
    ) -> HashMap<PeerId, Vec<PeerId>> {
        let mut result = HashMap::new();

        for (chunk_idx, &triplet_idx) in selection.iter().enumerate() {
            let (_, views) = &chunk_views[chunk_idx];
            let (_, valid_triplets) = &chunk_valid_triplets[chunk_idx];
            let triplet = &valid_triplets[triplet_idx];

            for &view_idx in &triplet.indices {
                let view = &views[view_idx];
                result.insert(view.storing_node_id, view.merkle_candidates_view.clone());
            }
        }

        result
    }

    /// Extract candidates per storing node from ALL queried nodes (not just those in a selection).
    fn get_all_candidates_per_node(
        &self,
        chunk_views: &[(XorName, Vec<StoringNodeMerkleView>)],
    ) -> HashMap<PeerId, Vec<PeerId>> {
        let mut result = HashMap::new();

        for (_, views) in chunk_views {
            for view in views {
                result.insert(view.storing_node_id, view.merkle_candidates_view.clone());
            }
        }

        result
    }

    /// Find consensus from collected TopologyVerificationFailed errors.
    ///
    /// This is the **preferred method** for getting accurate merkle candidates because
    /// the `node_peers` field in topology errors contains results from actual network
    /// lookups (not just local routing table).
    ///
    /// # Flow
    /// 1. Make initial payment with client-predicted candidates
    /// 2. Try to upload - collect any TopologyVerificationFailed errors
    /// 3. Call this function with collected errors
    /// 4. If consensus differs from initial payment, retry with correct candidates
    ///
    /// # Arguments
    /// * `errors` - Collection of topology errors from failed upload attempts
    ///
    /// # Returns
    /// * Consensus merkle candidates (intersection of all error.node_peers)
    pub fn find_consensus_from_topology_errors(
        &self,
        errors: &TopologyErrorCollection,
    ) -> Result<Vec<PeerId>, CandidateConsensusError> {
        if errors.len() < 3 {
            return Err(CandidateConsensusError::InsufficientTopologyErrors { got: errors.len() });
        }

        info!("Finding consensus from {} topology errors", errors.len());

        // Convert topology errors to merkle views
        // The node_peers field contains the network-lookup-based view
        let merkle_views: HashMap<PeerId, Vec<PeerId>> = errors
            .errors
            .iter()
            .map(|(peer_id, info)| (*peer_id, info.node_peers.clone()))
            .collect();

        // Find intersection across all views
        let consensus = self.find_merkle_candidate_intersection(&merkle_views)?;

        info!(
            "Topology error consensus: {} nodes agree on {} merkle candidates",
            errors.len(),
            consensus.len()
        );

        Ok(consensus)
    }

    // Backward compatibility wrapper - deprecated
    #[deprecated(note = "Use get_midpoint_consensus instead")]
    pub async fn get_merkle_candidates_by_consensus(
        &self,
        chunk_address: XorName,
        midpoint_address: XorName,
    ) -> Result<MidpointConsensus, CandidateConsensusError> {
        self.get_midpoint_consensus(vec![chunk_address], midpoint_address)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer_id() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_intersection_logic() {
        let a: HashSet<u32> = [1, 2, 3, 4, 5].into_iter().collect();
        let b: HashSet<u32> = [2, 3, 4, 5, 6].into_iter().collect();
        let c: HashSet<u32> = [3, 4, 5, 6, 7].into_iter().collect();

        let intersection: HashSet<u32> = a
            .intersection(&b)
            .cloned()
            .collect::<HashSet<_>>()
            .intersection(&c)
            .cloned()
            .collect();

        assert_eq!(intersection, [3, 4, 5].into_iter().collect());
    }

    #[test]
    fn test_merkle_view_intersection() {
        let p1 = make_peer_id();
        let p2 = make_peer_id();
        let p3 = make_peer_id();

        // Common candidates
        let common1 = make_peer_id();
        let common2 = make_peer_id();
        let common3 = make_peer_id();
        let common4 = make_peer_id();
        let common5 = make_peer_id();
        let common6 = make_peer_id();
        let common7 = make_peer_id();
        let common8 = make_peer_id();
        let common9 = make_peer_id();
        let common10 = make_peer_id();

        // Extra candidates only some nodes see
        let extra1 = make_peer_id();
        let extra2 = make_peer_id();

        let mut merkle_views: HashMap<PeerId, Vec<PeerId>> = HashMap::new();
        merkle_views.insert(
            p1,
            vec![
                common1, common2, common3, common4, common5, common6, common7, common8, common9,
                common10, extra1,
            ],
        );
        merkle_views.insert(
            p2,
            vec![
                common1, common2, common3, common4, common5, common6, common7, common8, common9,
                common10, extra2,
            ],
        );
        merkle_views.insert(
            p3,
            vec![
                common1, common2, common3, common4, common5, common6, common7, common8, common9,
                common10,
            ],
        );

        // Find intersection manually
        let v1: HashSet<PeerId> = merkle_views.get(&p1).unwrap().iter().cloned().collect();
        let v2: HashSet<PeerId> = merkle_views.get(&p2).unwrap().iter().cloned().collect();
        let v3: HashSet<PeerId> = merkle_views.get(&p3).unwrap().iter().cloned().collect();

        let intersection: HashSet<PeerId> = v1
            .intersection(&v2)
            .cloned()
            .collect::<HashSet<_>>()
            .intersection(&v3)
            .cloned()
            .collect();

        // Should have exactly 10 common candidates
        assert_eq!(intersection.len(), 10);
        assert!(intersection.contains(&common1));
        assert!(intersection.contains(&common10));
        assert!(!intersection.contains(&extra1));
        assert!(!intersection.contains(&extra2));
    }
}
