// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Client, networking::NetworkError};
use ant_evm::{
    AttoTokens, EvmWallet,
    merkle_payments::{
        CANDIDATES_PER_POOL, MAX_LEAVES, MerklePaymentCandidateNode, MerklePaymentCandidatePool,
        MerklePaymentProof, MerklePaymentVerificationError, MerkleTree, MidpointProof,
    },
};
use ant_protocol::{
    NetworkAddress,
    storage::{ChunkAddress, DataTypes},
};
use evmlib::merkle_batch_payment::PoolCommitment;
use futures::stream::FuturesUnordered;
use libp2p::kad::PeerInfo;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};
use xor_name::XorName;

/// Contains the Merkle payment proofs for each XOR address and per-file chunk counts
/// This is the Merkle payment equivalent of [`Receipt`](crate::client::payment::Receipt)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerklePaymentReceipt {
    /// Merkle payment proofs for each XOR address
    pub proofs: HashMap<XorName, MerklePaymentProof>,
    /// Chunk count for each file path
    pub file_chunk_counts: HashMap<String, usize>,
    /// Total amount paid for this Merkle batch
    pub amount_paid: AttoTokens,
}

impl Default for MerklePaymentReceipt {
    fn default() -> Self {
        Self {
            proofs: HashMap::new(),
            file_chunk_counts: HashMap::new(),
            amount_paid: AttoTokens::zero(),
        }
    }
}

impl MerklePaymentReceipt {
    /// Merge another receipt into this one
    pub fn merge(&mut self, other: Self) {
        self.proofs.extend(other.proofs);
        self.file_chunk_counts.extend(other.file_chunk_counts);
        self.amount_paid = AttoTokens::from_atto(
            self.amount_paid
                .as_atto()
                .saturating_add(other.amount_paid.as_atto()),
        );
    }
}

/// Errors that can occur during Merkle batch payment operations
#[derive(Debug, thiserror::Error)]
pub enum MerklePaymentError {
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),
    #[error("Merkle tree error: {0}")]
    MerkleTree(#[from] ant_evm::merkle_payments::MerkleTreeError),
    #[error("Not enough valid candidate responses: got {got}, needed {needed}")]
    InsufficientCandidates { got: usize, needed: usize },
    #[error("Failed to serialize: {0}")]
    Serialization(String),
    #[error("Smart contract error: {0}")]
    SmartContract(String),
    #[error(
        "EVM wallet and client use different EVM networks. Please use the same network for both."
    )]
    EvmWalletNetworkMismatch,
    #[error("Wallet error: {0:?}")]
    EvmWalletError(#[from] ant_evm::EvmWalletError),
    #[error("Failed to get timestamp: {0}")]
    TimestampError(#[from] std::time::SystemTimeError),
    #[error("Candidate pool verification failed: {0}")]
    PoolVerification(#[from] MerklePaymentVerificationError),
}

impl Client {
    /// Get Merkle candidate nodes for a specific target address
    ///
    /// This queries storage nodes (the validators) for their view of acceptable payees
    /// close to the target address, builds consensus, and collects signed [`MerklePaymentCandidateNode`]
    /// responses from the consensus payees.
    ///
    /// # Arguments
    /// * `target_address` - The address to find candidates for (from MidpointProof::address())
    /// * `storage_nodes` - Nodes that will receive/validate records (their view determines valid payees)
    /// * `data_type` - The data type being uploaded (must be same for all data in batch)
    /// * `data_size` - The per-record data size (typically MAX_CHUNK_SIZE for chunks)
    /// * `merkle_payment_timestamp` - Unix timestamp for the payment
    ///
    /// # Returns
    /// * Array of exactly [`CANDIDATES_PER_POOL`] MerklePaymentCandidateNode with valid signatures,
    ///   selected from the consensus payees that storage nodes agree on
    async fn get_merkle_candidate_pool(
        &self,
        target_address: XorName,
        storage_nodes: &[PeerInfo],
        data_type: DataTypes,
        data_size: usize,
        merkle_payment_timestamp: u64,
    ) -> Result<[MerklePaymentCandidateNode; CANDIDATES_PER_POOL], MerklePaymentError> {
        let network_addr = NetworkAddress::ChunkAddress(ChunkAddress::new(target_address));

        // Query storage nodes for their view of closest peers to the midpoint address
        // These are the validators - they decide which payees are acceptable
        let query_count = CANDIDATES_PER_POOL + 5; // Get a few extra for buffer
        let query_futures = storage_nodes.iter().map(|node| {
            let network = self.network.clone();
            let addr = network_addr.clone();
            let peer = node.clone();
            async move {
                network
                    .get_closest_peers_from_peer(addr, peer, Some(query_count))
                    .await
            }
        });
        let results: Vec<_> = futures::future::join_all(query_futures).await;

        // Count peer appearances across responses to build consensus
        let mut peer_counts: HashMap<libp2p::PeerId, usize> = HashMap::new();
        let mut peer_addrs: HashMap<libp2p::PeerId, Vec<libp2p::Multiaddr>> = HashMap::new();
        let mut successful_responses = 0usize;

        for result in results.into_iter().flatten() {
            successful_responses += 1;
            for (peer_addr, addrs) in result {
                if let Some(peer_id) = peer_addr.as_peer_id() {
                    *peer_counts.entry(peer_id).or_insert(0) += 1;
                    peer_addrs.entry(peer_id).or_default().extend(addrs);
                }
            }
        }

        debug!(
            "Queried {} storage nodes, got {} successful responses for target {target_address:?}",
            storage_nodes.len(),
            successful_responses
        );

        // Take peers that appear in majority of responses (>50%)
        let threshold = successful_responses / 2;
        let mut consensus_peers: Vec<_> = peer_counts
            .iter()
            .filter(|&(_, count)| *count > threshold)
            .map(|(peer_id, _)| *peer_id)
            .collect();

        // Sort by distance to target address
        consensus_peers
            .sort_by_key(|peer_id| NetworkAddress::from(*peer_id).distance(&network_addr));

        debug!(
            "Found {} consensus peers (seen > {} times) for target {target_address:?}",
            consensus_peers.len(),
            threshold
        );

        // Fall back to direct query if consensus is insufficient
        if consensus_peers.len() < CANDIDATES_PER_POOL {
            debug!(
                "Insufficient consensus peers ({} < {}), falling back to direct query",
                consensus_peers.len(),
                CANDIDATES_PER_POOL
            );
            return self
                .get_merkle_candidate_pool_direct(
                    target_address,
                    data_type,
                    data_size,
                    merkle_payment_timestamp,
                )
                .await;
        }

        // Build PeerInfo from consensus peers (take extra for fault tolerance)
        let peers_to_query = std::cmp::min(
            consensus_peers.len(),
            CANDIDATES_PER_POOL + (CANDIDATES_PER_POOL / 4),
        );
        let consensus_peer_infos: Vec<PeerInfo> = consensus_peers
            .into_iter()
            .take(peers_to_query)
            .map(|peer_id| {
                let addrs = peer_addrs.get(&peer_id).cloned().unwrap_or_default();
                // Deduplicate addresses
                let unique_addrs: Vec<_> = addrs
                    .into_iter()
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                PeerInfo {
                    peer_id,
                    addrs: unique_addrs,
                }
            })
            .collect();

        // Request quotes from consensus peers in parallel
        let mut tasks = FuturesUnordered::new();
        for peer_info in &consensus_peer_infos {
            let network = self.network.clone();
            let network_addr = network_addr.clone();
            let data_type_index = data_type.get_index();
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

        // Collect successful responses
        let mut successful_candidates: Vec<(libp2p::PeerId, MerklePaymentCandidateNode)> =
            Vec::new();
        use futures::StreamExt;
        while let Some((peer_id, result)) = tasks.next().await {
            match result {
                Ok(candidate) => {
                    successful_candidates.push((peer_id, candidate));
                }
                Err(e) => {
                    warn!(
                        "Failed to get quote from consensus peer {peer_id:?} for target {target_address:?}: {e}"
                    );
                }
            }
        }

        debug!(
            "Got {} successful quote responses from {} consensus peers for target {target_address:?}",
            successful_candidates.len(),
            consensus_peer_infos.len(),
        );

        // Check if we have enough successful responses
        if successful_candidates.len() < CANDIDATES_PER_POOL {
            return Err(MerklePaymentError::InsufficientCandidates {
                got: successful_candidates.len(),
                needed: CANDIDATES_PER_POOL,
            });
        }

        // Sort by distance and take the closest
        successful_candidates
            .sort_by_key(|(peer_id, _)| NetworkAddress::from(*peer_id).distance(&network_addr));

        let closest_successful: Vec<MerklePaymentCandidateNode> = successful_candidates
            .into_iter()
            .take(CANDIDATES_PER_POOL)
            .map(|(_, candidate)| candidate)
            .collect();

        // Convert to exact-sized array
        let candidates_array: [MerklePaymentCandidateNode; CANDIDATES_PER_POOL] =
            closest_successful.try_into().map_err(|v: Vec<_>| {
                MerklePaymentError::InsufficientCandidates {
                    got: v.len(),
                    needed: CANDIDATES_PER_POOL,
                }
            })?;

        Ok(candidates_array)
    }

    /// Fallback method: Get Merkle candidate nodes using direct query (original behavior)
    ///
    /// This is used when storage node consensus is insufficient.
    async fn get_merkle_candidate_pool_direct(
        &self,
        target_address: XorName,
        data_type: DataTypes,
        data_size: usize,
        merkle_payment_timestamp: u64,
    ) -> Result<[MerklePaymentCandidateNode; CANDIDATES_PER_POOL], MerklePaymentError> {
        const PEERS_TO_QUERY: usize = CANDIDATES_PER_POOL + (CANDIDATES_PER_POOL / 4);

        let network_addr = NetworkAddress::ChunkAddress(ChunkAddress::new(target_address));
        let closest_peers = self
            .network
            .get_closest_peers_with_retries(network_addr.clone(), Some(PEERS_TO_QUERY))
            .await?;

        let unique_peers: HashMap<libp2p::PeerId, PeerInfo> = closest_peers
            .into_iter()
            .map(|peer_info| (peer_info.peer_id, peer_info))
            .collect();

        if unique_peers.len() < CANDIDATES_PER_POOL {
            return Err(MerklePaymentError::InsufficientCandidates {
                got: unique_peers.len(),
                needed: CANDIDATES_PER_POOL,
            });
        }

        let peer_info_with_distances: Vec<_> = unique_peers
            .values()
            .map(|peer_info| {
                let peer_addr = NetworkAddress::from(peer_info.peer_id);
                let distance = network_addr.distance(&peer_addr);
                (peer_info.clone(), distance)
            })
            .collect();

        let mut tasks = FuturesUnordered::new();
        for (peer_info, _distance) in &peer_info_with_distances {
            let network = self.network.clone();
            let network_addr = network_addr.clone();
            let data_type_index = data_type.get_index();
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

        let mut successful_candidates: Vec<(libp2p::PeerId, MerklePaymentCandidateNode)> =
            Vec::new();
        use futures::StreamExt;
        while let Some((peer_id, result)) = tasks.next().await {
            match result {
                Ok(candidate) => {
                    successful_candidates.push((peer_id, candidate));
                }
                Err(e) => {
                    warn!(
                        "Failed to get quote from peer {peer_id:?} for target {target_address:?}: {e}"
                    );
                }
            }
        }

        if successful_candidates.len() < CANDIDATES_PER_POOL {
            return Err(MerklePaymentError::InsufficientCandidates {
                got: successful_candidates.len(),
                needed: CANDIDATES_PER_POOL,
            });
        }

        successful_candidates
            .sort_by_key(|(peer_id, _)| NetworkAddress::from(*peer_id).distance(&network_addr));

        let closest_successful: Vec<MerklePaymentCandidateNode> = successful_candidates
            .into_iter()
            .take(CANDIDATES_PER_POOL)
            .map(|(_, candidate)| candidate)
            .collect();

        let candidates_array: [MerklePaymentCandidateNode; CANDIDATES_PER_POOL] =
            closest_successful.try_into().map_err(|v: Vec<_>| {
                MerklePaymentError::InsufficientCandidates {
                    got: v.len(),
                    needed: CANDIDATES_PER_POOL,
                }
            })?;

        Ok(candidates_array)
    }

    /// Build a single candidate pool for one midpoint proof
    async fn build_single_candidate_pool(
        &self,
        midpoint_proof: MidpointProof,
        storage_nodes: &[PeerInfo],
        data_type: DataTypes,
        data_size: usize,
    ) -> Result<MerklePaymentCandidatePool, MerklePaymentError> {
        let target = midpoint_proof.address();
        let timestamp = midpoint_proof.merkle_payment_timestamp;

        // Get candidates for this pool using storage nodes' consensus
        let candidate_nodes = self
            .get_merkle_candidate_pool(target, storage_nodes, data_type, data_size, timestamp)
            .await?;

        let pool = MerklePaymentCandidatePool {
            midpoint_proof,
            candidate_nodes,
        };

        // Validate signatures before accepting the pool
        pool.verify_signatures(timestamp)?;

        Ok(pool)
    }

    /// Build candidate pools for all midpoint proofs (in parallel)
    ///
    /// # Arguments
    /// * `midpoint_proofs` - The midpoint proofs from the Merkle tree
    /// * `storage_nodes` - Nodes that will receive/validate records (their view determines valid payees)
    /// * `data_type` - Data type for all items in batch
    /// * `data_size` - The per-record data size (typically MAX_CHUNK_SIZE for chunks)
    ///
    /// # Returns
    /// * Vector of MerklePaymentCandidatePool, one for each midpoint
    pub(crate) async fn build_candidate_pools(
        &self,
        midpoint_proofs: Vec<MidpointProof>,
        storage_nodes: &[PeerInfo],
        data_type: DataTypes,
        data_size: usize,
    ) -> Result<Vec<MerklePaymentCandidatePool>, MerklePaymentError> {
        // Build all pools in parallel, sharing the storage_nodes reference
        let pool_futures = midpoint_proofs.into_iter().map(|proof| {
            let client = self.clone();
            let storage_nodes = storage_nodes.to_vec();
            async move {
                client
                    .build_single_candidate_pool(proof, &storage_nodes, data_type, data_size)
                    .await
            }
        });
        let pools = futures::future::try_join_all(pool_futures).await?;

        Ok(pools)
    }

    /// Pay for a batch of data addresses using Merkle payment and get the proofs
    ///
    /// Automatically splits large batches (>4096 addresses) into multiple Merkle trees.
    ///
    /// # Arguments
    /// * `data_type` - The data type (must be same for all items)
    /// * `content_addrs` - Iterator of XorName addresses
    /// * `data_size` - The per-record data size that nodes will store (typically MAX_CHUNK_SIZE for chunks)
    /// * `wallet` - The EVM wallet to pay with
    ///
    /// # Returns
    /// * `MerklePaymentReceipt` - HashMap mapping each address to its MerklePaymentProof
    pub async fn pay_for_merkle_batch(
        &self,
        data_type: DataTypes,
        content_addrs: impl Iterator<Item = XorName>,
        data_size: usize,
        wallet: &EvmWallet,
    ) -> Result<MerklePaymentReceipt, MerklePaymentError> {
        if wallet.network() != self.evm_network() {
            return Err(MerklePaymentError::EvmWalletNetworkMismatch);
        }

        let addresses: Vec<XorName> = content_addrs.collect();
        let batches: Vec<Vec<XorName>> = addresses.chunks(MAX_LEAVES).map(|c| c.to_vec()).collect();
        let batches_len = batches.len();
        let addresses_len = addresses.len();
        #[cfg(feature = "loud")]
        println!("Paying for {addresses_len} addresses in {batches_len} batch(es)");
        info!("Paying for {addresses_len} addresses in {batches_len} batch(es)");

        let mut merged_receipt = MerklePaymentReceipt::default();
        for (i, batch) in batches.into_iter().enumerate() {
            #[cfg(feature = "loud")]
            println!("Processing batch {}/{batches_len}", i + 1);
            info!("Processing batch {}/{batches_len}", i + 1);
            let receipt = self
                .pay_for_single_merkle_batch(data_type, batch, data_size, wallet)
                .await?;
            merged_receipt.merge(receipt);
        }

        Ok(merged_receipt)
    }

    /// Prepare a Merkle batch - builds tree, queries candidate pools
    /// Returns (tree, candidate_pools, pool_commitments, timestamp)
    pub(crate) async fn prepare_merkle_batch(
        &self,
        data_type: DataTypes,
        addresses: Vec<XorName>,
        data_size: usize,
    ) -> Result<
        (
            MerkleTree,
            Vec<MerklePaymentCandidatePool>,
            Vec<PoolCommitment>,
            u64,
        ),
        MerklePaymentError,
    > {
        info!(
            "Preparing Merkle batch for {} addresses with data_type {data_type:?}",
            addresses.len()
        );

        // Collect storage nodes from a sample of chunk addresses
        // These nodes will validate payments, so we ask them for their view of acceptable payees
        let storage_nodes = self.collect_storage_nodes_sample(&addresses).await?;
        info!(
            "Collected {} unique storage nodes from sample of chunk addresses",
            storage_nodes.len()
        );

        // Pad to minimum 2 leaves if only 1 address (rare edge case when N-1 of N chunks already exist)
        // The duplicate leaf gets a different random salt, so the tree is valid.
        // Only the proof at index 0 is used (in pay_for_single_merkle_batch the original addresses
        // vector is used for proof generation, which has only 1 element).
        let addresses = match addresses[..] {
            [only_one] => vec![only_one, only_one],
            _ => addresses,
        };

        // Build Merkle tree
        let tree = MerkleTree::from_xornames(addresses)?;
        let depth = tree.depth();
        info!("Built Merkle tree: depth={depth}");

        // Get timestamp and reward candidates
        let merkle_payment_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let midpoint_proofs = tree.reward_candidates(merkle_payment_timestamp)?;
        info!("Generated {} midpoint proofs", midpoint_proofs.len());

        // Query network for candidate pools with signature validation
        // Use storage nodes' consensus to determine acceptable payees
        let candidate_pools = self
            .build_candidate_pools(midpoint_proofs, &storage_nodes, data_type, data_size)
            .await?;
        info!(
            "Collected and validated all {} candidate pools",
            candidate_pools.len()
        );

        // Convert to pool commitments
        let pool_commitments: Vec<PoolCommitment> = candidate_pools
            .iter()
            .map(|pool| pool.to_commitment())
            .collect();

        Ok((
            tree,
            candidate_pools,
            pool_commitments,
            merkle_payment_timestamp,
        ))
    }

    /// Collect a sample of storage nodes from chunk addresses
    ///
    /// These are the nodes that will receive and validate records. We query them
    /// for their view of acceptable payees to ensure payment validation passes.
    async fn collect_storage_nodes_sample(
        &self,
        addresses: &[XorName],
    ) -> Result<Vec<PeerInfo>, MerklePaymentError> {
        // Sample up to 5 chunk addresses evenly distributed across the batch
        let sample_size = std::cmp::min(5, addresses.len());
        let step = if sample_size > 0 {
            addresses.len() / sample_size
        } else {
            1
        };
        let sample_indices: Vec<usize> = (0..addresses.len())
            .step_by(step.max(1))
            .take(sample_size)
            .collect();

        debug!(
            "Sampling storage nodes from {} chunk addresses (indices: {:?})",
            sample_size, sample_indices
        );

        // Query storage nodes for each sampled chunk address in parallel
        let query_futures = sample_indices.iter().map(|&idx| {
            let network = self.network.clone();
            let addr = NetworkAddress::ChunkAddress(ChunkAddress::new(addresses[idx]));
            async move { network.get_closest_peers_with_retries(addr, Some(5)).await }
        });
        let results: Vec<_> = futures::future::join_all(query_futures).await;

        // Collect all unique storage nodes
        let mut seen_peers: HashSet<libp2p::PeerId> = HashSet::new();
        let mut storage_nodes: Vec<PeerInfo> = Vec::new();

        for result in results.into_iter().flatten() {
            for peer in result {
                if seen_peers.insert(peer.peer_id) {
                    storage_nodes.push(peer);
                }
            }
        }

        // Ensure we have at least some storage nodes
        if storage_nodes.is_empty() {
            return Err(MerklePaymentError::InsufficientCandidates { got: 0, needed: 1 });
        }

        Ok(storage_nodes)
    }

    /// Pay for a single batch of up to MAX_LEAVES addresses
    pub(crate) async fn pay_for_single_merkle_batch(
        &self,
        data_type: DataTypes,
        addresses: Vec<XorName>,
        data_size: usize,
        wallet: &EvmWallet,
    ) -> Result<MerklePaymentReceipt, MerklePaymentError> {
        // Prepare the batch (build tree, query pools)
        let (tree, candidate_pools, pool_commitments, merkle_payment_timestamp) = self
            .prepare_merkle_batch(data_type, addresses.clone(), data_size)
            .await?;
        let depth = tree.depth();

        // Submit payment to smart contract
        debug!("Waiting for wallet lock");
        let lock_guard = wallet.lock().await;
        debug!("Locked wallet");
        let (winner_pool_hash, amount) = wallet
            .pay_for_merkle_tree(depth, pool_commitments, merkle_payment_timestamp)
            .await?;
        let amount = AttoTokens::from_atto(amount);
        drop(lock_guard);
        debug!("Unlocked wallet");

        info!("Payment submitted, winner pool: {winner_pool_hash:?}, amount: {amount}");

        // Find winner pool and generate proofs
        let winner_pool = candidate_pools
            .into_iter()
            .find(|pool| pool.hash() == winner_pool_hash)
            .ok_or_else(|| {
                MerklePaymentError::SmartContract(format!(
                    "Smart contract returned invalid pool hash: {}",
                    hex::encode(winner_pool_hash)
                ))
            })?;

        let mut proofs = HashMap::new();
        for (i, address) in addresses.into_iter().enumerate() {
            let address_proof = tree.generate_address_proof(i, address)?;
            let payment_proof = MerklePaymentProof {
                address,
                data_proof: address_proof,
                winner_pool: winner_pool.clone(),
            };
            proofs.insert(address, payment_proof);
        }

        let receipt = MerklePaymentReceipt {
            proofs,
            file_chunk_counts: HashMap::new(),
            amount_paid: amount,
        };

        info!(
            "Generated {} Merkle payment proofs, total amount: {amount}",
            receipt.proofs.len()
        );
        Ok(receipt)
    }
}
