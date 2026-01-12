// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Client, networking::NetworkError};
use super::candidate_consensus::CandidateConsensusError;
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
use libp2p::PeerId;
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
    #[error("Candidate consensus error: {0}")]
    CandidateConsensus(#[from] CandidateConsensusError),
}

impl Client {
    /// Get Merkle candidate nodes using network consensus.
    ///
    /// This finds storing node triplets for each chunk that maps to the midpoint,
    /// then queries ALL storing nodes for their view of merkle candidates and
    /// finds consensus across all of them.
    ///
    /// # Arguments
    /// * `chunk_addresses` - All chunk addresses that map to this midpoint
    /// * `midpoint_address` - The merkle tree midpoint address
    /// * `data_type` - The data type being uploaded
    /// * `data_size` - The per-record data size
    /// * `merkle_payment_timestamp` - Unix timestamp for the payment
    ///
    /// # Returns
    /// * Array of CANDIDATES_PER_POOL candidate nodes from the consensus set
    async fn get_merkle_candidate_pool(
        &self,
        chunk_addresses: Vec<XorName>,
        midpoint_address: XorName,
        data_type: DataTypes,
        data_size: usize,
        merkle_payment_timestamp: u64,
    ) -> Result<[MerklePaymentCandidateNode; CANDIDATES_PER_POOL], MerklePaymentError> {
        info!(
            "Getting merkle candidates by consensus: {} chunks → midpoint {:?}",
            chunk_addresses.len(),
            midpoint_address
        );

        // Step 1: Get consensus on who the merkle candidates should be
        // For each chunk, find 3 storing nodes with mutual membership
        // Then query ALL storing nodes for their view of merkle candidates
        let consensus = self
            .get_midpoint_consensus(chunk_addresses, midpoint_address)
            .await?;

        debug!(
            "Found consensus: {} chunk triplets, {} total storing nodes, {} consensus merkle candidates",
            consensus.chunk_triplets.len(),
            consensus.all_storing_nodes.len(),
            consensus.consensus_merkle_candidates.len()
        );

        // Step 2: Build the list of candidates to query for quotes
        // Use the consensus merkle candidates
        let candidates_to_query: HashSet<PeerId> =
            consensus.consensus_merkle_candidates.iter().cloned().collect();

        // Sort by distance to midpoint for consistent ordering
        let network_addr = NetworkAddress::ChunkAddress(ChunkAddress::new(midpoint_address));
        let mut sorted_candidates: Vec<PeerId> = candidates_to_query.into_iter().collect();
        sorted_candidates.sort_by_key(|peer_id| {
            let peer_addr = NetworkAddress::from(*peer_id);
            network_addr.distance(&peer_addr)
        });

        // Take the closest CANDIDATES_PER_POOL candidates
        let candidates_to_query: Vec<PeerId> = sorted_candidates
            .into_iter()
            .take(CANDIDATES_PER_POOL + 5) // Query a few extra for fault tolerance
            .collect();

        if candidates_to_query.len() < CANDIDATES_PER_POOL {
            return Err(MerklePaymentError::InsufficientCandidates {
                got: candidates_to_query.len(),
                needed: CANDIDATES_PER_POOL,
            });
        }

        // Step 3: Get quotes from the consensus candidates
        // We need to find peer info (addresses) for each candidate
        let closest_peers = self
            .network
            .get_closest_peers(network_addr.clone(), Some(CANDIDATES_PER_POOL + 10))
            .await?;

        let peer_info_map: HashMap<PeerId, libp2p::kad::PeerInfo> = closest_peers
            .into_iter()
            .map(|info| (info.peer_id, info))
            .collect();

        // Add addresses from storing node triplets (they might know addresses of merkle candidates)
        let mut peer_info_map_extended = peer_info_map;
        for triplet in &consensus.chunk_triplets {
            for (peer_id, addrs) in &triplet.storing_node_addrs {
                peer_info_map_extended.entry(*peer_id).or_insert_with(|| {
                    libp2p::kad::PeerInfo {
                        peer_id: *peer_id,
                        addrs: addrs.clone(),
                    }
                });
            }
        }

        // Request quotes from consensus candidates
        let mut tasks = FuturesUnordered::new();
        for peer_id in &candidates_to_query {
            if let Some(peer_info) = peer_info_map_extended.get(peer_id) {
                let network = self.network.clone();
                let network_addr = network_addr.clone();
                let data_type_index = data_type.get_index();
                let peer_info = peer_info.clone();
                let peer_id = *peer_id;
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
        }

        // Collect successful responses
        let mut successful_candidates: Vec<(PeerId, MerklePaymentCandidateNode)> = Vec::new();
        use futures::StreamExt;
        while let Some((peer_id, result)) = tasks.next().await {
            match result {
                Ok(candidate) => {
                    successful_candidates.push((peer_id, candidate));
                }
                Err(e) => {
                    warn!(
                        "Failed to get consensus quote from peer {peer_id:?}: {e}"
                    );
                }
            }
        }

        debug!(
            "Got {} successful consensus quotes for target {midpoint_address:?}",
            successful_candidates.len()
        );

        if successful_candidates.len() < CANDIDATES_PER_POOL {
            return Err(MerklePaymentError::InsufficientCandidates {
                got: successful_candidates.len(),
                needed: CANDIDATES_PER_POOL,
            });
        }

        // Sort by distance and take closest
        successful_candidates.sort_by_key(|(peer_id, _)| {
            let peer_addr = NetworkAddress::from(*peer_id);
            network_addr.distance(&peer_addr)
        });

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

        info!(
            "Successfully got {} consensus-based candidates for target {midpoint_address:?}",
            CANDIDATES_PER_POOL
        );

        Ok(candidates_array)
    }

    /// Build a single candidate pool for one midpoint proof.
    ///
    /// # Arguments
    /// * `midpoint_proof` - The midpoint proof (contains leaf_addresses for this midpoint)
    /// * `data_type` - The data type being uploaded
    /// * `data_size` - The per-record data size
    async fn build_single_candidate_pool(
        &self,
        midpoint_proof: MidpointProof,
        data_type: DataTypes,
        data_size: usize,
    ) -> Result<MerklePaymentCandidatePool, MerklePaymentError> {
        let midpoint_address = midpoint_proof.address();
        let timestamp = midpoint_proof.merkle_payment_timestamp;

        // Get chunk addresses from the midpoint proof
        let chunk_addresses = midpoint_proof.leaf_addresses.clone();

        // Get candidates using consensus from ALL storing nodes of ALL chunks
        let candidate_nodes = self
            .get_merkle_candidate_pool(
                chunk_addresses,
                midpoint_address,
                data_type,
                data_size,
                timestamp,
            )
            .await?;

        let pool = MerklePaymentCandidatePool {
            midpoint_proof,
            candidate_nodes,
        };

        // Validate signatures before accepting the pool
        pool.verify_signatures(timestamp)?;

        Ok(pool)
    }

    /// Build candidate pools for all midpoint proofs (in parallel).
    ///
    /// # Arguments
    /// * `midpoint_proofs` - The midpoint proofs from the merkle tree (each contains leaf_addresses)
    /// * `data_type` - The data type being uploaded
    /// * `data_size` - The per-record data size
    pub(crate) async fn build_candidate_pools(
        &self,
        midpoint_proofs: Vec<MidpointProof>,
        data_type: DataTypes,
        data_size: usize,
    ) -> Result<Vec<MerklePaymentCandidatePool>, MerklePaymentError> {
        let pool_futures = midpoint_proofs.into_iter().map(|proof| {
            let client = self.clone();
            async move {
                client
                    .build_single_candidate_pool(proof, data_type, data_size)
                    .await
            }
        });
        let pools = futures::future::try_join_all(pool_futures).await?;

        Ok(pools)
    }

    /// Prepare a Merkle batch - builds tree, queries candidate pools using consensus.
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

        if addresses.is_empty() {
            return Err(MerklePaymentError::InsufficientCandidates { got: 0, needed: 1 });
        }

        // Pad to minimum 2 leaves if only 1 address
        let addresses = match addresses[..] {
            [only_one] => vec![only_one, only_one],
            _ => addresses,
        };

        // Build Merkle tree
        let tree = MerkleTree::from_xornames(addresses.clone())?;
        let depth = tree.depth();
        info!("Built Merkle tree: depth={depth}");

        // Get timestamp and reward candidates
        // Each midpoint_proof includes leaf_addresses - the chunks that map to it
        let merkle_payment_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let midpoint_proofs = tree.reward_candidates(merkle_payment_timestamp, &addresses)?;
        info!(
            "Generated {} midpoint proofs (each contains its leaf addresses)",
            midpoint_proofs.len()
        );

        // Query network for candidate pools using consensus from storing nodes
        // For each midpoint, we query storing nodes from ALL chunks in midpoint_proof.leaf_addresses
        let candidate_pools = self
            .build_candidate_pools(midpoint_proofs, data_type, data_size)
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

    /// Pay for a single batch of up to MAX_LEAVES addresses.
    pub(crate) async fn pay_for_single_merkle_batch(
        &self,
        data_type: DataTypes,
        addresses: Vec<XorName>,
        data_size: usize,
        wallet: &EvmWallet,
    ) -> Result<MerklePaymentReceipt, MerklePaymentError> {
        // Prepare the batch using consensus
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

        info!("Payment submitted , winner pool: {winner_pool_hash:?}, amount: {amount}");

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
            "Generated {} Merkle payment proofs , total amount: {amount}",
            receipt.proofs.len()
        );
        Ok(receipt)
    }

    /// Pay for a batch of data addresses using Merkle payment.
    ///
    /// Uses network consensus to select merkle candidates by:
    /// 1. Finding storing node triplets (3 nodes with mutual membership) for each chunk
    /// 2. Querying all storing nodes for their view of merkle candidates
    /// 3. Finding consensus across all storing nodes for each midpoint
    ///
    /// Automatically splits large batches (>4096 addresses) into multiple Merkle trees.
    ///
    /// # Arguments
    /// * `data_type` - The data type (must be same for all items)
    /// * `content_addrs` - Iterator of XorName addresses
    /// * `data_size` - The per-record data size
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
}
