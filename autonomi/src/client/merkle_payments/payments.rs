// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::consensus::ConsensusError;
use crate::{Client, networking::NetworkError};
use ant_evm::{
    AttoTokens, EvmWallet,
    merkle_payments::{MAX_LEAVES, MerklePaymentCandidatePool, MerklePaymentProof, MerkleTree},
};
use ant_protocol::storage::{Chunk, DataTypes};
use evmlib::merkle_batch_payment::PoolCommitment;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};
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
    #[error("Consensus error: {0}")]
    Consensus(#[from] ConsensusError),
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
}

impl Client {
    /// Pay for a batch of chunks using Merkle payment and get the proofs
    ///
    /// Automatically splits large batches (>4096 chunks) into multiple Merkle trees.
    /// Uses consensus-based merkle candidate selection where storing nodes must agree.
    ///
    /// # Arguments
    /// * `data_type` - The data type (must be same for all items)
    /// * `chunks` - Iterator of Chunk objects (with actual data for consensus probing)
    /// * `data_size` - The per-record data size that nodes will store (typically MAX_CHUNK_SIZE for chunks)
    /// * `wallet` - The EVM wallet to pay with
    ///
    /// # Returns
    /// * `MerklePaymentReceipt` - HashMap mapping each address to its MerklePaymentProof
    pub async fn pay_for_merkle_batch(
        &self,
        data_type: DataTypes,
        chunks: impl Iterator<Item = Chunk>,
        data_size: usize,
        wallet: &EvmWallet,
    ) -> Result<MerklePaymentReceipt, MerklePaymentError> {
        if wallet.network() != self.evm_network() {
            return Err(MerklePaymentError::EvmWalletNetworkMismatch);
        }

        let chunks: Vec<Chunk> = chunks.collect();
        let batches: Vec<Vec<Chunk>> = chunks.chunks(MAX_LEAVES).map(|c| c.to_vec()).collect();
        let batches_len = batches.len();
        let chunks_len = chunks.len();
        #[cfg(feature = "loud")]
        println!("Paying for {chunks_len} chunks in {batches_len} batch(es)");
        info!("Paying for {chunks_len} chunks in {batches_len} batch(es)");

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

    /// Prepare a Merkle batch for cost estimation only (no consensus probing).
    ///
    /// This is a lightweight version that doesn't do consensus probing - it just
    /// queries nodes close to midpoints to get pool commitments for cost estimation.
    /// For actual payment, use `prepare_merkle_batch` which requires chunks and does
    /// full consensus probing.
    ///
    /// Returns (tree, pool_commitments, timestamp)
    pub(crate) async fn prepare_merkle_batch_for_cost(
        &self,
        data_type: DataTypes,
        addresses: Vec<XorName>,
        data_size: usize,
    ) -> Result<(MerkleTree, Vec<PoolCommitment>, u64), MerklePaymentError> {
        info!(
            "Preparing Merkle batch for cost estimation: {} addresses with data_type {data_type:?}",
            addresses.len()
        );

        // Pad to minimum 2 leaves if only 1 address
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

        // For cost estimation, we don't need consensus - just query closest nodes
        // and use their view for pool commitments (estimation only)
        let mut pool_commitments = Vec::with_capacity(midpoint_proofs.len());
        for midpoint_proof in midpoint_proofs {
            let pool = self
                .build_candidate_pool_for_cost(midpoint_proof, data_type, data_size)
                .await?;
            pool_commitments.push(pool.to_commitment());
        }

        info!(
            "Built {} pool commitments for cost estimation",
            pool_commitments.len()
        );

        Ok((tree, pool_commitments, merkle_payment_timestamp))
    }

    /// Build a candidate pool for cost estimation (no consensus, just query closest).
    async fn build_candidate_pool_for_cost(
        &self,
        midpoint_proof: ant_evm::merkle_payments::MidpointProof,
        data_type: DataTypes,
        data_size: usize,
    ) -> Result<MerklePaymentCandidatePool, MerklePaymentError> {
        use ant_protocol::storage::ChunkAddress;
        use std::num::NonZero;

        let midpoint_address = midpoint_proof.address();
        let merkle_payment_timestamp = midpoint_proof.merkle_payment_timestamp;

        // Get closest nodes to midpoint
        let midpoint_network_addr =
            crate::networking::NetworkAddress::ChunkAddress(ChunkAddress::new(midpoint_address));
        let closest = self
            .network
            .get_closest_n_peers(
                midpoint_network_addr,
                NonZero::new(ant_protocol::CLOSE_GROUP_SIZE).expect("CLOSE_GROUP_SIZE is non-zero"),
            )
            .await?;

        if closest.len() < ant_evm::merkle_payments::CANDIDATES_PER_POOL {
            return Err(MerklePaymentError::Consensus(
                super::consensus::ConsensusError::InsufficientResponses {
                    got: closest.len(),
                    needed: ant_evm::merkle_payments::CANDIDATES_PER_POOL,
                },
            ));
        }

        // Get quotes from closest nodes
        let candidates = self
            .build_consensus_candidate_pool_quotes_only(
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

    /// Get quotes from nodes (helper for cost estimation).
    async fn build_consensus_candidate_pool_quotes_only(
        &self,
        peers: &[libp2p::kad::PeerInfo],
        midpoint_address: XorName,
        data_type: DataTypes,
        data_size: usize,
        merkle_payment_timestamp: u64,
    ) -> Result<
        [ant_evm::merkle_payments::MerklePaymentCandidateNode;
            ant_evm::merkle_payments::CANDIDATES_PER_POOL],
        MerklePaymentError,
    > {
        use ant_protocol::storage::ChunkAddress;
        use futures::StreamExt;
        use futures::stream::FuturesUnordered;

        let network_addr =
            crate::networking::NetworkAddress::ChunkAddress(ChunkAddress::new(midpoint_address));
        let data_type_index = data_type.get_index();

        let mut tasks = FuturesUnordered::new();
        for peer_info in peers
            .iter()
            .take(ant_evm::merkle_payments::CANDIDATES_PER_POOL + 4)
        {
            let network = self.network.clone();
            let network_addr = network_addr.clone();
            let peer_info = peer_info.clone();

            tasks.push(async move {
                network
                    .get_merkle_candidate_quote(
                        network_addr,
                        peer_info,
                        data_type_index,
                        data_size,
                        merkle_payment_timestamp,
                    )
                    .await
            });
        }

        let mut candidates = Vec::new();
        while let Some(result) = tasks.next().await {
            if let Ok(candidate) = result {
                candidates.push(candidate);
                if candidates.len() >= ant_evm::merkle_payments::CANDIDATES_PER_POOL {
                    break;
                }
            }
        }

        candidates.try_into().map_err(|v: Vec<_>| {
            MerklePaymentError::Consensus(ConsensusError::InsufficientResponses {
                got: v.len(),
                needed: ant_evm::merkle_payments::CANDIDATES_PER_POOL,
            })
        })
    }

    /// Prepare a Merkle batch - builds tree, queries candidate pools using consensus
    ///
    /// This uses consensus-based merkle candidate selection where storing nodes
    /// must agree on the merkle candidates for each midpoint before payment.
    ///
    /// Probing for consensus requires on-chain payments. The probe cost is returned
    /// separately so it can be included in the total amount paid.
    ///
    /// Returns (tree, candidate_pools, pool_commitments, timestamp, probe_cost)
    pub(crate) async fn prepare_merkle_batch(
        &self,
        data_type: DataTypes,
        chunks: Vec<Chunk>,
        data_size: usize,
        wallet: &EvmWallet,
    ) -> Result<
        (
            MerkleTree,
            Vec<MerklePaymentCandidatePool>,
            Vec<PoolCommitment>,
            u64,
            AttoTokens,
        ),
        MerklePaymentError,
    > {
        info!(
            "Preparing Merkle batch for {} chunks with data_type {data_type:?} using consensus",
            chunks.len()
        );

        // Extract addresses from chunks
        let addresses: Vec<XorName> = chunks.iter().map(|c| *c.name()).collect();

        // Pad to minimum 2 leaves if only 1 chunk (rare edge case when N-1 of N chunks already exist)
        // The duplicate leaf gets a different random salt, so the tree is valid.
        // Only the proof at index 0 is used (in pay_for_single_merkle_batch the original addresses
        // vector is used for proof generation, which has only 1 element).
        let (addresses, chunks) = match addresses[..] {
            [only_one] => (
                vec![only_one, only_one],
                vec![chunks[0].clone(), chunks[0].clone()],
            ),
            _ => (addresses, chunks),
        };

        // Build Merkle tree
        let tree = MerkleTree::from_xornames(addresses.clone())?;
        let depth = tree.depth();
        info!("Built Merkle tree: depth={depth}");

        // Get timestamp and reward candidates
        let merkle_payment_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let midpoint_proofs = tree.reward_candidates(merkle_payment_timestamp)?;
        info!("Generated {} midpoint proofs", midpoint_proofs.len());

        // Build consensus-based candidate pools
        // This probes storing nodes (close to chunk addresses) to get their topology views
        // of merkle candidates (close to midpoint addresses) and builds consensus.
        // Probing requires on-chain payments which are included in probe_cost.
        let (candidate_pools, probe_cost) = self
            .build_consensus_candidate_pools(
                midpoint_proofs,
                &chunks,
                depth,
                data_type,
                data_size,
                wallet,
            )
            .await?;
        info!(
            "Built {} consensus-based candidate pools, probe cost: {probe_cost}",
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
            probe_cost,
        ))
    }

    /// Pay for a single batch of up to MAX_LEAVES chunks
    ///
    /// This includes both the probe cost (for consensus discovery) and the main payment.
    pub(crate) async fn pay_for_single_merkle_batch(
        &self,
        data_type: DataTypes,
        chunks: Vec<Chunk>,
        data_size: usize,
        wallet: &EvmWallet,
    ) -> Result<MerklePaymentReceipt, MerklePaymentError> {
        // Extract addresses for proof generation
        let addresses: Vec<XorName> = chunks.iter().map(|c| *c.name()).collect();

        // Prepare the batch (build tree, query pools with actual chunks for consensus)
        // This includes paid probing for consensus discovery
        let (tree, candidate_pools, pool_commitments, merkle_payment_timestamp, probe_cost) = self
            .prepare_merkle_batch(data_type, chunks, data_size, wallet)
            .await?;
        let depth = tree.depth();

        // Submit main payment to smart contract
        debug!("Waiting for wallet lock");
        let lock_guard = wallet.lock().await;
        debug!("Locked wallet");
        let (winner_pool_hash, main_amount) = wallet
            .pay_for_merkle_tree(depth, pool_commitments, merkle_payment_timestamp)
            .await?;
        let main_amount = AttoTokens::from_atto(main_amount);
        drop(lock_guard);
        debug!("Unlocked wallet");

        // Total amount = probe cost + main payment
        let total_amount =
            AttoTokens::from_atto(probe_cost.as_atto().saturating_add(main_amount.as_atto()));

        info!(
            "Payment submitted, winner pool: {winner_pool_hash:?}, main: {main_amount}, probe: {probe_cost}, total: {total_amount}"
        );

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
            amount_paid: total_amount,
        };

        info!(
            "Generated {} Merkle payment proofs, total amount: {total_amount}",
            receipt.proofs.len()
        );
        Ok(receipt)
    }
}
