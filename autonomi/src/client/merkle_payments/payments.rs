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
    merkle_payments::{
        MAX_LEAVES, MerklePaymentCandidatePool, MerklePaymentProof, MerkleTree,
    },
};
use ant_protocol::storage::DataTypes;
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

    /// Prepare a Merkle batch - builds tree, queries candidate pools using consensus
    ///
    /// This uses consensus-based merkle candidate selection where storing nodes
    /// must agree on the merkle candidates for each midpoint before payment.
    ///
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
            "Preparing Merkle batch for {} addresses with data_type {data_type:?} using consensus",
            addresses.len()
        );

        // Pad to minimum 2 leaves if only 1 address (rare edge case when N-1 of N chunks already exist)
        // The duplicate leaf gets a different random salt, so the tree is valid.
        // Only the proof at index 0 is used (in pay_for_single_merkle_batch the original addresses
        // vector is used for proof generation, which has only 1 element).
        let addresses = match addresses[..] {
            [only_one] => vec![only_one, only_one],
            _ => addresses,
        };

        // Build Merkle tree (clone addresses since we need them later for consensus)
        let tree = MerkleTree::from_xornames(addresses.clone())?;
        let depth = tree.depth();
        info!("Built Merkle tree: depth={depth}");

        // Get timestamp and reward candidates
        let merkle_payment_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let midpoint_proofs = tree.reward_candidates(merkle_payment_timestamp)?;
        info!("Generated {} midpoint proofs", midpoint_proofs.len());

        // Build consensus-based candidate pools
        // This probes storing nodes (close to chunk addresses) to get their topology views
        // of merkle candidates (close to midpoint addresses) and builds consensus
        let candidate_pools = self
            .build_consensus_candidate_pools(midpoint_proofs, &addresses, depth, data_type, data_size)
            .await?;
        info!(
            "Built {} consensus-based candidate pools",
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
