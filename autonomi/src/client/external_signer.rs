// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Unified External Signer API for Autonomi payments
//!
//! This module provides a simple, serializable API for integrating with external transaction
//! signers (MetaMask, Ledger, WalletConnect, mobile wallets, etc.).
//!
//! # Flow
//!
//! 1. **Prepare**: Call `client.prepare_payment()` to get a `PreparedPayment` struct
//! 2. **Serialize**: Send the `PreparedPayment` to your frontend/wallet (it's fully JSON-serializable)
//! 3. **Sign**: Execute each transaction in `prepared.transactions` using your wallet
//! 4. **Complete**: Call `Client::complete_payment()` with the signing results
//! 5. **Upload**: Use the returned `PaymentReceipt` with upload functions
//!
//! # Example
//!
//! ```rust,ignore
//! // 1. Prepare payment (no wallet needed)
//! let prepared = client.prepare_payment(
//!     DataTypes::Chunk,
//!     addresses.iter().cloned(),
//!     MAX_CHUNK_SIZE,
//! ).await?;
//!
//! // 2. Serialize and send to frontend
//! let json = serde_json::to_string(&prepared)?;
//!
//! // 3. Frontend executes transactions and returns results...
//!
//! // 4. Complete payment
//! let receipt = Client::complete_payment(prepared, results)?;
//!
//! // 5. Upload with receipt
//! client.upload_with_receipt(data, receipt).await?;
//! ```

use crate::client::merkle_payments::{MerklePaymentError, MerklePaymentReceipt, PreparedMerklePayment};
use crate::client::payment::{receipt_from_store_quotes, Receipt};
use crate::client::quote::{CostError, DataTypes};
use crate::Client;
use ant_evm::{AttoTokens, EvmNetwork, QuotePayment};
use evmlib::common::Amount;
use evmlib::utils::http_provider;
use serde::{Deserialize, Serialize};
use xor_name::XorName;

/// Threshold for using Merkle payments vs regular payments
pub const MERKLE_PAYMENT_THRESHOLD: usize = 64;

/// Re-export low-level calldata functions for advanced users
pub use evmlib::external_signer::*;

// ============================================================================
// Types
// ============================================================================

/// Unified payment preparation for external signers
///
/// This struct is fully JSON-serializable and contains everything
/// an external wallet needs to execute the payment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedPayment {
    /// Unique session ID for this payment
    pub session_id: String,

    /// Whether this uses Merkle (bulk) or Regular (per-quote) payments
    pub payment_kind: PaymentKind,

    /// Total estimated cost in atto tokens (as decimal string for JS BigInt compatibility)
    pub total_cost: String,

    /// Number of data items being paid for
    pub item_count: usize,

    /// EVM transactions to execute (in order)
    /// First is always token approval (if needed), rest are payments
    pub transactions: Vec<PreparedTransaction>,

    /// Contract addresses used (for verification by frontend)
    pub contracts: ContractAddresses,

    /// Network configuration
    pub network: NetworkInfo,

    /// Internal data needed for completion (opaque JSON blob)
    /// External signers should pass this back unchanged
    #[serde(rename = "_internal")]
    internal: serde_json::Value,
}

/// Payment kind - Merkle (bulk) or Regular (per-quote)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentKind {
    /// Regular per-quote payments (for smaller uploads)
    Regular,
    /// Merkle tree batch payments (for larger uploads, more efficient)
    Merkle,
}

/// A single EVM transaction ready for signing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedTransaction {
    /// Human-readable description
    pub description: String,

    /// Transaction index (for ordering)
    pub index: u32,

    /// Target contract address (0x-prefixed)
    pub to: String,

    /// Transaction calldata (0x-prefixed hex)
    pub calldata: String,

    /// Suggested gas limit (estimate + 20% buffer)
    pub gas_limit: u64,

    /// Transaction purpose
    pub tx_type: TransactionType,
}

/// Transaction purpose/type
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransactionType {
    /// ERC20 approve transaction (must complete before payments)
    Approve {
        /// Spender address (0x-prefixed)
        spender: String,
        /// Amount to approve as decimal string
        amount: String,
    },
    /// Regular batch payment
    Payment {
        /// Quote hashes included in this batch (0x-prefixed)
        quote_hashes: Vec<String>,
    },
    /// Merkle tree payment
    MerklePayment {
        /// Merkle tree depth
        depth: u8,
        /// Number of candidate pools
        pool_count: usize,
        /// Payment timestamp (unix seconds)
        timestamp: u64,
    },
}

/// Contract addresses for verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractAddresses {
    /// Payment token (ANT) contract address
    pub payment_token: String,
    /// Regular payment vault contract address
    pub payment_vault: String,
    /// Merkle payment vault contract address (if available)
    pub merkle_payment_vault: Option<String>,
}

/// Network information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// EVM chain ID
    pub chain_id: u64,
    /// RPC URL for the network
    pub rpc_url: String,
    /// Human-readable network name
    pub name: String,
}

/// Result to pass back after external signing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPaymentResult {
    /// Transaction hash (0x-prefixed)
    pub tx_hash: String,

    /// Transaction index that was signed
    pub tx_index: u32,

    /// For Merkle payments: parsed event data
    /// Can be omitted if you call `parse_merkle_event_from_receipt` to get it
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_event: Option<MerklePaymentEvent>,
}

/// Merkle payment event data (from MerklePaymentMade event)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePaymentEvent {
    /// Winner pool hash (0x-prefixed, 64 hex chars = 32 bytes)
    pub winner_pool_hash: String,
    /// Amount paid as decimal string
    pub amount_paid: String,
}

/// Unified receipt for uploads - works with both payment types
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PaymentReceipt {
    /// Regular payment receipt
    Regular(Receipt),
    /// Merkle payment receipt
    Merkle(MerklePaymentReceipt),
}

// ============================================================================
// Internal State Types (serialized in _internal field)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InternalPaymentState {
    kind: PaymentKind,
    regular: Option<RegularPaymentState>,
    merkle: Option<MerklePaymentState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RegularPaymentState {
    /// Pre-computed receipt (ready to use after payment confirms)
    receipt: Receipt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MerklePaymentState {
    /// The prepared merkle payment data
    prepared: PreparedMerklePayment,
}

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during external signer operations
#[derive(Debug, thiserror::Error)]
pub enum ExternalSignerError {
    #[error("Cost estimation error: {0}")]
    Cost(#[from] CostError),
    #[error("Merkle payment error: {0}")]
    Merkle(#[from] MerklePaymentError),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Invalid internal state: {0}")]
    InvalidState(String),
    #[error("Missing transaction result for index {0}")]
    MissingResult(u32),
    #[error("Missing merkle event in result")]
    MissingMerkleEvent,
    #[error("Invalid winner pool hash: {0}")]
    InvalidPoolHash(String),
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),
    #[error("Merkle payment vault not available on this network")]
    MerkleVaultNotAvailable,
    #[error("Contract error: {0}")]
    Contract(String),
}

// ============================================================================
// Client Methods
// ============================================================================

impl Client {
    /// Prepare a payment for external signing
    ///
    /// Automatically selects Merkle vs Regular based on item count:
    /// - `< 64` items: Regular per-quote payments
    /// - `>= 64` items: Merkle tree batch payment (more efficient)
    ///
    /// Returns a fully serializable `PreparedPayment` that contains everything
    /// an external wallet needs to execute the payment.
    ///
    /// # Arguments
    /// * `data_type` - The type of data being uploaded
    /// * `content_addrs` - Iterator of content addresses to pay for
    /// * `data_size` - Size of each data item (typically MAX_CHUNK_SIZE for chunks)
    ///
    /// # Example
    /// ```rust,ignore
    /// let prepared = client.prepare_payment(
    ///     DataTypes::Chunk,
    ///     addresses.iter().cloned(),
    ///     MAX_CHUNK_SIZE,
    /// ).await?;
    ///
    /// // Serialize to JSON for frontend
    /// let json = serde_json::to_string(&prepared)?;
    /// ```
    pub async fn prepare_payment(
        &self,
        data_type: DataTypes,
        content_addrs: impl Iterator<Item = XorName> + Clone,
        data_size: usize,
    ) -> Result<PreparedPayment, ExternalSignerError> {
        let addrs_vec: Vec<XorName> = content_addrs.clone().collect();
        let item_count = addrs_vec.len();

        // Auto-select payment kind based on threshold
        if item_count >= MERKLE_PAYMENT_THRESHOLD {
            self.prepare_merkle_payment_internal(data_type, addrs_vec, data_size)
                .await
        } else {
            self.prepare_regular_payment_internal(data_type, addrs_vec, data_size)
                .await
        }
    }

    /// Force prepare a Regular (per-quote) payment regardless of item count
    pub async fn prepare_regular_payment(
        &self,
        data_type: DataTypes,
        content_addrs: impl Iterator<Item = XorName>,
        data_size: usize,
    ) -> Result<PreparedPayment, ExternalSignerError> {
        let addrs_vec: Vec<XorName> = content_addrs.collect();
        self.prepare_regular_payment_internal(data_type, addrs_vec, data_size)
            .await
    }

    /// Force prepare a Merkle payment regardless of item count
    pub async fn prepare_merkle_payment(
        &self,
        data_type: DataTypes,
        content_addrs: impl Iterator<Item = XorName>,
        data_size: usize,
    ) -> Result<PreparedPayment, ExternalSignerError> {
        let addrs_vec: Vec<XorName> = content_addrs.collect();
        self.prepare_merkle_payment_internal(data_type, addrs_vec, data_size)
            .await
    }

    /// Complete payment after external signing
    ///
    /// This is a pure function - no network calls needed.
    /// The internal state from PreparedPayment is used to generate proofs.
    ///
    /// # Arguments
    /// * `prepared` - The prepared payment from `prepare_payment()`
    /// * `results` - Results from signing each transaction
    ///
    /// # Returns
    /// * `PaymentReceipt` - Receipt that can be used for uploads
    pub fn complete_payment(
        prepared: PreparedPayment,
        results: Vec<SignedPaymentResult>,
    ) -> Result<PaymentReceipt, ExternalSignerError> {
        // Deserialize internal state
        let internal: InternalPaymentState = serde_json::from_value(prepared.internal)
            .map_err(|e: serde_json::Error| ExternalSignerError::InvalidState(e.to_string()))?;

        match internal.kind {
            PaymentKind::Regular => {
                let state = internal.regular.ok_or_else(|| {
                    ExternalSignerError::InvalidState("Missing regular payment state".to_string())
                })?;
                Self::complete_regular_payment(state, results)
            }
            PaymentKind::Merkle => {
                let state = internal.merkle.ok_or_else(|| {
                    ExternalSignerError::InvalidState("Missing merkle payment state".to_string())
                })?;
                Self::complete_merkle_payment(state, results)
            }
        }
    }

    // ------------------------------------------------------------------------
    // Internal: Regular Payment Preparation
    // ------------------------------------------------------------------------

    async fn prepare_regular_payment_internal(
        &self,
        data_type: DataTypes,
        addrs: Vec<XorName>,
        data_size: usize,
    ) -> Result<PreparedPayment, ExternalSignerError> {
        let item_count = addrs.len();
        let session_id = generate_session_id();

        // Get quotes from network
        let content_addrs = addrs.iter().map(|addr| (*addr, data_size));
        let quotes = self.get_store_quotes(data_type, content_addrs).await?;

        // Pre-compute the receipt (we'll return this after payment confirms)
        let receipt = receipt_from_store_quotes(quotes.clone());

        // Get payment data
        let payments: Vec<QuotePayment> = quotes.payments();
        let total_amount: Amount = payments.iter().map(|(_, _, amt)| *amt).sum();

        // Build transactions
        let network = self.evm_network();
        let contracts = build_contract_addresses(network);
        let network_info = build_network_info(network);

        let mut transactions = Vec::new();
        let mut tx_index = 0u32;

        // Build calldata using evmlib
        let calldata_result = evmlib::external_signer::pay_for_quotes_calldata(network, payments)
            .map_err(|e| ExternalSignerError::Contract(e.to_string()))?;

        // Token approval transaction (if needed)
        if calldata_result.approve_amount > Amount::ZERO {
            let (approve_calldata, approve_to) = evmlib::external_signer::approve_to_spend_tokens_calldata(
                network,
                calldata_result.approve_spender,
                calldata_result.approve_amount,
            );

            transactions.push(PreparedTransaction {
                description: "Approve ANT token spending".to_string(),
                index: tx_index,
                to: format!("{approve_to:?}"),
                calldata: format!("0x{}", hex::encode(&approve_calldata)),
                gas_limit: 60_000, // ERC20 approve is typically ~46k gas
                tx_type: TransactionType::Approve {
                    spender: format!("{:?}", calldata_result.approve_spender),
                    amount: calldata_result.approve_amount.to_string(),
                },
            });
            tx_index += 1;
        }

        // Payment transactions (batched)
        for (calldata, quote_hashes) in calldata_result.batched_calldata_map {
            let quote_hashes_hex: Vec<String> = quote_hashes
                .iter()
                .map(|h| format!("0x{}", hex::encode(h)))
                .collect();

            let to_addr = calldata_result.to;
            transactions.push(PreparedTransaction {
                description: format!("Pay for {} quotes", quote_hashes.len()),
                index: tx_index,
                to: format!("{to_addr:?}"),
                calldata: format!("0x{}", hex::encode(&calldata)),
                gas_limit: estimate_payment_gas(quote_hashes.len()),
                tx_type: TransactionType::Payment {
                    quote_hashes: quote_hashes_hex,
                },
            });
            tx_index += 1;
        }

        // Build internal state with pre-computed receipt
        let internal = InternalPaymentState {
            kind: PaymentKind::Regular,
            regular: Some(RegularPaymentState { receipt }),
            merkle: None,
        };

        Ok(PreparedPayment {
            session_id,
            payment_kind: PaymentKind::Regular,
            total_cost: total_amount.to_string(),
            item_count,
            transactions,
            contracts,
            network: network_info,
            internal: serde_json::to_value(internal)
                .map_err(|e: serde_json::Error| ExternalSignerError::Serialization(e.to_string()))?,
        })
    }

    // ------------------------------------------------------------------------
    // Internal: Merkle Payment Preparation
    // ------------------------------------------------------------------------

    async fn prepare_merkle_payment_internal(
        &self,
        data_type: DataTypes,
        addrs: Vec<XorName>,
        data_size: usize,
    ) -> Result<PreparedPayment, ExternalSignerError> {
        let item_count = addrs.len();
        let session_id = generate_session_id();

        // Check if merkle vault is available
        let network = self.evm_network();
        let merkle_vault_address = network
            .merkle_payments_address()
            .ok_or(ExternalSignerError::MerkleVaultNotAvailable)?;

        // Prepare merkle payment using existing method
        let prepared = self
            .prepare_merkle_payment_external(data_type, addrs.iter().cloned(), data_size)
            .await?;

        // Estimate cost
        let estimated_cost = self.estimate_merkle_cost(&prepared).await?;

        // Build transactions
        let contracts = build_contract_addresses(network);
        let network_info = build_network_info(network);

        let mut transactions = Vec::new();
        let mut tx_index = 0u32;

        // Token approval transaction
        let (approve_calldata, approve_to) = evmlib::external_signer::approve_to_spend_tokens_calldata(
            network,
            *merkle_vault_address,
            estimated_cost,
        );

        transactions.push(PreparedTransaction {
            description: "Approve ANT token spending for Merkle payment".to_string(),
            index: tx_index,
            to: format!("{approve_to:?}"),
            calldata: format!("0x{}", hex::encode(&approve_calldata)),
            gas_limit: 60_000,
            tx_type: TransactionType::Approve {
                spender: format!("{merkle_vault_address:?}"),
                amount: estimated_cost.to_string(),
            },
        });
        tx_index += 1;

        // Merkle payment transaction
        let merkle_calldata = self.build_merkle_payment_calldata(&prepared)?;

        transactions.push(PreparedTransaction {
            description: format!(
                "Merkle tree payment (depth={}, {} pools)",
                prepared.depth,
                prepared.pool_commitments.len()
            ),
            index: tx_index,
            to: format!("{merkle_vault_address:?}"),
            calldata: format!("0x{}", hex::encode(&merkle_calldata)),
            gas_limit: estimate_merkle_payment_gas(prepared.depth, prepared.pool_commitments.len()),
            tx_type: TransactionType::MerklePayment {
                depth: prepared.depth,
                pool_count: prepared.pool_commitments.len(),
                timestamp: prepared.merkle_payment_timestamp,
            },
        });

        // Build internal state
        let internal = InternalPaymentState {
            kind: PaymentKind::Merkle,
            regular: None,
            merkle: Some(MerklePaymentState { prepared }),
        };

        Ok(PreparedPayment {
            session_id,
            payment_kind: PaymentKind::Merkle,
            total_cost: estimated_cost.to_string(),
            item_count,
            transactions,
            contracts,
            network: network_info,
            internal: serde_json::to_value(internal)
                .map_err(|e: serde_json::Error| ExternalSignerError::Serialization(e.to_string()))?,
        })
    }

    /// Estimate merkle payment cost
    async fn estimate_merkle_cost(
        &self,
        prepared: &PreparedMerklePayment,
    ) -> Result<Amount, ExternalSignerError> {
        let network = self.evm_network();
        let merkle_vault_address = network
            .merkle_payments_address()
            .ok_or(ExternalSignerError::MerkleVaultNotAvailable)?;

        let provider = http_provider(network.rpc_url().clone());
        let handler = evmlib::contract::merkle_payment_vault::handler::MerklePaymentVaultHandler::new(
            *merkle_vault_address,
            provider,
        );

        let cost = handler
            .estimate_merkle_tree_cost(
                prepared.depth,
                prepared.pool_commitments.clone(),
                prepared.merkle_payment_timestamp,
            )
            .await
            .map_err(|e| ExternalSignerError::Contract(e.to_string()))?;

        Ok(cost)
    }

    /// Build merkle payment calldata
    fn build_merkle_payment_calldata(
        &self,
        prepared: &PreparedMerklePayment,
    ) -> Result<Vec<u8>, ExternalSignerError> {
        let network = self.evm_network();
        let merkle_vault_address = network
            .merkle_payments_address()
            .ok_or(ExternalSignerError::MerkleVaultNotAvailable)?;

        let provider = http_provider(network.rpc_url().clone());
        let handler = evmlib::contract::merkle_payment_vault::handler::MerklePaymentVaultHandler::new(
            *merkle_vault_address,
            provider,
        );

        // Use the contract interface to generate calldata
        use evmlib::contract::merkle_payment_vault::interface::IMerklePaymentVault;

        let pool_commitments: Vec<IMerklePaymentVault::PoolCommitment> = prepared
            .pool_commitments
            .iter()
            .map(|pc| pc.clone().into())
            .collect();

        let calldata = handler
            .contract
            .payForMerkleTree(
                prepared.depth,
                pool_commitments,
                prepared.merkle_payment_timestamp,
            )
            .calldata()
            .to_vec();

        Ok(calldata)
    }

    // ------------------------------------------------------------------------
    // Internal: Payment Completion
    // ------------------------------------------------------------------------

    fn complete_regular_payment(
        state: RegularPaymentState,
        _results: Vec<SignedPaymentResult>,
    ) -> Result<PaymentReceipt, ExternalSignerError> {
        // The receipt was pre-computed during preparation
        // Once payment transactions confirm, the receipt is valid
        Ok(PaymentReceipt::Regular(state.receipt))
    }

    fn complete_merkle_payment(
        state: MerklePaymentState,
        results: Vec<SignedPaymentResult>,
    ) -> Result<PaymentReceipt, ExternalSignerError> {
        // Find the merkle payment result (should be the last transaction)
        let merkle_result = results
            .iter()
            .find(|r| r.merkle_event.is_some())
            .or_else(|| results.last())
            .ok_or(ExternalSignerError::MissingResult(1))?;

        let event = merkle_result
            .merkle_event
            .as_ref()
            .ok_or(ExternalSignerError::MissingMerkleEvent)?;

        // Parse winner pool hash
        let winner_pool_hash = parse_pool_hash(&event.winner_pool_hash)?;

        // Parse amount
        let amount: Amount = event
            .amount_paid
            .parse()
            .map_err(|_| ExternalSignerError::InvalidAmount(event.amount_paid.clone()))?;

        // Complete using existing method
        let receipt = Client::complete_merkle_payment_external(
            state.prepared,
            winner_pool_hash,
            AttoTokens::from_atto(amount),
        )?;

        Ok(PaymentReceipt::Merkle(receipt))
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse a MerklePaymentMade event from transaction receipt logs
///
/// Use this if your wallet doesn't automatically parse events.
/// The event signature is: `MerklePaymentMade(bytes32 indexed winnerPoolHash, uint8 depth, uint256 totalAmount, uint64 merklePaymentTimestamp)`
///
/// # Arguments
/// * `logs` - The logs from the transaction receipt
///
/// # Returns
/// * `MerklePaymentEvent` - Parsed event data
pub fn parse_merkle_event_from_logs(logs: &[EvmLog]) -> Result<MerklePaymentEvent, ExternalSignerError> {
    // MerklePaymentMade event signature
    // keccak256("MerklePaymentMade(bytes32,uint8,uint256,uint64)")
    // The first topic is the event signature, second is the indexed winnerPoolHash

    for log in logs {
        if log.topics.is_empty() {
            continue;
        }

        // The first topic is the event signature
        // The second topic (topics[1]) is the indexed winnerPoolHash
        if log.topics.len() >= 2 {
            // Check if this looks like our event (has at least 2 topics and data)
            let winner_pool_hash = &log.topics[1];

            // Parse totalAmount from data (first 32 bytes after depth which is padded)
            // Layout: depth (32 bytes padded) + totalAmount (32 bytes) + timestamp (32 bytes padded)
            if log.data.len() >= 64 {
                // Skip depth (32 bytes), read totalAmount (next 32 bytes)
                let amount_bytes = &log.data[32..64];
                let amount = Amount::from_be_slice(amount_bytes);

                return Ok(MerklePaymentEvent {
                    winner_pool_hash: winner_pool_hash.clone(),
                    amount_paid: amount.to_string(),
                });
            }
        }
    }

    Err(ExternalSignerError::InvalidState(
        "MerklePaymentMade event not found in logs".to_string(),
    ))
}

/// Simple EVM log structure for event parsing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvmLog {
    /// Log topics (first is event signature, rest are indexed params)
    pub topics: Vec<String>,
    /// Log data (non-indexed params, hex-encoded)
    pub data: Vec<u8>,
}

fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("pay_{timestamp}")
}

fn build_contract_addresses(network: &EvmNetwork) -> ContractAddresses {
    let payment_token = network.payment_token_address();
    let payment_vault = network.data_payments_address();
    ContractAddresses {
        payment_token: format!("{payment_token:?}"),
        payment_vault: format!("{payment_vault:?}"),
        merkle_payment_vault: network
            .merkle_payments_address()
            .map(|a| format!("{a:?}")),
    }
}

fn build_network_info(network: &EvmNetwork) -> NetworkInfo {
    // Chain IDs for known networks
    let chain_id = match network {
        EvmNetwork::ArbitrumOne => 42161,
        EvmNetwork::ArbitrumSepoliaTest => 421614,
        EvmNetwork::Custom(_) => 0, // Custom networks don't have a known chain ID
    };

    NetworkInfo {
        chain_id,
        rpc_url: network.rpc_url().to_string(),
        name: network.identifier().to_string(),
    }
}

fn estimate_payment_gas(quote_count: usize) -> u64 {
    // Base gas + per-quote gas
    // Each quote transfer is roughly 50k gas
    let base = 50_000u64;
    let per_quote = 50_000u64;
    let estimate = base + (quote_count as u64 * per_quote);
    // Add 20% buffer
    estimate + (estimate / 5)
}

fn estimate_merkle_payment_gas(depth: u8, pool_count: usize) -> u64 {
    // Base gas + per-pool gas + depth factor
    let base = 100_000u64;
    let per_pool = 30_000u64;
    let depth_factor = 10_000u64 * (depth as u64);
    let estimate = base + (pool_count as u64 * per_pool) + depth_factor;
    // Add 20% buffer
    estimate + (estimate / 5)
}

fn parse_pool_hash(hex_str: &str) -> Result<[u8; 32], ExternalSignerError> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)
        .map_err(|_| ExternalSignerError::InvalidPoolHash(hex_str.to_string()))?;

    if bytes.len() != 32 {
        return Err(ExternalSignerError::InvalidPoolHash(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ============================================================================
// File/Directory Payment Preparation
// ============================================================================

/// Prepared file payment - contains both payment info and encrypted data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedFilePayment {
    /// The prepared payment (ready for external signing)
    pub payment: PreparedPayment,

    /// Encrypted file data needed for upload after payment
    /// This is stored as serialized bytes to keep it opaque
    #[serde(with = "encrypted_chunks_serde")]
    pub encrypted_chunks: EncryptedChunks,

    /// Number of chunks that already exist on the network (no payment needed)
    pub already_paid_count: usize,
}

/// Encrypted chunks data for upload
#[derive(Clone, Debug)]
pub struct EncryptedChunks {
    /// Data map chunk (must be uploaded)
    pub data_map_chunk: ant_protocol::storage::Chunk,
    /// Content chunks (must be uploaded)
    pub chunks: Vec<ant_protocol::storage::Chunk>,
}

// Custom serde for EncryptedChunks (serialize as bytes)
mod encrypted_chunks_serde {
    use super::EncryptedChunks;
    use ant_protocol::storage::Chunk;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct ChunkData {
        data_map: Vec<u8>,
        chunks: Vec<Vec<u8>>,
    }

    pub fn serialize<S>(chunks: &EncryptedChunks, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = ChunkData {
            data_map: chunks.data_map_chunk.value().to_vec(),
            chunks: chunks.chunks.iter().map(|c| c.value().to_vec()).collect(),
        };
        data.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<EncryptedChunks, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = ChunkData::deserialize(deserializer)?;
        Ok(EncryptedChunks {
            data_map_chunk: Chunk::new(bytes::Bytes::from(data.data_map)),
            chunks: data
                .chunks
                .into_iter()
                .map(|c| Chunk::new(bytes::Bytes::from(c)))
                .collect(),
        })
    }
}

impl Client {
    /// Prepare payment for a file upload with external signing
    ///
    /// This encrypts the file, checks which chunks need payment, and returns
    /// a `PreparedFilePayment` containing both the payment info and encrypted data.
    ///
    /// # Arguments
    /// * `file_path` - Path to the file to upload
    ///
    /// # Returns
    /// * `PreparedFilePayment` - Contains PreparedPayment for signing and EncryptedChunks for upload
    ///
    /// # Example
    /// ```rust,ignore
    /// // 1. Prepare file payment
    /// let prepared = client.prepare_file_payment("/path/to/file.zip").await?;
    /// println!("Cost: {} ATTO for {} chunks", prepared.payment.total_cost, prepared.payment.item_count);
    ///
    /// // 2. Execute transactions with external wallet...
    ///
    /// // 3. Complete payment
    /// let receipt = Client::complete_payment(prepared.payment, results)?;
    ///
    /// // 4. Upload chunks using receipt
    /// // (upload logic using prepared.encrypted_chunks)
    /// ```
    pub async fn prepare_file_payment(
        &self,
        file_path: impl AsRef<std::path::Path>,
    ) -> Result<PreparedFilePayment, ExternalSignerError> {
        let file_path = file_path.as_ref();

        // Read and encrypt the file
        let data = tokio::fs::read(file_path)
            .await
            .map_err(|e| ExternalSignerError::InvalidState(format!("Failed to read file: {e}")))?;

        let (data_map_chunk, chunks) = crate::self_encryption::encrypt(bytes::Bytes::from(data))
            .map_err(|e| ExternalSignerError::InvalidState(format!("Encryption failed: {e}")))?;

        // Collect all chunk addresses
        let mut all_addrs: Vec<XorName> = chunks.iter().map(|c| *c.name()).collect();
        all_addrs.push(*data_map_chunk.name());

        // Check which chunks already exist (dedup first)
        let unique_addrs: std::collections::HashSet<XorName> = all_addrs.iter().copied().collect();
        let addrs_to_check: Vec<_> = unique_addrs.into_iter().collect();

        // Check existence on network
        let network_addrs: Vec<_> = addrs_to_check
            .iter()
            .map(|xn| crate::networking::NetworkAddress::from(
                crate::client::data_types::chunk::ChunkAddress::new(*xn),
            ))
            .collect();

        let existing = self.check_records_exist_batch(&network_addrs, 16).await;

        let existing_set: std::collections::HashSet<XorName> = existing
            .into_iter()
            .filter_map(|addr| addr.xorname())
            .collect();

        // Filter to only addresses that need payment
        let addrs_to_pay: Vec<XorName> = addrs_to_check
            .into_iter()
            .filter(|addr| !existing_set.contains(addr))
            .collect();

        let already_paid_count = all_addrs.len() - addrs_to_pay.len();

        // Prepare payment for non-existing chunks
        let payment = if addrs_to_pay.is_empty() {
            // All chunks already exist - create empty payment
            PreparedPayment {
                session_id: generate_session_id(),
                payment_kind: PaymentKind::Regular,
                total_cost: "0".to_string(),
                item_count: 0,
                transactions: vec![],
                contracts: build_contract_addresses(self.evm_network()),
                network: build_network_info(self.evm_network()),
                internal: serde_json::to_value(InternalPaymentState {
                    kind: PaymentKind::Regular,
                    regular: Some(RegularPaymentState {
                        receipt: Receipt::new(),
                    }),
                    merkle: None,
                })
                .map_err(|e: serde_json::Error| ExternalSignerError::Serialization(e.to_string()))?,
            }
        } else {
            self.prepare_payment(
                DataTypes::Chunk,
                addrs_to_pay.into_iter(),
                crate::self_encryption::MAX_CHUNK_SIZE,
            )
            .await?
        };

        Ok(PreparedFilePayment {
            payment,
            encrypted_chunks: EncryptedChunks {
                data_map_chunk,
                chunks,
            },
            already_paid_count,
        })
    }

    /// Prepare payment for a directory upload with external signing
    ///
    /// This walks the directory, encrypts all files, checks which chunks need payment,
    /// and returns a `PreparedFilePayment` containing both the payment info and encrypted data.
    ///
    /// # Arguments
    /// * `dir_path` - Path to the directory to upload
    ///
    /// # Returns
    /// * `PreparedFilePayment` - Contains PreparedPayment for signing and EncryptedChunks for upload
    ///
    /// # Note
    /// For complex directory structures, consider using `prepare_payment` directly with
    /// pre-computed chunk addresses for more control over the process.
    pub async fn prepare_dir_payment(
        &self,
        dir_path: impl AsRef<std::path::Path>,
    ) -> Result<PreparedFilePayment, ExternalSignerError> {
        let dir_path = dir_path.as_ref();

        // Walk directory and encrypt each file
        let mut all_chunks: Vec<ant_protocol::storage::Chunk> = Vec::new();
        let mut all_data_maps: Vec<ant_protocol::storage::Chunk> = Vec::new();

        for entry in walkdir::WalkDir::new(dir_path) {
            let entry = entry.map_err(|e| {
                ExternalSignerError::InvalidState(format!("Failed to walk directory: {e}"))
            })?;

            if !entry.file_type().is_file() {
                continue;
            }

            // Read and encrypt each file
            let file_data = tokio::fs::read(entry.path()).await.map_err(|e| {
                ExternalSignerError::InvalidState(format!(
                    "Failed to read file {}: {e}",
                    entry.path().display()
                ))
            })?;

            let (data_map_chunk, chunks) =
                crate::self_encryption::encrypt(bytes::Bytes::from(file_data)).map_err(|e| {
                    ExternalSignerError::InvalidState(format!(
                        "Encryption failed for {}: {e}",
                        entry.path().display()
                    ))
                })?;

            all_data_maps.push(data_map_chunk);
            all_chunks.extend(chunks);
        }

        if all_chunks.is_empty() && all_data_maps.is_empty() {
            return Err(ExternalSignerError::InvalidState(
                "No files found in directory".to_string(),
            ));
        }

        // Collect all chunk addresses
        let mut all_addrs: Vec<XorName> = all_chunks.iter().map(|c| *c.name()).collect();
        for dm in &all_data_maps {
            all_addrs.push(*dm.name());
        }

        // Check which chunks already exist
        let unique_addrs: std::collections::HashSet<XorName> = all_addrs.iter().copied().collect();
        let addrs_to_check: Vec<_> = unique_addrs.into_iter().collect();

        let network_addrs: Vec<_> = addrs_to_check
            .iter()
            .map(|xn| {
                crate::networking::NetworkAddress::from(
                    crate::client::data_types::chunk::ChunkAddress::new(*xn),
                )
            })
            .collect();

        let existing = self.check_records_exist_batch(&network_addrs, 16).await;

        let existing_set: std::collections::HashSet<XorName> = existing
            .into_iter()
            .filter_map(|addr| addr.xorname())
            .collect();

        let addrs_to_pay: Vec<XorName> = addrs_to_check
            .into_iter()
            .filter(|addr| !existing_set.contains(addr))
            .collect();

        let already_paid_count = all_addrs.len() - addrs_to_pay.len();

        // Prepare payment
        let payment = if addrs_to_pay.is_empty() {
            PreparedPayment {
                session_id: generate_session_id(),
                payment_kind: PaymentKind::Regular,
                total_cost: "0".to_string(),
                item_count: 0,
                transactions: vec![],
                contracts: build_contract_addresses(self.evm_network()),
                network: build_network_info(self.evm_network()),
                internal: serde_json::to_value(InternalPaymentState {
                    kind: PaymentKind::Regular,
                    regular: Some(RegularPaymentState {
                        receipt: Receipt::new(),
                    }),
                    merkle: None,
                })
                .map_err(|e: serde_json::Error| ExternalSignerError::Serialization(e.to_string()))?,
            }
        } else {
            self.prepare_payment(
                DataTypes::Chunk,
                addrs_to_pay.into_iter(),
                crate::self_encryption::MAX_CHUNK_SIZE,
            )
            .await?
        };

        // Use first data map as the primary one (for single file, this is correct;
        // for directories, caller would typically create an archive)
        let data_map_chunk = all_data_maps
            .into_iter()
            .next()
            .unwrap_or_else(|| ant_protocol::storage::Chunk::new(bytes::Bytes::new()));

        Ok(PreparedFilePayment {
            payment,
            encrypted_chunks: EncryptedChunks {
                data_map_chunk,
                chunks: all_chunks,
            },
            already_paid_count,
        })
    }
}

// ============================================================================
// Legacy API (for backward compatibility)
// ============================================================================

/// Get quotes for data - legacy API for backward compatibility
///
/// Returns a cost map, data payments to be executed and a list of free (already paid for) chunks.
impl Client {
    pub async fn get_quotes_for_content_addresses(
        &self,
        data_type: DataTypes,
        content_addrs: impl Iterator<Item = (XorName, usize)> + Clone,
    ) -> Result<
        (
            std::collections::HashMap<XorName, super::quote::QuoteForAddress>,
            Vec<QuotePayment>,
            Vec<XorName>,
        ),
        super::PutError,
    > {
        let quote = self
            .get_store_quotes(data_type, content_addrs.clone())
            .await?;
        let payments = quote.payments();
        let free_chunks: Vec<_> = content_addrs
            .filter(|(addr, _)| !quote.0.contains_key(addr))
            .collect();
        let quotes_per_addr: std::collections::HashMap<_, _> = quote.0.into_iter().collect();

        Ok((
            quotes_per_addr,
            payments,
            free_chunks.iter().map(|(addr, _)| *addr).collect(),
        ))
    }
}

/// Encrypts data as chunks - legacy API
pub fn encrypt_data(
    data: bytes::Bytes,
) -> Result<(ant_protocol::storage::Chunk, Vec<ant_protocol::storage::Chunk>), crate::self_encryption::Error>
{
    let now = std::time::Instant::now();
    let result = crate::self_encryption::encrypt(data)?;

    debug!("Encryption took: {:.2?}", now.elapsed());

    Ok((result.0, result.1))
}
