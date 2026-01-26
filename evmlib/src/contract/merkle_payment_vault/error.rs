// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::common::{Address, U256};
use crate::contract::merkle_payment_vault::interface::IMerklePaymentVault;
use crate::retry;
use alloy::sol;

// Define ERC20 error types from OpenZeppelin's ERC20 implementation
// These errors can be thrown by the ANT token during transferFrom calls
sol! {
    #[allow(missing_docs)]
    #[derive(Debug, PartialEq, Eq)]
    library ERC20Errors {
        error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed);
        error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed);
        error ERC20InvalidReceiver(address receiver);
        error ERC20InvalidSender(address sender);
        error ERC20InvalidSpender(address spender);
        error ERC20InvalidApprover(address approver);
    }
}

// Define SafeERC20 and Address library errors from OpenZeppelin
// These can be thrown when using SafeERC20.safeTransferFrom
sol! {
    #[allow(missing_docs)]
    #[derive(Debug, PartialEq, Eq)]
    library OpenZeppelinErrors {
        /// An operation with an ERC-20 token failed (SafeERC20)
        error SafeERC20FailedOperation(address token);
        /// A call to an address target failed (Address library)
        error FailedInnerCall();
        /// There's no code at target address (Address library)
        error AddressEmptyCode(address target);
        /// Insufficient balance for address - used in native token transfers (Address library)
        error AddressInsufficientBalance(address account);
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Contract error: {0}")]
    Contract(#[from] alloy::contract::Error),
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error("Merkle payments address not configured for this network")]
    MerklePaymentsAddressNotConfigured,
    #[error(transparent)]
    Transaction(#[from] retry::TransactionError),

    // Smart contract custom errors (from IMerklePaymentVault.json)
    #[error("ANT token address is null")]
    AntTokenNull,
    #[error("Batch limit exceeded")]
    BatchLimitExceeded,
    #[error("Merkle tree depth {depth} exceeds maximum allowed depth {max}")]
    DepthTooLarge { depth: u8, max: u8 },
    #[error("Grace period not over")]
    GracePeriodNotOver,
    #[error("Invalid amount")]
    InvalidAmount,
    #[error("Invalid Chainlink price")]
    InvalidChainlinkPrice,
    #[error("Invalid input length")]
    InvalidInputLength,
    #[error("Invalid quote hash")]
    InvalidQuoteHash,
    #[error("Invalid recipients count")]
    InvalidRecipientsCount,
    #[error("Invalid root")]
    InvalidRoot,
    #[error("Invalid tree depth")]
    InvalidTreeDepth,
    #[error("Payment already exists for pool hash: {0}")]
    PaymentAlreadyExists(String),
    #[error("Payment not found for pool hash: {0}")]
    PaymentNotFound(String),
    #[error("Price feed address is null")]
    PriceFeedNull,
    #[error("Root already paid")]
    RootAlreadyPaid,
    #[error("Sequencer is down")]
    SequencerDown,
    #[error("Wrong candidate count in pool {pool_idx}: expected {expected}, got {got}")]
    WrongCandidateCount {
        pool_idx: u64,
        expected: u64,
        got: u64,
    },
    #[error("Wrong pool count: expected {expected}, got {got}")]
    WrongPoolCount { expected: u64, got: u64 },

    // ERC20 token errors (from ANT token during transferFrom)
    #[error(
        "ERC20: insufficient allowance for spender {spender} (has {allowance}, needs {needed})"
    )]
    Erc20InsufficientAllowance {
        spender: Address,
        allowance: U256,
        needed: U256,
    },
    #[error("ERC20: insufficient balance for sender {sender} (has {balance}, needs {needed})")]
    Erc20InsufficientBalance {
        sender: Address,
        balance: U256,
        needed: U256,
    },
    #[error("ERC20: invalid receiver address {receiver} (cannot transfer to zero address)")]
    Erc20InvalidReceiver { receiver: Address },
    #[error("ERC20: invalid sender address {sender}")]
    Erc20InvalidSender { sender: Address },
    #[error("ERC20: invalid spender address {spender}")]
    Erc20InvalidSpender { spender: Address },
    #[error("ERC20: invalid approver address {approver}")]
    Erc20InvalidApprover { approver: Address },

    // SafeERC20 and Address library errors (from OpenZeppelin)
    #[error("SafeERC20: operation failed for token {token}")]
    SafeErc20FailedOperation { token: Address },
    #[error("Address: inner call failed")]
    FailedInnerCall,
    #[error("Address: no code at target address {target}")]
    AddressEmptyCode { target: Address },
    #[error("Address: insufficient balance for account {account}")]
    AddressInsufficientBalance { account: Address },
}

impl Error {
    /// Try to decode a contract error from revert data
    ///
    /// This attempts to decode errors from:
    /// 1. MerklePaymentVault contract errors
    /// 2. ERC20 token errors (from ANT token during transferFrom calls)
    /// 3. OpenZeppelin library errors (SafeERC20, Address)
    pub(crate) fn try_decode_revert(data: &[u8]) -> Option<Self> {
        use alloy::sol_types::SolInterface;

        // The revert data should start with the 4-byte selector followed by the error data
        if data.len() < 4 {
            return None;
        }

        let selector: [u8; 4] = data[..4].try_into().ok()?;
        let error_data = &data[4..];

        // Try to decode as IMerklePaymentVaultErrors
        if let Ok(contract_error) =
            IMerklePaymentVault::IMerklePaymentVaultErrors::abi_decode_raw(selector, error_data)
        {
            return Some(Self::from_contract_error(contract_error));
        }

        // Try to decode as ERC20 errors (from ANT token during transferFrom)
        if let Ok(erc20_error) =
            ERC20Errors::ERC20ErrorsErrors::abi_decode_raw(selector, error_data)
        {
            return Some(Self::from_erc20_error(erc20_error));
        }

        // Try to decode as OpenZeppelin library errors (SafeERC20, Address)
        if let Ok(oz_error) =
            OpenZeppelinErrors::OpenZeppelinErrorsErrors::abi_decode_raw(selector, error_data)
        {
            return Some(Self::from_openzeppelin_error(oz_error));
        }

        None
    }

    /// Convert a decoded OpenZeppelin library error to our Error type
    fn from_openzeppelin_error(error: OpenZeppelinErrors::OpenZeppelinErrorsErrors) -> Self {
        use OpenZeppelinErrors::OpenZeppelinErrorsErrors;

        match error {
            OpenZeppelinErrorsErrors::SafeERC20FailedOperation(e) => {
                Self::SafeErc20FailedOperation { token: e.token }
            }
            OpenZeppelinErrorsErrors::FailedInnerCall(_) => Self::FailedInnerCall,
            OpenZeppelinErrorsErrors::AddressEmptyCode(e) => {
                Self::AddressEmptyCode { target: e.target }
            }
            OpenZeppelinErrorsErrors::AddressInsufficientBalance(e) => {
                Self::AddressInsufficientBalance { account: e.account }
            }
        }
    }

    /// Convert a decoded ERC20 error to our Error type
    fn from_erc20_error(error: ERC20Errors::ERC20ErrorsErrors) -> Self {
        use ERC20Errors::ERC20ErrorsErrors;

        match error {
            ERC20ErrorsErrors::ERC20InsufficientAllowance(e) => Self::Erc20InsufficientAllowance {
                spender: e.spender,
                allowance: e.allowance,
                needed: e.needed,
            },
            ERC20ErrorsErrors::ERC20InsufficientBalance(e) => Self::Erc20InsufficientBalance {
                sender: e.sender,
                balance: e.balance,
                needed: e.needed,
            },
            ERC20ErrorsErrors::ERC20InvalidReceiver(e) => Self::Erc20InvalidReceiver {
                receiver: e.receiver,
            },
            ERC20ErrorsErrors::ERC20InvalidSender(e) => Self::Erc20InvalidSender {
                sender: e.sender,
            },
            ERC20ErrorsErrors::ERC20InvalidSpender(e) => Self::Erc20InvalidSpender {
                spender: e.spender,
            },
            ERC20ErrorsErrors::ERC20InvalidApprover(e) => Self::Erc20InvalidApprover {
                approver: e.approver,
            },
        }
    }

    /// Convert a decoded contract error to our Error type
    fn from_contract_error(error: IMerklePaymentVault::IMerklePaymentVaultErrors) -> Self {
        use IMerklePaymentVault::IMerklePaymentVaultErrors;

        match error {
            IMerklePaymentVaultErrors::AntTokenNull(_) => Self::AntTokenNull,
            IMerklePaymentVaultErrors::BatchLimitExceeded(_) => Self::BatchLimitExceeded,
            IMerklePaymentVaultErrors::DepthTooLarge(e) => Self::DepthTooLarge {
                depth: e.depth,
                max: e.max,
            },
            IMerklePaymentVaultErrors::GracePeriodNotOver(_) => Self::GracePeriodNotOver,
            IMerklePaymentVaultErrors::InvalidAmount(_) => Self::InvalidAmount,
            IMerklePaymentVaultErrors::InvalidChainlinkPrice(_) => Self::InvalidChainlinkPrice,
            IMerklePaymentVaultErrors::InvalidInputLength(_) => Self::InvalidInputLength,
            IMerklePaymentVaultErrors::InvalidQuoteHash(_) => Self::InvalidQuoteHash,
            IMerklePaymentVaultErrors::InvalidRecipientsCount(_) => Self::InvalidRecipientsCount,
            IMerklePaymentVaultErrors::InvalidRoot(_) => Self::InvalidRoot,
            IMerklePaymentVaultErrors::InvalidTreeDepth(_) => Self::InvalidTreeDepth,
            IMerklePaymentVaultErrors::PaymentAlreadyExists(e) => {
                Self::PaymentAlreadyExists(hex::encode(e.poolHash))
            }
            IMerklePaymentVaultErrors::PaymentNotFound(e) => {
                Self::PaymentNotFound(hex::encode(e.poolHash))
            }
            IMerklePaymentVaultErrors::PriceFeedNull(_) => Self::PriceFeedNull,
            IMerklePaymentVaultErrors::RootAlreadyPaid(_) => Self::RootAlreadyPaid,
            IMerklePaymentVaultErrors::SequencerDown(_) => Self::SequencerDown,
            IMerklePaymentVaultErrors::WrongCandidateCount(e) => Self::WrongCandidateCount {
                pool_idx: e.poolIdx.try_into().unwrap_or(u64::MAX),
                expected: e.expected.try_into().unwrap_or(u64::MAX),
                got: e.got.try_into().unwrap_or(u64::MAX),
            },
            IMerklePaymentVaultErrors::WrongPoolCount(e) => Self::WrongPoolCount {
                expected: e.expected.try_into().unwrap_or(u64::MAX),
                got: e.got.try_into().unwrap_or(u64::MAX),
            },
        }
    }
}
