use ant_evm::RewardsAddress;
use libp2p::identity::Keypair;
use std::time::{SystemTime, UNIX_EPOCH};

const REWARDS_PROOF_VALID_FOR_SECS: u64 = 172800; // 172800 secs is 48 hours

/// Rewards address with expiration date and signature signed by the providing node.
pub struct RewardsAddressProof {
    pub rewards_address: RewardsAddress,
    pub date_expiration: u64,
    pub signature: Vec<u8>,
}

impl RewardsAddressProof {
    pub fn new(rewards_address: RewardsAddress, keypair: &Keypair) -> Self {
        let date_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Clock may have gone backwards")
            .as_secs();

        let date_expiration = date_now.saturating_add(REWARDS_PROOF_VALID_FOR_SECS);

        let mut bytes_to_sign = vec![];
        bytes_to_sign.extend_from_slice(rewards_address.as_slice());
        bytes_to_sign.extend_from_slice(&date_expiration.to_be_bytes());

        // Sign the data.
        // Should never fail.
        let signature = keypair
            .sign(bytes_to_sign.as_slice())
            .expect("Could not sign RewardsAddressProof");

        Self {
            rewards_address,
            date_expiration,
            signature,
        }
    }
}
