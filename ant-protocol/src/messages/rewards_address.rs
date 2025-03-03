use crate::time::time_in_secs_since_unix_epoch;
use ant_evm::RewardsAddress;
use libp2p::identity::Keypair;

const REWARDS_PROOF_VALID_FOR_SECS: u64 = 172800; // 172800 secs is 48 hours

/// Rewards address with expiration date and signature signed by the providing node.
pub struct RewardsAddressProof {
    /// Rewards address of the node.
    pub rewards_address: RewardsAddress,
    /// Expiration date of the rewards address proof.
    pub date_expiration: u64,
    /// pub key of the node.
    pub pub_key: Vec<u8>,
    /// The node's signature for the rewards address proof.
    pub signature: Vec<u8>,
}

impl RewardsAddressProof {
    pub fn sign_new(rewards_address: RewardsAddress, keypair: &Keypair) -> Self {
        let date_now = time_in_secs_since_unix_epoch();
        let date_expiration = date_now.saturating_add(REWARDS_PROOF_VALID_FOR_SECS);

        let mut payload = vec![];
        payload.extend_from_slice(rewards_address.as_slice());
        payload.extend_from_slice(&date_expiration.to_be_bytes());

        // Sign the data.
        // Should never fail.
        let signature = keypair
            .sign(payload.as_slice())
            .expect("Could not sign RewardsAddressProof");

        let pub_key = keypair.public().encode_protobuf();

        Self {
            rewards_address,
            date_expiration,
            pub_key,
            signature,
        }
    }

    /// Checks if the signature of the rewards address proof is valid.
    pub fn is_signature_valid(&self) -> bool {
        if let Ok(pub_key) =
            libp2p::identity::PublicKey::try_decode_protobuf(self.pub_key.as_slice())
        {
            // Verify the signature using the public key
            pub_key.verify(self.to_payload().as_slice(), &self.signature)
        } else {
            false // Return false if the public key cannot be decoded
        }
    }

    /// Checks if the rewards address proof is expired.
    pub fn is_expired(&self) -> bool {
        let date_now = time_in_secs_since_unix_epoch();
        self.date_expiration <= date_now
    }

    /// Returns the message payload.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut payload = vec![];
        payload.extend_from_slice(self.rewards_address.as_slice());
        payload.extend_from_slice(&self.date_expiration.to_be_bytes());
        payload
    }

    /// Converts the public key in the rewards address proof to a PeerId.
    ///
    /// Returns `None` if the public key is invalid.
    pub fn to_peer_id(&self) -> Option<libp2p::PeerId> {
        if let Ok(pub_key) =
            libp2p::identity::PublicKey::try_decode_protobuf(self.pub_key.as_slice())
        {
            return Some(pub_key.to_peer_id());
        }

        None
    }
}
