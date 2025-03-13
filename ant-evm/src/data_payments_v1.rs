// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::ProofOfPayment;
use evmlib::{
    common::{Address as RewardsAddress, QuoteHash},
    quoting_metrics::QuotingMetrics,
};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use super::data_payments::{EncodedPeerId, PaymentQuote};

/// Old ProofOfPayment for retro compatibility
/// The proof of payment for a data payment
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ProofOfPaymentV1 {
    pub peer_quotes: Vec<(EncodedPeerId, PaymentQuote)>,
}

impl From<ProofOfPayment> for ProofOfPaymentV1 {
    fn from(proof: ProofOfPayment) -> Self {
        ProofOfPaymentV1 {
            peer_quotes: proof
                .peer_quotes
                .into_iter()
                .map(|(encoded_peer_id, payment_quote, _)| (encoded_peer_id, payment_quote))
                .collect(),
        }
    }
}

impl ProofOfPaymentV1 {
    /// returns a short digest of the proof of payment to use for verification
    pub fn digest(&self) -> Vec<(QuoteHash, QuotingMetrics, RewardsAddress)> {
        self.peer_quotes
            .clone()
            .into_iter()
            .map(|(_, quote)| (quote.hash(), quote.quoting_metrics, quote.rewards_address))
            .collect()
    }

    /// returns the list of payees
    pub fn payees(&self) -> Vec<PeerId> {
        self.peer_quotes
            .iter()
            .filter_map(|(peer_id, _)| peer_id.to_peer_id().ok())
            .collect()
    }

    /// has the quote expired
    pub fn has_expired(&self) -> bool {
        self.peer_quotes
            .iter()
            .any(|(_, quote)| quote.has_expired())
    }

    /// Returns all quotes by given peer id
    pub fn quotes_by_peer(&self, peer_id: &PeerId) -> Vec<&PaymentQuote> {
        self.peer_quotes
            .iter()
            .filter_map(|(_id, quote)| {
                if let Ok(quote_peer_id) = quote.peer_id() {
                    if *peer_id == quote_peer_id {
                        return Some(quote);
                    }
                }
                None
            })
            .collect()
    }

    /// verifies the proof of payment is valid for the given peer id
    pub fn verify_for(&self, peer_id: PeerId) -> bool {
        // make sure I am in the list of payees
        if !self.payees().contains(&peer_id) {
            warn!("Payment does not contain node peer id");
            debug!("Payment contains peer ids: {:?}", self.payees());
            debug!("Node peer id: {:?}", peer_id);
            return false;
        }

        // verify all signatures
        for (encoded_peer_id, quote) in self.peer_quotes.iter() {
            let peer_id = match encoded_peer_id.to_peer_id() {
                Ok(peer_id) => peer_id,
                Err(e) => {
                    warn!("Invalid encoded peer id: {e}");
                    return false;
                }
            };
            if !quote.check_is_signed_by_claimed_peer(peer_id) {
                warn!("Payment is not signed by claimed peer");
                return false;
            }
        }
        true
    }

    /// Verifies whether all quotes were made for the expected data type.
    pub fn verify_data_type(&self, data_type: u32) -> bool {
        for (_, quote) in self.peer_quotes.iter() {
            if quote.quoting_metrics.data_type != data_type {
                return false;
            }
        }

        true
    }
}
