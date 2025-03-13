// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Client;
use crate::client::high_level::files::FILE_UPLOAD_BATCH_SIZE;
use crate::client::utils::process_tasks_with_max_concurrency;
use ant_evm::payment_vault::get_market_price;
use ant_evm::{Amount, PaymentQuote, QuotePayment, QuotingMetrics, RewardsAddressProof};
use ant_networking::{Network, NetworkError};
pub use ant_protocol::storage::DataTypes;
use ant_protocol::{storage::ChunkAddress, NetworkAddress, CLOSE_GROUP_SIZE};
use libp2p::PeerId;
use std::collections::HashMap;
use xor_name::XorName;

// todo: limit depends per RPC endpoint. We should make this configurable
// todo: test the limit for the Arbitrum One public RPC endpoint
// Working limit of the Arbitrum Sepolia public RPC endpoint
const GET_MARKET_PRICE_BATCH_LIMIT: usize = 2000;

/// A quote for a single address
#[derive(Debug, Clone, Default)]
pub struct QuoteForAddress(
    ///             PeerId of the peer
    ///             |       Signed quote from the peer
    ///             |       |             Store cost at this address
    ///             |       |             |       Relayer node to reward if any
    ///             |       |             |       |
    ///             V       V             V       V
    pub(crate) Vec<(PeerId, PaymentQuote, Amount, Option<RewardsAddressProof>)>,
);

impl QuoteForAddress {
    pub fn price(&self) -> Amount {
        self.0.iter().map(|(_, _, price, _)| price).sum()
    }
}

/// A quote for many addresses
pub struct StoreQuote(pub HashMap<XorName, QuoteForAddress>);

impl StoreQuote {
    pub fn price(&self) -> Amount {
        self.0.values().map(|quote| quote.price()).sum()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn payments(&self) -> Vec<QuotePayment> {
        let mut quote_payments = vec![];
        for (_address, quote) in self.0.iter() {
            for (_peer, quote, price, relay_addr_proof) in quote.0.iter() {
                let relay_addr = relay_addr_proof.clone().map(|proof| proof.rewards_address);
                quote_payments.push((quote.hash(), quote.rewards_address, relay_addr, *price));
            }
        }
        quote_payments
    }
}

/// Errors that can occur during the cost calculation.
#[derive(Debug, thiserror::Error)]
pub enum CostError {
    #[error("Failed to self-encrypt data.")]
    SelfEncryption(#[from] crate::self_encryption::Error),
    #[error("Could not get store quote for: {0:?} after several retries")]
    CouldNotGetStoreQuote(XorName),
    #[error("Could not get store costs: {0:?}")]
    CouldNotGetStoreCosts(NetworkError),
    #[error("Not enough node quotes for {0:?}, got: {1:?} and need at least {2:?}")]
    NotEnoughNodeQuotes(XorName, usize, usize),
    #[error("Failed to serialize {0}")]
    Serialization(String),
    #[error("Market price error: {0:?}")]
    MarketPriceError(#[from] ant_evm::payment_vault::error::Error),
    #[error("Received invalid cost")]
    InvalidCost,
}

impl Client {
    /// Get raw quotes from nodes.
    /// These quotes do not include actual record prices.
    /// You will likely want to use `get_store_quotes` instead.
    pub async fn get_raw_quotes(
        &self,
        data_type: DataTypes,
        content_addrs: impl Iterator<Item = (XorName, usize)>,
    ) -> Vec<
        Result<
            (
                XorName,
                Vec<(PeerId, PaymentQuote, Option<RewardsAddressProof>)>,
            ),
            CostError,
        >,
    > {
        let futures: Vec<_> = content_addrs
            .into_iter()
            .map(|(content_addr, data_size)| {
                fetch_store_quote_with_retries(
                    &self.network,
                    content_addr,
                    data_type.get_index(),
                    data_size,
                )
            })
            .collect();

        process_tasks_with_max_concurrency(futures, *FILE_UPLOAD_BATCH_SIZE).await
    }

    pub async fn get_store_quotes(
        &self,
        data_type: DataTypes,
        content_addrs: impl Iterator<Item = (XorName, usize)>,
    ) -> Result<StoreQuote, CostError> {
        let raw_quotes_per_addr = self.get_raw_quotes(data_type, content_addrs).await;
        let mut all_quotes = Vec::new();

        for result in raw_quotes_per_addr {
            let (content_addr, mut raw_quotes) = result?;
            debug!(
                "fetched raw quotes for content_addr: {content_addr}, with {} quotes.",
                raw_quotes.len()
            );

            if raw_quotes.is_empty() {
                debug!("content_addr: {content_addr} is already paid for. No need to fetch market price.");
                continue;
            }

            let target_addr = NetworkAddress::from_chunk_address(ChunkAddress::new(content_addr));

            // Only keep the quotes of the 5 closest nodes
            raw_quotes.sort_by_key(|(peer_id, _, _)| {
                NetworkAddress::from_peer(*peer_id).distance(&target_addr)
            });
            raw_quotes.truncate(CLOSE_GROUP_SIZE);

            for (peer_id, quote, relay_addr) in raw_quotes.into_iter() {
                all_quotes.push((content_addr, peer_id, quote, relay_addr));
            }
        }

        let mut all_prices = Vec::new();

        for chunk in all_quotes.chunks(GET_MARKET_PRICE_BATCH_LIMIT) {
            let quoting_metrics: Vec<QuotingMetrics> = chunk
                .iter()
                .map(|(_, _, quote, _)| quote.quoting_metrics.clone())
                .collect();

            debug!(
                "Getting market prices for {} quoting metrics",
                quoting_metrics.len()
            );

            let batch_prices = get_market_price(&self.evm_network, quoting_metrics).await?;

            all_prices.extend(batch_prices);
        }

        let quotes_with_prices: Vec<(
            XorName,
            PeerId,
            PaymentQuote,
            Amount,
            Option<RewardsAddressProof>,
        )> = all_quotes
            .into_iter()
            .zip(all_prices.into_iter())
            .map(|((content_addr, peer_id, quote, relay_addr), price)| {
                (content_addr, peer_id, quote, price, relay_addr)
            })
            .collect();

        let mut quotes_per_addr: HashMap<XorName, QuoteForAddress> = HashMap::new();

        for (content_addr, peer_id, quote, price, relay_addr) in quotes_with_prices {
            let entry = quotes_per_addr.entry(content_addr).or_default();
            entry.0.push((peer_id, quote, price, relay_addr));
            entry.0.sort_by_key(|(_, _, price, _)| *price);
        }

        let mut quotes_to_pay_per_addr = HashMap::new();

        const MINIMUM_QUOTES_TO_PAY: usize = 5;

        for (content_addr, quotes) in quotes_per_addr {
            if quotes.0.len() >= MINIMUM_QUOTES_TO_PAY {
                let (p1, q1, _, r1) = &quotes.0[0];
                let (p2, q2, _, r2) = &quotes.0[1];

                quotes_to_pay_per_addr.insert(
                    content_addr,
                    QuoteForAddress(vec![
                        (*p1, q1.clone(), Amount::ZERO, r1.clone()),
                        (*p2, q2.clone(), Amount::ZERO, r2.clone()),
                        quotes.0[2].clone(),
                        quotes.0[3].clone(),
                        quotes.0[4].clone(),
                    ]),
                );
            } else {
                return Err(CostError::NotEnoughNodeQuotes(
                    content_addr,
                    quotes.0.len(),
                    MINIMUM_QUOTES_TO_PAY,
                ));
            }
        }

        Ok(StoreQuote(quotes_to_pay_per_addr))
    }

    pub async fn get_rewards_address_for_peer(
        &self,
        peer_id: PeerId,
    ) -> Result<RewardsAddressProof, NetworkError> {
        self.network.get_rewards_address_with_proof(peer_id).await
    }
}

/// Fetch a store quote for a content address.
async fn fetch_store_quote(
    network: &Network,
    content_addr: XorName,
    data_type: u32,
    data_size: usize,
) -> Result<Vec<(PeerId, PaymentQuote, Option<RewardsAddressProof>)>, NetworkError> {
    network
        .get_store_quote_from_network(
            NetworkAddress::from_chunk_address(ChunkAddress::new(content_addr)),
            data_type,
            data_size,
            vec![],
        )
        .await
}

/// Fetch a store quote for a content address with a retry strategy.
async fn fetch_store_quote_with_retries(
    network: &Network,
    content_addr: XorName,
    data_type: u32,
    data_size: usize,
) -> Result<
    (
        XorName,
        Vec<(PeerId, PaymentQuote, Option<RewardsAddressProof>)>,
    ),
    CostError,
> {
    let mut retries = 0;

    loop {
        match fetch_store_quote(network, content_addr, data_type, data_size).await {
            Ok(quote) => {
                if quote.is_empty() {
                    // Empty quotes indicates the record already exists.
                    break Ok((content_addr, quote));
                }
                if quote.len() < CLOSE_GROUP_SIZE {
                    retries += 1;
                    error!("Error while fetching store quote: not enough quotes ({}/{CLOSE_GROUP_SIZE}), retry #{retries}, quotes {quote:?}",
                        quote.len());
                    if retries > 2 {
                        break Err(CostError::CouldNotGetStoreQuote(content_addr));
                    }
                }
                break Ok((content_addr, quote));
            }
            Err(err) if retries < 2 => {
                retries += 1;
                error!("Error while fetching store quote: {err:?}, retry #{retries}");
            }
            Err(err) => {
                error!(
                    "Error while fetching store quote: {err:?}, stopping after {retries} retries"
                );
                break Err(CostError::CouldNotGetStoreQuote(content_addr));
            }
        }
        // Shall have a sleep between retries to avoid choking the network.
        // This shall be rare to happen though.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
