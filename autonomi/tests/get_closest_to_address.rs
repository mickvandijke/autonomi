// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use ant_bootstrap::InitialPeersConfig;
use ant_evm::EvmNetwork;
use ant_logging::LogBuilder;
use ant_protocol::NetworkAddress;
use autonomi::{Client, ClientConfig};
use eyre::Result;
use libp2p::kad::PeerInfo;
use libp2p::{kad::Record, PeerId};
use rand::{thread_rng, RngCore};
use serial_test::serial;
use std::str::FromStr;

#[tokio::test]
#[serial]
async fn test_get_closest_to_address_with_specific_peer_id() -> Result<()> {
    let _log_appender_guard = LogBuilder::init_single_threaded_tokio_test();

    let client = Client::init().await?;

    // Use the specific peer ID provided by the user
    let peer_id_str = "12D3KooWLdEihufgzRdskTqhPbAANssCrW4wmE8ZdwNcNvhbXLje";
    let peer_id = PeerId::from_str(peer_id_str)?;

    // Get closest peers to this address
    let closest_peers = client
        .get_closest_to_address(NetworkAddress::from(peer_id))
        .await?;

    // Print results for verification
    println!("Target PeerId: {peer_id}");
    println!("Found {} closest peers:", closest_peers.len());

    for (index, peer_info) in closest_peers.iter().enumerate() {
        println!(
            "  {}. PeerId: {}, Addrs: {:?}",
            index + 1,
            peer_info.peer_id,
            peer_info.addrs
        );
    }

    // Verify we got some peers back
    assert!(
        !closest_peers.is_empty(),
        "Should return at least one closest peer"
    );

    // Check if the target peer ID itself is in the results
    let target_peer_in_results = closest_peers
        .iter()
        .any(|peer_info| peer_info.peer_id == peer_id);

    if target_peer_in_results {
        println!("✓ Target peer ID {peer_id} found in closest peers results");
    } else {
        println!("✗ Target peer ID {peer_id} not found in closest peers results");
    }

    // The test passes regardless of whether the target peer is in results,
    // as this depends on network topology and whether the peer is actually online
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_get_closest_to_address_with_specific_peer_id_and_bootstrap_to_that_peer_id(
) -> Result<()> {
    let _log_appender_guard = LogBuilder::init_single_threaded_tokio_test();

    let local = false;

    let config = ClientConfig {
        init_peers_config: InitialPeersConfig {
            first: false,
            local,
            ignore_cache: true,
            addrs: vec!["/ip4/165.232.105.244/udp/58159/quic-v1/p2p/12D3KooWQPKWQoaGASa2ThF6otajk8BpQKT3od1ATV4dkQJmkGrz".parse()?],
            network_contacts_url: vec![],
            bootstrap_cache_dir: None,
        },
        evm_network: EvmNetwork::new(local).unwrap_or_default(),
        strategy: Default::default(),
        network_id: None,
    };

    let client = Client::init_with_config(config).await?;

    // Use the specific peer ID provided by the user
    let peer_id_str = "12D3KooWQPKWQoaGASa2ThF6otajk8BpQKT3od1ATV4dkQJmkGrz";
    let peer_id = PeerId::from_str(peer_id_str)?;

    // Get closest peers to this address
    let closest_peers = client
        .get_closest_to_address(NetworkAddress::from(peer_id))
        .await?;

    // Print results for verification
    println!("Target PeerId: {peer_id}");
    println!("Found {} closest peers:", closest_peers.len());

    for (index, peer_info) in closest_peers.iter().enumerate() {
        println!(
            "  {}. PeerId: {}, Addrs: {:?}",
            index + 1,
            peer_info.peer_id,
            peer_info.addrs
        );
    }

    // Verify we got some peers back
    assert!(
        !closest_peers.is_empty(),
        "Should return at least one closest peer"
    );

    // Check if the target peer ID itself is in the results
    let target_peer_in_results = closest_peers
        .iter()
        .any(|peer_info| peer_info.peer_id == peer_id);

    if target_peer_in_results {
        println!("✓ Target peer ID {peer_id} found in closest peers results");
    } else {
        println!("✗ Target peer ID {peer_id} not found in closest peers results");
    }

    // The test passes regardless of whether the target peer is in results,
    // as this depends on network topology and whether the peer is actually online
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_put_record_with_specific_peer_id_and_bootstrap_to_that_peer_id() -> Result<()> {
    let _log_appender_guard = LogBuilder::init_single_threaded_tokio_test();

    let local = false;
    let addrs = vec!["/ip4/138.68.141.192/udp/60495/quic-v1/p2p/12D3KooWPK1N3ziyykJf9GFr9j8wbDt23awvw2sQbJFWQDsdzB56".parse()?];

    let config = ClientConfig {
        init_peers_config: InitialPeersConfig {
            first: false,
            local,
            ignore_cache: true,
            addrs: addrs.clone(),
            network_contacts_url: vec![],
            bootstrap_cache_dir: None,
        },
        evm_network: EvmNetwork::new(local).unwrap_or_default(),
        strategy: Default::default(),
        network_id: None,
    };

    let client = Client::init_with_config(config).await?;

    // Use the specific peer ID provided by the user
    let peer_id_str = "12D3KooWPK1N3ziyykJf9GFr9j8wbDt23awvw2sQbJFWQDsdzB56";
    let peer_id = PeerId::from_str(peer_id_str)?;

    // Create random record
    let mut rng = thread_rng();
    let mut key = vec![0u8; 32];
    let mut value = vec![0u8; 64];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut value);
    let record = Record {
        key: key.into(),
        value,
        publisher: None,
        expires: None,
    };

    let to = PeerInfo { peer_id, addrs };

    // Put record to peer
    let res = client.put_record(record, vec![to]).await;

    println!("{:?}", res);

    assert!(res.is_ok());

    Ok(())
}
