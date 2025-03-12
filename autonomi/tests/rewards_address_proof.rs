use ant_node::spawn::network_spawner::NetworkSpawner;
use autonomi::{Client, ClientConfig, ClientOperatingStrategy, RewardsAddress};
use evmlib::testnet::Testnet;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
#[ignore] // Works locally but not in CI
async fn get_rewards_address_proof() {
    let evm_testnet = Testnet::new().await;
    let evm_network = evm_testnet.to_network();

    let rewards_address = RewardsAddress::new([1u8; 20]);

    let network = NetworkSpawner::new()
        .with_evm_network(evm_network.clone())
        .with_rewards_address(rewards_address)
        .with_local(true)
        .with_size(20)
        .spawn()
        .await
        .unwrap();

    let node = network.running_nodes().first().unwrap();
    let bootstrap_peer = node
        .get_listen_addrs_with_peer_id()
        .await
        .unwrap()
        .first()
        .unwrap()
        .clone();

    let config = ClientConfig {
        local: true,
        peers: Some(vec![bootstrap_peer]),
        evm_network,
        strategy: ClientOperatingStrategy::default(),
    };

    let client = Client::init_with_config(config).await.unwrap();

    sleep(Duration::from_secs(5)).await;

    let peer_id = node.peer_id();
    let rewards_address_proof = client.get_rewards_address_for_peer(peer_id).await.unwrap();
    println!("{rewards_address_proof:?}");
    assert_eq!(rewards_address_proof.rewards_address, rewards_address);
}
