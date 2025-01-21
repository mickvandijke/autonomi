use ant_evm::EvmTestnet;
use ant_node::spawn::network::NetworkSpawner;
use std::time::Duration;
use tokio::time::sleep;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_env("RUST_LOG"))
        .init();

    // start local Ethereum node
    let evm_testnet = EvmTestnet::new().await;
    let evm_network = evm_testnet.to_network();
    let network_size = 2;

    let running_network = NetworkSpawner::new()
        .with_evm_network(evm_network)
        .with_local(true)
        .with_size(network_size)
        .spawn()
        .await
        .unwrap();

    assert_eq!(running_network.running_nodes().len(), network_size);

    // Validate each node's listen addresses are not empty
    for node in running_network.running_nodes() {
        let listen_addrs = node.get_listen_addrs().await.unwrap();

        assert!(!listen_addrs.is_empty());
    }

    // Wait for nodes to dial each other
    sleep(Duration::from_secs(20)).await;

    // TODO: Validate that all nodes know each other
    for node in running_network.running_nodes() {
        let known_peers = node.get_swarm_local_state().await.unwrap().connected_peers;

        println!("Known peers: {known_peers:?}");

        // TODO: nodes do not know each other..
    }

    running_network.shutdown();
}
