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

    let network_size = 20;

    let running_network = NetworkSpawner::new()
        .with_evm_network(Default::default())
        .with_local(true)
        .with_size(network_size)
        .spawn()
        .await
        .unwrap();

    assert_eq!(running_network.running_nodes().len(), network_size);

    // Wait for nodes to dial each other
    sleep(Duration::from_secs(10)).await;

    // Validate that all nodes know each other
    for node in running_network.running_nodes() {
        let known_peers = node.get_swarm_local_state().await.unwrap().connected_peers;

        assert_eq!(known_peers.len(), network_size - 1);
    }

    running_network.shutdown();
}
