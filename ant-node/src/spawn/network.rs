use crate::spawn::node::NodeSpawner;
use crate::RunningNode;
use ant_evm::{EvmNetwork, RewardsAddress};
use libp2p::Multiaddr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

pub struct NetworkSpawner {
    evm_network: EvmNetwork,
    rewards_address: RewardsAddress,
    local: bool,
    upnp: bool,
    root_dir: Option<PathBuf>,
    size: usize,
}

impl NetworkSpawner {
    pub fn new() -> Self {
        Self {
            evm_network: Default::default(),
            rewards_address: Default::default(),
            local: false,
            upnp: false,
            root_dir: None,
            size: 5,
        }
    }

    /// Sets the EVM network.
    pub fn with_evm_network(mut self, evm_network: EvmNetwork) -> Self {
        self.evm_network = evm_network;
        self
    }

    /// Sets the rewards address.
    pub fn with_rewards_address(mut self, rewards_address: RewardsAddress) -> Self {
        self.rewards_address = rewards_address;
        self
    }

    /// Sets the local mode value.
    pub fn with_local(mut self, value: bool) -> Self {
        self.local = value;
        self
    }

    /// Sets the UPnP value (automatic port forwarding).
    pub fn with_upnp(mut self, value: bool) -> Self {
        self.upnp = value;
        self
    }

    /// Sets the root directory for the nodes.
    pub fn with_root_dir(mut self, root_dir: Option<PathBuf>) -> Self {
        self.root_dir = root_dir;
        self
    }

    /// Sets the amount of nodes spawned in the network.
    pub fn with_size(mut self, size: usize) -> Self {
        self.size = size;
        self
    }

    pub async fn spawn(self) -> eyre::Result<SpawnedNetwork> {
        spawn_network(
            self.evm_network,
            self.rewards_address,
            self.local,
            self.upnp,
            self.root_dir,
            self.size,
        )
        .await
    }
}

impl Default for NetworkSpawner {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SpawnedNetwork {
    running_nodes: Vec<RunningNode>,
}

impl SpawnedNetwork {
    pub fn running_nodes(&self) -> &Vec<RunningNode> {
        &self.running_nodes
    }
}

async fn spawn_network(
    evm_network: EvmNetwork,
    rewards_address: RewardsAddress,
    local: bool,
    upnp: bool,
    root_dir: Option<PathBuf>,
    size: usize,
) -> eyre::Result<SpawnedNetwork> {
    let mut running_nodes: Vec<RunningNode> = vec![];

    for i in 0..size {
        let ip = match local {
            true => IpAddr::V4(Ipv4Addr::LOCALHOST),
            false => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };

        let socket_addr = SocketAddr::new(ip, 0);

        let mut initial_peers: Vec<Multiaddr> = vec![];

        for peer in running_nodes.iter() {
            if let Ok(listen_addrs) = peer.get_listen_addrs().await {
                initial_peers.extend(listen_addrs);
            }
        }

        let node = NodeSpawner::new()
            .with_socket_addr(socket_addr)
            .with_evm_network(evm_network.clone())
            .with_rewards_address(rewards_address)
            .with_initial_peers(initial_peers)
            .with_local(local)
            .with_upnp(upnp)
            .with_root_dir(root_dir.clone())
            .spawn()
            .await?;

        let listen_addrs = node.get_listen_addrs().await;

        info!(
            "Spawned node #{} with listen addresses: {:?}",
            i + 1,
            listen_addrs
        );

        running_nodes.push(node);
    }

    Ok(SpawnedNetwork { running_nodes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_evm::EvmTestnet;

    #[tokio::test]
    async fn test_spawn_network() {
        // start local Ethereum node
        let evm_testnet = EvmTestnet::new().await;
        let evm_network = evm_testnet.to_network();
        let network_size = 20;

        let spawned_network = NetworkSpawner::new()
            .with_evm_network(evm_network)
            .with_size(network_size)
            .spawn()
            .await
            .unwrap();

        assert_eq!(spawned_network.running_nodes().len(), network_size);

        // Validate each node's listen addresses are not empty
        for node in spawned_network.running_nodes() {
            let listen_addrs = node.get_listen_addrs().await.unwrap();

            assert!(!listen_addrs.is_empty());
        }
    }
}
