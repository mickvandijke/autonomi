// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Developer and analytics tools for network diagnostics.
//!
//! This module provides commands for debugging and analyzing the network from
//! the perspective of specific nodes. These commands require the `developer`
//! feature to be enabled on both the client (ant-cli) and the target node.

use crate::actions::{NetworkContext, connect_to_network};
use ant_evm::EvmWallet;
use ant_evm::merkle_payments::MerklePaymentProof;
use ant_protocol::storage::{Chunk, DataTypes, RecordKind, try_serialize_record};
use ant_protocol::NetworkAddress;
use autonomi::Bytes;
use autonomi::Client;
use autonomi::client::data_types::chunk::ChunkAddress;
use autonomi::client::data_types::graph::GraphEntryAddress;
use autonomi::client::merkle_payments::MerklePaymentReceipt;
use autonomi::networking::{Multiaddr, PeerId, PeerInfo};
use autonomi::PublicKey;
use color_eyre::{Result, eyre::eyre};
use libp2p::kad::Record;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Get the version of a node.
///
/// This command queries a specific node to retrieve its software version.
pub async fn node_version(node_addr: &str, network_context: NetworkContext) -> Result<()> {
    println!("Connecting to network...");
    let client = connect_to_network(network_context)
        .await
        .map_err(|(err, _exit_code)| err)?;

    // Resolve the node - either from multiaddr or by discovering PeerId
    let node_info = resolve_node(&client, node_addr).await?;
    let peer_id = node_info.peer_id;

    println!("Querying node {peer_id} for version...");
    println!();

    // Query the node for its version
    let version = client
        .get_node_version(node_info)
        .await
        .map_err(|e| eyre!("Failed to query node version: {e}"))?;

    println!("Node {peer_id}");
    println!("  Version: {version}");

    Ok(())
}

/// Query a specific node to get its network view of closest peers to a target address.
///
/// This command asks the specified node to perform an actual Kademlia network lookup
/// and returns the results from that node's network perspective.
pub async fn closest_peers(
    node_addr: &str,
    target: &str,
    num_peers: Option<usize>,
    compare: bool,
    network_context: NetworkContext,
) -> Result<()> {
    // Parse the target address (hex string)
    let target_addr = parse_target_address(target)?;

    println!("Connecting to network...");
    let client = connect_to_network(network_context)
        .await
        .map_err(|(err, _exit_code)| err)?;

    // Try to resolve the node - either from multiaddr or by discovering PeerId
    let node_info = resolve_node(&client, node_addr).await?;
    let peer_id = node_info.peer_id;

    println!("Querying node {peer_id} for closest peers to {target}...");

    // Perform the developer query
    let response = client
        .dev_get_closest_peers_from_node(node_info, target_addr.clone(), num_peers)
        .await
        .map_err(|e| eyre!("Failed to query node: {e}"))?;

    if compare {
        println!("Querying client's perspective...");
        println!();

        // Get the client's view of closest peers
        let client_peers = client
            .network()
            .get_closest_peers(target_addr.clone(), num_peers)
            .await
            .map_err(|e| eyre!("Failed to get client's closest peers: {e}"))?;

        display_comparison(&response, &client_peers, &target_addr, target, peer_id);
    } else {
        println!();
        display_node_results(&response, &target_addr, target);
    }

    Ok(())
}

/// Display results for the standard (non-comparison) mode.
fn display_node_results(
    response: &autonomi::networking::DevGetClosestPeersFromNetworkResponse,
    target_addr: &NetworkAddress,
    target: &str,
) {
    println!(
        "Closest peers to {} from node {}:",
        target, response.queried_node
    );
    println!();

    if response.peers.is_empty() {
        println!("  No peers found.");
    } else {
        println!(
            "  {:<4} {:<54} {:<15} Multiaddrs",
            "#", "PeerId", "Distance"
        );
        println!("  {}", "-".repeat(130));

        for (i, (peer_addr, multiaddrs)) in response.peers.iter().enumerate() {
            let distance = target_addr.distance(peer_addr);
            let distance_ilog2 = distance.ilog2().unwrap_or(0);

            let multiaddr_str = if multiaddrs.is_empty() {
                "N/A".to_string()
            } else {
                multiaddrs
                    .iter()
                    .map(|m: &Multiaddr| m.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };

            let peer_display = if let Some(peer_id) = peer_addr.as_peer_id() {
                peer_id.to_string()
            } else {
                peer_addr.to_string()
            };

            println!(
                "  {:<4} {:<54} {:<15} {}",
                i + 1,
                peer_display,
                distance_ilog2,
                multiaddr_str
            );
        }
    }

    println!();
    println!("Total: {} peers", response.peers.len());
}

/// Display comparison between node's view and client's view.
fn display_comparison(
    node_response: &autonomi::networking::DevGetClosestPeersFromNetworkResponse,
    client_peers: &[PeerInfo],
    target_addr: &NetworkAddress,
    target: &str,
    queried_peer_id: PeerId,
) {
    use std::collections::HashSet;

    // Build sets of peer IDs for comparison
    let node_peer_ids: HashSet<PeerId> = node_response
        .peers
        .iter()
        .filter_map(|(addr, _)| addr.as_peer_id())
        .collect();

    let client_peer_ids: HashSet<PeerId> = client_peers.iter().map(|p| p.peer_id).collect();

    let common: HashSet<PeerId> = node_peer_ids.intersection(&client_peer_ids).copied().collect();
    let node_only: HashSet<PeerId> = node_peer_ids.difference(&client_peer_ids).copied().collect();
    let client_only: HashSet<PeerId> = client_peer_ids.difference(&node_peer_ids).copied().collect();

    println!("Comparison of closest peers to {target}");
    println!("{}", "=".repeat(100));
    println!();

    // Summary
    println!("Summary:");
    println!("  Node's view:   {} peers", node_response.peers.len());
    println!("  Client's view: {} peers", client_peers.len());
    println!("  In common:     {} peers", common.len());
    println!("  Node only:     {} peers", node_only.len());
    println!("  Client only:   {} peers", client_only.len());
    println!();
    println!("  Note: Client's results include the queried node itself.");
    println!("        Nodes don't include themselves in their own results.");
    println!();

    // Node's perspective
    println!(
        "NODE'S PERSPECTIVE (from {}):",
        node_response.queried_node
    );
    println!(
        "  {:<4} {:<54} {:<10} Status",
        "#", "PeerId", "Distance"
    );
    println!("  {}", "-".repeat(80));

    for (i, (peer_addr, _)) in node_response.peers.iter().enumerate() {
        let distance = target_addr.distance(peer_addr);
        let distance_ilog2 = distance.ilog2().unwrap_or(0);

        let peer_display = if let Some(peer_id) = peer_addr.as_peer_id() {
            peer_id.to_string()
        } else {
            peer_addr.to_string()
        };

        let status = if let Some(peer_id) = peer_addr.as_peer_id() {
            if common.contains(&peer_id) {
                "common"
            } else {
                "node-only"
            }
        } else {
            "unknown"
        };

        println!(
            "  {:<4} {:<54} {:<10} {}",
            i + 1,
            peer_display,
            distance_ilog2,
            status
        );
    }

    println!();

    // Client's perspective
    println!("CLIENT'S PERSPECTIVE:");
    println!(
        "  {:<4} {:<54} {:<10} Status",
        "#", "PeerId", "Distance"
    );
    println!("  {}", "-".repeat(85));

    // Sort client peers by distance
    let mut sorted_client_peers: Vec<_> = client_peers.iter().collect();
    sorted_client_peers.sort_by_key(|p| {
        let addr = NetworkAddress::from(p.peer_id);
        target_addr.distance(&addr)
    });

    for (i, peer_info) in sorted_client_peers.iter().enumerate() {
        let peer_addr = NetworkAddress::from(peer_info.peer_id);
        let distance = target_addr.distance(&peer_addr);
        let distance_ilog2 = distance.ilog2().unwrap_or(0);

        let status = if peer_info.peer_id == queried_peer_id {
            "queried-node*"
        } else if common.contains(&peer_info.peer_id) {
            "common"
        } else {
            "client-only"
        };

        println!(
            "  {:<4} {:<54} {:<10} {}",
            i + 1,
            peer_info.peer_id,
            distance_ilog2,
            status
        );
    }

    println!();

    // Peers only in node's view
    if !node_only.is_empty() {
        println!("PEERS ONLY IN NODE'S VIEW:");
        for peer_id in &node_only {
            let peer_addr = NetworkAddress::from(*peer_id);
            let distance = target_addr.distance(&peer_addr);
            let distance_ilog2 = distance.ilog2().unwrap_or(0);
            println!("  {peer_id} (distance: {distance_ilog2})");
        }
        println!();
    }

    // Peers only in client's view
    if !client_only.is_empty() {
        println!("PEERS ONLY IN CLIENT'S VIEW:");
        for peer_id in &client_only {
            let peer_addr = NetworkAddress::from(*peer_id);
            let distance = target_addr.distance(&peer_addr);
            let distance_ilog2 = distance.ilog2().unwrap_or(0);
            if *peer_id == queried_peer_id {
                println!(
                    "  {peer_id} (distance: {distance_ilog2}) <- queried node (nodes don't include themselves)"
                );
            } else {
                println!("  {peer_id} (distance: {distance_ilog2})");
            }
        }
    }
}

/// Resolve a node identifier to PeerInfo.
///
/// Accepts either:
/// - A full multiaddr (e.g., /ip4/127.0.0.1/udp/12000/quic-v1/p2p/12D3KooW...)
/// - Just a PeerId (e.g., 12D3KooW...)
///
/// When only a PeerId is provided, the network is queried to discover the peer's addresses.
async fn resolve_node(client: &Client, node_addr: &str) -> Result<PeerInfo> {
    // First, try to parse as a PeerId directly
    if let Ok(peer_id) = node_addr.parse::<PeerId>() {
        println!("Discovering addresses for peer {peer_id}...");

        // Query the network to find this peer's addresses
        let peer_network_addr = NetworkAddress::from(peer_id);
        let closest_peers = client
            .network()
            .get_closest_peers(peer_network_addr, Some(20))
            .await
            .map_err(|e| eyre!("Failed to discover peer addresses: {e}"))?;

        // Look for our target peer in the results
        for peer_info in closest_peers {
            if peer_info.peer_id == peer_id {
                if peer_info.addrs.is_empty() {
                    return Err(eyre!(
                        "Found peer {peer_id} but no addresses are known. Try using a full multiaddr."
                    ));
                }
                println!("Found peer at: {}", peer_info.addrs[0]);
                return Ok(peer_info);
            }
        }

        return Err(eyre!(
            "Could not find peer {peer_id} in the network. Make sure the node is online and try using a full multiaddr."
        ));
    }

    // Try to parse as a multiaddr
    let multiaddr: Multiaddr = node_addr
        .parse()
        .map_err(|e| eyre!("Invalid node address. Expected PeerId or multiaddr: {e}"))?;

    // Extract PeerId from multiaddr
    let peer_id = extract_peer_id(&multiaddr)
        .ok_or_else(|| eyre!("Multiaddr must contain a peer ID (p2p component)"))?;

    Ok(PeerInfo {
        peer_id,
        addrs: vec![multiaddr],
    })
}

/// Extract PeerId from a Multiaddr
fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    // The multiaddr should end with /p2p/<peer_id>
    // We'll extract it from the string representation
    let addr_str = addr.to_string();
    let p2p_idx = addr_str.find("/p2p/")?;
    let peer_id_str = &addr_str[p2p_idx + 5..];
    peer_id_str.parse().ok()
}

/// Parse a target address from various formats.
///
/// Accepts:
/// - ChunkAddress (hex)
/// - PublicKey (hex) - for GraphEntry, Pointer, or Scratchpad addresses
/// - Raw 32-byte hex (XorName)
/// - PeerId
/// - NetworkAddress debug format (e.g., `NetworkAddress::RecordKey("...")`)
fn parse_target_address(target: &str) -> Result<NetworkAddress> {
    let hex_str = target.strip_prefix("0x").unwrap_or(target);

    // Try parsing as ChunkAddress first
    if let Ok(chunk_addr) = ChunkAddress::from_hex(target) {
        return Ok(NetworkAddress::from(chunk_addr));
    }

    // Try parsing as PublicKey (could be GraphEntry, Pointer, or Scratchpad)
    if let Ok(public_key) = PublicKey::from_hex(hex_str) {
        return Ok(NetworkAddress::from(GraphEntryAddress::new(public_key)));
    }

    // Try parsing from NetworkAddress debug format:
    // NetworkAddress::RecordKey("e9d7b3208bcb7ef566102027ca9a7f3ced7c0f8abf87c9bb0ef9130b625572f2") - (...)
    if let Some(start) = target.find('"')
        && let Some(end) = target[start + 1..].find('"')
    {
        let extracted_hex = &target[start + 1..start + 1 + end];
        if let Ok(chunk_addr) = ChunkAddress::from_hex(extracted_hex) {
            return Ok(NetworkAddress::from(chunk_addr));
        }
    }

    // Try to parse as raw hex bytes (xor_name)
    if let Ok(bytes) = hex::decode(hex_str)
        && bytes.len() == 32
    {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(NetworkAddress::from(xor_name::XorName(arr)));
    }

    // Try to parse as a PeerId
    if let Ok(peer_id) = target.parse::<PeerId>() {
        return Ok(NetworkAddress::from(peer_id));
    }

    Err(eyre!(
        "Invalid target address. Expected ChunkAddress, PublicKey, 32-byte hex, PeerId, or NetworkAddress debug format. Got: {target}"
    ))
}

/// Verify that nodes are running the version they report.
///
/// This command tests nodes by sending a Merkle payment request and analyzing
/// the error message to determine the actual code version running on the node.
///
/// The test exploits the fact that error messages changed between versions:
/// - Pre-2025.12.2.1: "Failed to get closest peers with majority knowledge to"
/// - 2025.12.2.1+: "Failed to get closest peers for"
pub async fn verify_version(
    node_addrs: Option<&str>,
    count: usize,
    proof_file: &str,
    network_context: NetworkContext,
) -> Result<()> {
    // Load the test proof from file
    println!("Loading test proof from: {proof_file}");
    let proof_path = Path::new(proof_file);
    if !proof_path.exists() {
        return Err(eyre!(
            "Proof file not found: {proof_file}\n\
             Create one first using: ant developer create-test-proof"
        ));
    }

    let proof_json = std::fs::read_to_string(proof_path)
        .map_err(|e| eyre!("Failed to read proof file: {e}"))?;
    let test_data: TestProofData = serde_json::from_str(&proof_json)
        .map_err(|e| eyre!("Failed to parse proof file: {e}"))?;

    // Parse the chunk address
    let chunk_addr_bytes = hex::decode(&test_data.chunk_address)
        .map_err(|e| eyre!("Failed to decode chunk address: {e}"))?;
    let mut addr_array = [0u8; 32];
    addr_array.copy_from_slice(&chunk_addr_bytes);
    let chunk_xorname = xor_name::XorName(addr_array);

    // Get the proof for this chunk
    let test_proof = test_data
        .receipt
        .proofs
        .get(&chunk_xorname)
        .ok_or_else(|| eyre!("Proof file doesn't contain proof for the stored chunk address"))?
        .clone();

    // Recreate the chunk from the stored data
    let chunk_data_bytes = hex::decode(&test_data.chunk_data)
        .map_err(|e| eyre!("Failed to decode chunk data: {e}"))?;
    let test_chunk = Chunk::new(Bytes::from(chunk_data_bytes));

    println!("Loaded proof for chunk: {}", test_data.chunk_address);
    println!();

    println!("Connecting to network...");
    let client = connect_to_network(network_context)
        .await
        .map_err(|(err, _exit_code)| err)?;

    // Get the list of nodes to test
    let nodes = if let Some(addrs) = node_addrs {
        // Parse comma-separated node addresses
        let mut nodes = Vec::new();
        for addr_str in addrs.split(',') {
            let addr_str = addr_str.trim();
            if addr_str.is_empty() {
                continue;
            }
            match resolve_node(&client, addr_str).await {
                Ok(node) => nodes.push(node),
                Err(e) => {
                    eprintln!("Warning: Failed to resolve {addr_str}: {e}");
                }
            }
        }
        if nodes.is_empty() {
            return Err(eyre!(
                "No valid nodes could be resolved from the provided addresses"
            ));
        }
        nodes
    } else {
        // Get random nodes from the network
        println!("Discovering random nodes from the network...");
        get_random_nodes(&client, count).await?
    };

    println!();
    println!("Testing {} nodes for version consistency...", nodes.len());
    println!("{}", "=".repeat(80));
    println!();

    // Test all nodes in parallel with timeout
    const NODE_TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    let test_futures = nodes.into_iter().map(|node_info| {
        let client = client.clone();
        let test_proof = test_proof.clone();
        let test_chunk = test_chunk.clone();
        async move {
            let peer_id = node_info.peer_id;

            // Step 1: Get reported version (with timeout)
            let version_result = tokio::time::timeout(
                NODE_TEST_TIMEOUT,
                client.get_node_version(node_info.clone()),
            )
            .await;

            let reported_version = match version_result {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    return TestResult::Failed {
                        peer_id,
                        reported_version: None,
                        error: format!("Failed to get version: {e}"),
                    };
                }
                Err(_) => {
                    return TestResult::Failed {
                        peer_id,
                        reported_version: None,
                        error: "Timeout getting version".to_string(),
                    };
                }
            };

            // Step 2: Send Merkle payment with real proof and analyze error (with timeout)
            let test_result = tokio::time::timeout(
                NODE_TEST_TIMEOUT,
                test_node_with_merkle_proof(&client, &node_info, &test_proof, &test_chunk),
            )
            .await;

            let actual_version_indicator = match test_result {
                Ok(Ok(indicator)) => indicator,
                Ok(Err(e)) => {
                    return TestResult::Failed {
                        peer_id,
                        reported_version: Some(reported_version),
                        error: format!("Failed to test: {e}"),
                    };
                }
                Err(_) => {
                    return TestResult::Failed {
                        peer_id,
                        reported_version: Some(reported_version),
                        error: "Timeout testing node".to_string(),
                    };
                }
            };

            TestResult::Success {
                peer_id,
                reported_version,
                actual_version_indicator,
            }
        }
    });

    let test_results: Vec<TestResult> = futures::future::join_all(test_futures).await;

    // Process and display results
    // Group nodes by their reported version for each category
    let mut old_error_by_version: std::collections::HashMap<String, Vec<PeerId>> =
        std::collections::HashMap::new();
    let mut unconfirmed_by_version: std::collections::HashMap<String, Vec<PeerId>> =
        std::collections::HashMap::new();
    let mut timeout_by_version: std::collections::HashMap<String, Vec<PeerId>> =
        std::collections::HashMap::new();

    for result in test_results {
        match result {
            TestResult::Failed {
                peer_id,
                reported_version,
                error,
            } => {
                let version_str = reported_version
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                println!("{peer_id}: CLIENT TIMEOUT ({error}) (reported: {version_str})");
                timeout_by_version
                    .entry(version_str)
                    .or_default()
                    .push(peer_id);
            }
            TestResult::Success {
                peer_id,
                reported_version,
                actual_version_indicator,
            } => {
                match actual_version_indicator {
                    VersionIndicator::Old => {
                        println!("{peer_id}: OLD ERROR (reported: {reported_version})");
                        old_error_by_version
                            .entry(reported_version.to_string())
                            .or_default()
                            .push(peer_id);
                    }
                    VersionIndicator::Unconfirmed => {
                        println!("{peer_id}: UNCONFIRMED (reported: {reported_version})");
                        unconfirmed_by_version
                            .entry(reported_version.to_string())
                            .or_default()
                            .push(peer_id);
                    }
                }
            }
        }
    }

    // Summary
    println!();
    println!("{}", "=".repeat(80));
    println!("SUMMARY");
    println!("{}", "=".repeat(80));

    let old_error_count: usize = old_error_by_version.values().map(|v| v.len()).sum();
    let unconfirmed_count: usize = unconfirmed_by_version.values().map(|v| v.len()).sum();
    let timeout_count: usize = timeout_by_version.values().map(|v| v.len()).sum();
    let total_tested = old_error_count + unconfirmed_count + timeout_count;

    if total_tested == 0 {
        println!("No nodes were tested.");
        return Ok(());
    }

    let old_percentage = (old_error_count as f64 / total_tested as f64) * 100.0;
    let unconfirmed_percentage = (unconfirmed_count as f64 / total_tested as f64) * 100.0;
    let timeout_percentage = (timeout_count as f64 / total_tested as f64) * 100.0;

    println!();
    println!("Total tested:              {total_tested}");
    println!();

    // Returned old error message
    println!("Returned old error msg:    {old_error_count} ({old_percentage:.1}%)");
    if !old_error_by_version.is_empty() {
        let mut versions: Vec<_> = old_error_by_version.keys().collect();
        versions.sort();
        for version in versions {
            let count = old_error_by_version[version].len();
            let pct = (count as f64 / total_tested as f64) * 100.0;
            println!("  - {version}: {count} ({pct:.1}%)");
        }
    }
    println!();

    // Unconfirmed
    println!("Unconfirmed:               {unconfirmed_count} ({unconfirmed_percentage:.1}%)");
    if !unconfirmed_by_version.is_empty() {
        let mut versions: Vec<_> = unconfirmed_by_version.keys().collect();
        versions.sort();
        for version in versions {
            let count = unconfirmed_by_version[version].len();
            let pct = (count as f64 / total_tested as f64) * 100.0;
            println!("  - {version}: {count} ({pct:.1}%)");
        }
    }
    println!();

    // Client timeout
    println!("Client timeout:            {timeout_count} ({timeout_percentage:.1}%)");
    if !timeout_by_version.is_empty() {
        let mut versions: Vec<_> = timeout_by_version.keys().collect();
        versions.sort();
        for version in versions {
            let count = timeout_by_version[version].len();
            let pct = (count as f64 / total_tested as f64) * 100.0;
            println!("  - {version}: {count} ({pct:.1}%)");
        }
    }

    Ok(())
}

/// Test proof data that includes the chunk needed for testing
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TestProofData {
    /// The Merkle payment receipt
    pub receipt: MerklePaymentReceipt,
    /// The chunk data (hex encoded) for testing
    pub chunk_data: String,
    /// The chunk address
    pub chunk_address: String,
}

/// Create a test proof for version verification.
///
/// This makes a small Merkle payment to create a valid proof that can be used
/// with verify_version to test nodes.
pub async fn create_test_proof(output: &str, network_context: NetworkContext) -> Result<()> {
    // Get wallet from environment
    let secret_key = std::env::var("SECRET_KEY").map_err(|_| {
        eyre!(
            "SECRET_KEY environment variable not set.\n\
             Please set it to your EVM wallet private key (hex format, without 0x prefix)."
        )
    })?;

    println!("Connecting to network...");
    let client = connect_to_network(network_context)
        .await
        .map_err(|(err, _exit_code)| err)?;

    // Create the wallet
    let wallet = EvmWallet::new_from_private_key(client.evm_network().clone(), &secret_key)
        .map_err(|e| eyre!("Failed to create wallet: {e}"))?;

    println!("Wallet address: {:?}", wallet.address());
    println!();

    // Create two real chunks with known content
    // We use timestamp to ensure unique addresses each time
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| eyre!("Failed to get timestamp: {e}"))?
        .as_secs();

    let chunk1_data = Bytes::from(format!("test_proof_chunk1_{timestamp}").into_bytes());
    let chunk2_data = Bytes::from(format!("test_proof_chunk2_{timestamp}").into_bytes());

    let chunk1 = Chunk::new(chunk1_data.clone());
    let chunk2 = Chunk::new(chunk2_data);

    let addr1 = *chunk1.name();
    let addr2 = *chunk2.name();

    println!("Creating Merkle payment for 2 test chunks...");
    println!("  Chunk 1 address: {}", hex::encode(addr1));
    println!("  Chunk 2 address: {}", hex::encode(addr2));
    println!();

    // Pay for the batch using Merkle payment
    // Use Chunk data type and the actual chunk size
    let data_size = chunk1_data.len();

    println!("Submitting Merkle payment to smart contract...");
    let receipt = client
        .pay_for_merkle_batch(
            DataTypes::Chunk,
            vec![addr1, addr2].into_iter(),
            data_size,
            &wallet,
        )
        .await
        .map_err(|e| eyre!("Failed to create Merkle payment: {e}"))?;

    println!("Payment successful!");
    println!("  Amount paid: {}", receipt.amount_paid);
    println!("  Proofs generated: {}", receipt.proofs.len());
    println!();

    // Create the test proof data with the chunk included
    let test_data = TestProofData {
        receipt,
        chunk_data: hex::encode(&chunk1_data),
        chunk_address: hex::encode(addr1),
    };

    // Save to the output file
    let json = serde_json::to_string_pretty(&test_data)
        .map_err(|e| eyre!("Failed to serialize test data: {e}"))?;

    std::fs::write(output, &json).map_err(|e| eyre!("Failed to write output file: {e}"))?;

    println!("Test proof saved to: {output}");
    println!();
    println!("You can now use this proof with:");
    println!("  ant developer verify-version -p {output}");

    Ok(())
}

/// Indicator of actual node version based on error message analysis
enum VersionIndicator {
    /// Node is running old version (< 2025.12.2.1)
    Old,
    /// Could not confirm node is running old version
    Unconfirmed,
}

/// Result of testing a single node
enum TestResult {
    Success {
        peer_id: PeerId,
        reported_version: autonomi::networking::version::PackageVersion,
        actual_version_indicator: VersionIndicator,
    },
    Failed {
        peer_id: PeerId,
        reported_version: Option<autonomi::networking::version::PackageVersion>,
        error: String,
    },
}

/// Test a node by sending a Merkle payment with a real proof and analyzing the error
///
/// This uses a valid proof from a previous payment. The node will verify the payment
/// on the smart contract, but will fail when trying to verify the candidate pool
/// (because the proof's candidate nodes are not the closest to the data address).
/// The error message format reveals the node's actual code version.
async fn test_node_with_merkle_proof(
    client: &Client,
    node_info: &PeerInfo,
    proof: &MerklePaymentProof,
    chunk: &Chunk,
) -> Result<VersionIndicator> {
    // Use the chunk's actual address
    let chunk_address = *chunk.address();

    // Serialize the record with the proof and chunk
    let record_value = try_serialize_record(
        &(proof.clone(), chunk.clone()),
        RecordKind::DataWithMerklePayment(DataTypes::Chunk),
    )
    .map_err(|e| eyre!("Failed to serialize record: {e}"))?;

    let record = Record {
        key: NetworkAddress::from(chunk_address).to_record_key(),
        value: record_value.to_vec(),
        publisher: None,
        expires: None,
    };

    // Send to the node and capture the error
    // We use Quorum::One since we're only sending to one node
    use autonomi::networking::Quorum;
    let error_msg = match client
        .network()
        .put_record(record, vec![node_info.clone()], Quorum::One)
        .await
    {
        Ok(_) => {
            // Unexpected success - node accepted the payment
            return Ok(VersionIndicator::Unconfirmed);
        }
        Err(e) => e.to_string(),
    };

    // Analyze the error message
    analyze_error_for_version(&error_msg)
}

/// Analyze an error message to determine the node's actual version
fn analyze_error_for_version(error_msg: &str) -> Result<VersionIndicator> {
    // Old version error string
    if error_msg.contains("Failed to get closest peers with majority knowledge to") {
        return Ok(VersionIndicator::Old);
    }

    // Also check for other version-distinguishing patterns
    if error_msg.contains("majority knowledge") {
        return Ok(VersionIndicator::Old);
    }

    // Could not confirm old version
    Ok(VersionIndicator::Unconfirmed)
}

/// Get random nodes from the network
async fn get_random_nodes(client: &Client, count: usize) -> Result<Vec<PeerInfo>> {
    use rand::seq::SliceRandom;

    let mut seen_peers = std::collections::HashSet::new();
    let mut all_peers = Vec::new();

    // Keep querying until we have enough unique nodes or hit max attempts
    const BATCH_SIZE: usize = 10; // Queries per batch
    const MAX_BATCHES: usize = 20; // Max batches to try

    for batch in 0..MAX_BATCHES {
        if all_peers.len() >= count {
            break;
        }

        // Run batch of queries in parallel
        let query_futures = (0..BATCH_SIZE).map(|i| {
            let client = client.clone();
            let query_id = batch * BATCH_SIZE + i;
            async move {
                let random_addr = NetworkAddress::from(xor_name::XorName::from_content(
                    format!("random_query_{query_id}_{}", rand::random::<u64>()).as_bytes(),
                ));
                client.network().get_closest_peers(random_addr, None).await
            }
        });

        let results = futures::future::join_all(query_futures).await;

        for peers in results.into_iter().flatten() {
            for peer in peers {
                if seen_peers.insert(peer.peer_id) {
                    all_peers.push(peer);
                }
            }
        }
    }

    if all_peers.is_empty() {
        return Err(eyre!("Could not discover any nodes from the network"));
    }

    // Shuffle and take the requested count
    let mut rng = rand::thread_rng();
    all_peers.shuffle(&mut rng);
    all_peers.truncate(count);

    Ok(all_peers)
}
