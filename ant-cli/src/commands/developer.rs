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
use ant_protocol::messages::merkle_payments::{CANDIDATES_PER_POOL, PEERS_TO_QUERY};
use ant_protocol::NetworkAddress;
use autonomi::Client;
use autonomi::PublicKey;
use autonomi::client::data_types::chunk::ChunkAddress;
use autonomi::client::data_types::graph::GraphEntryAddress;
use autonomi::networking::{
    DevGetClosestPeersWithMajorityFromNodeResponse, Multiaddr, PeerId, PeerInfo,
};
use color_eyre::{Result, eyre::eyre};

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

/// Compare merkle payment candidates between client and node perspectives.
///
/// This command simulates the complete merkle candidate selection and verification flow,
/// comparing what the client would select vs what the node's majority knowledge determines.
pub async fn merkle_candidates(
    node_addr: &str,
    target: &str,
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

    println!("Running merkle candidate comparison for {target}...");
    println!();

    run_merkle_simulation(&client, &target_addr, target, node_info).await
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

    let common: HashSet<PeerId> = node_peer_ids
        .intersection(&client_peer_ids)
        .copied()
        .collect();
    let node_only: HashSet<PeerId> = node_peer_ids
        .difference(&client_peer_ids)
        .copied()
        .collect();
    let client_only: HashSet<PeerId> = client_peer_ids
        .difference(&node_peer_ids)
        .copied()
        .collect();

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
    println!("NODE'S PERSPECTIVE (from {}):", node_response.queried_node);
    println!("  {:<4} {:<54} {:<10} Status", "#", "PeerId", "Distance");
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
    println!("  {:<4} {:<54} {:<10} Status", "#", "PeerId", "Distance");
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

/// Run full merkle payment simulation with majority knowledge verification.
///
/// This compares:
/// 1. Client side: Query closest peers to target, select top 16 as candidates
/// 2. Node side: Ask the node to build majority knowledge by querying its peers
/// 3. Compare client's candidates against the node's majority knowledge view
async fn run_merkle_simulation(
    client: &Client,
    target_addr: &NetworkAddress,
    target: &str,
    verifying_node: PeerInfo,
) -> Result<()> {
    use std::collections::HashSet;

    let verifying_peer_id = verifying_node.peer_id;

    println!("MERKLE PAYMENT SIMULATION for {target}");
    println!("{}", "=".repeat(100));
    println!();
    println!(
        "Parameters: PEERS_TO_QUERY={PEERS_TO_QUERY}, CANDIDATES_PER_POOL={CANDIDATES_PER_POOL}"
    );
    println!();

    // ========================================================================
    // PHASE 1: Client-side candidate selection simulation
    // ========================================================================
    println!("PHASE 1: CLIENT CANDIDATE SELECTION");
    println!("{}", "-".repeat(50));
    println!();

    println!("  Querying closest peers from client's perspective...");
    let client_peers = client
        .network()
        .get_closest_peers(target_addr.clone(), Some(PEERS_TO_QUERY))
        .await
        .map_err(|e| eyre!("Failed to get client's closest peers: {e}"))?;

    // Sort by distance and select top CANDIDATES_PER_POOL
    let mut client_peers_sorted: Vec<_> = client_peers.iter().collect();
    client_peers_sorted.sort_by_key(|p| {
        let addr = NetworkAddress::from(p.peer_id);
        target_addr.distance(&addr)
    });

    let client_candidates: Vec<PeerId> = client_peers_sorted
        .iter()
        .take(CANDIDATES_PER_POOL)
        .map(|p| p.peer_id)
        .collect();

    println!(
        "  Queried {} peers, selected {} candidates",
        client_peers.len(),
        client_candidates.len()
    );
    println!();

    // ========================================================================
    // PHASE 2: Node-side majority knowledge (via RPC)
    // ========================================================================
    println!("PHASE 2: NODE MAJORITY KNOWLEDGE VERIFICATION (via RPC)");
    println!("{}", "-".repeat(50));
    println!();
    println!("  Asking node {verifying_peer_id} to build majority knowledge");
    println!("  by querying its peers and aggregating their views.");
    println!();

    let majority_response = client
        .dev_get_closest_peers_with_majority_from_node(
            verifying_node,
            target_addr.clone(),
            Some(CANDIDATES_PER_POOL),
        )
        .await
        .map_err(|e| eyre!("Failed to get majority knowledge from node: {e}"))?;

    println!(
        "  Found {} peers with majority consensus",
        majority_response.peers.len()
    );
    println!();

    // ========================================================================
    // PHASE 3: Verification comparison
    // ========================================================================
    println!("PHASE 3: VERIFICATION COMPARISON");
    println!("{}", "-".repeat(50));
    println!();

    let client_set: HashSet<PeerId> = client_candidates.iter().copied().collect();
    let majority_candidates: Vec<PeerId> = majority_response
        .peers
        .iter()
        .filter_map(|(addr, _)| addr.as_peer_id())
        .collect();
    let majority_set: HashSet<PeerId> = majority_candidates.iter().copied().collect();

    let validated: HashSet<PeerId> = client_set.intersection(&majority_set).copied().collect();
    let client_only: HashSet<PeerId> = client_set.difference(&majority_set).copied().collect();
    let majority_only: HashSet<PeerId> = majority_set.difference(&client_set).copied().collect();

    let validation_rate = if !client_set.is_empty() {
        (validated.len() as f64 / client_set.len() as f64) * 100.0
    } else {
        0.0
    };

    println!("SUMMARY:");
    println!("  Client candidates:     {}", client_candidates.len());
    println!("  Majority candidates:   {}", majority_candidates.len());
    println!("  Validated (in both):   {}", validated.len());
    println!("  Client-only:           {}", client_only.len());
    println!("  Majority-only:         {}", majority_only.len());
    println!("  Validation rate:       {validation_rate:.1}%");
    println!();

    // Verification result
    if validation_rate >= 75.0 {
        println!("  PASS - Node would likely accept this payment");
        println!("    Majority of client's candidates are validated by network consensus");
    } else if validation_rate >= 50.0 {
        println!("  MARGINAL - Payment verification uncertain");
        println!("    Some candidates may not be recognized by the verifying node");
    } else {
        println!("  FAIL - Node would likely reject this payment");
        println!("    Too few candidates match the node's majority knowledge view");
    }
    println!();

    // ========================================================================
    // Detailed breakdown
    // ========================================================================
    display_merkle_details(
        target_addr,
        &client_candidates,
        &majority_response,
        &validated,
        &client_only,
        &majority_only,
        &client_peers_sorted,
    );

    Ok(())
}

/// Display detailed breakdown of merkle simulation results.
fn display_merkle_details(
    target_addr: &NetworkAddress,
    client_candidates: &[PeerId],
    majority_response: &DevGetClosestPeersWithMajorityFromNodeResponse,
    validated: &std::collections::HashSet<PeerId>,
    client_only: &std::collections::HashSet<PeerId>,
    majority_only: &std::collections::HashSet<PeerId>,
    client_peers_sorted: &[&PeerInfo],
) {
    println!("CLIENT'S SELECTED CANDIDATES:");
    println!(
        "  {:<4} {:<54} {:<10} Status",
        "#", "PeerId", "Distance"
    );
    println!("  {}", "-".repeat(80));

    for (i, peer_id) in client_candidates.iter().enumerate() {
        let peer_addr = NetworkAddress::from(*peer_id);
        let distance = target_addr.distance(&peer_addr);
        let distance_ilog2 = distance.ilog2().unwrap_or(0);

        let status = if validated.contains(peer_id) {
            "validated"
        } else {
            "not in majority"
        };

        println!(
            "  {:<4} {:<54} {:<10} {}",
            i + 1,
            peer_id,
            distance_ilog2,
            status
        );
    }
    println!();

    println!("NODE'S MAJORITY KNOWLEDGE CANDIDATES:");
    println!(
        "  {:<4} {:<54} {:<10} Status",
        "#", "PeerId", "Distance"
    );
    println!("  {}", "-".repeat(80));

    for (i, (peer_addr, _)) in majority_response.peers.iter().enumerate() {
        let distance = target_addr.distance(peer_addr);
        let distance_ilog2 = distance.ilog2().unwrap_or(0);

        let peer_display = if let Some(peer_id) = peer_addr.as_peer_id() {
            let status = if validated.contains(&peer_id) {
                "common"
            } else {
                "majority-only"
            };
            (peer_id.to_string(), status)
        } else {
            (peer_addr.to_string(), "unknown")
        };

        println!(
            "  {:<4} {:<54} {:<10} {}",
            i + 1,
            peer_display.0,
            distance_ilog2,
            peer_display.1
        );
    }
    println!();

    // Show peers that didn't make majority
    if !client_only.is_empty() {
        println!("CANDIDATES ONLY IN CLIENT'S POOL (not validated):");
        for peer_id in client_only {
            let peer_addr = NetworkAddress::from(*peer_id);
            let distance = target_addr.distance(&peer_addr);
            let distance_ilog2 = distance.ilog2().unwrap_or(0);
            println!("  {peer_id} (dist: {distance_ilog2}) - not in node's majority knowledge");
        }
        println!();
    }

    if !majority_only.is_empty() {
        println!("CANDIDATES ONLY IN MAJORITY KNOWLEDGE (client missed):");
        for peer_id in majority_only {
            let peer_addr = NetworkAddress::from(*peer_id);
            let distance = target_addr.distance(&peer_addr);
            let distance_ilog2 = distance.ilog2().unwrap_or(0);

            let in_client_query = client_peers_sorted.iter().any(|p| p.peer_id == *peer_id);
            let reason = if in_client_query {
                "in client's query but not selected (farther than others)"
            } else {
                "not in client's initial query"
            };
            println!("  {peer_id} (dist: {distance_ilog2}) - {reason}");
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
