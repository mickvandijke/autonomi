// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
//
// Test the consensus-based merkle candidate selection against the live network.
//
// ## Merkle Tree Structure
//
// ```
// Chunk A (leaf 0) ─┐
// Chunk B (leaf 1) ─┼─→ Midpoint 0 ─→ Merkle Candidates (close to midpoint 0)
// Chunk C (leaf 2) ─┤
// Chunk D (leaf 3) ─┘
// Chunk E (leaf 4) ─┐
// Chunk F (leaf 5) ─┼─→ Midpoint 1 ─→ Merkle Candidates (close to midpoint 1)
// ...              ─┘
// ```
//
// ## Key Concepts
//
// Per-Leaf Requirement:
//   - Each chunk needs 3 STORING NODES (close to chunk address)
//   - These 3 must have MUTUAL MEMBERSHIP in their close groups
//
// Per-Midpoint Requirement:
//   - ALL storing nodes from ALL chunks mapping to a midpoint must agree
//   - They agree on who the MERKLE CANDIDATES should be (close to midpoint)
//
// ## Usage
//
//   # Test RT-based consensus (no payment required)
//   RUST_LOG=autonomi=debug cargo run --release --example test_consensus_payment
//
//   # Test with actual payment (requires SECRET_KEY with ANT tokens)
//   SECRET_KEY=<your_key> cargo run --release --example test_consensus_payment

use ant_evm::EvmWallet;
use ant_protocol::storage::DataTypes;
use autonomi::client::merkle_payments::TopologyErrorCollection;
use autonomi::Client;
use bytes::Bytes;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Merkle Candidate Consensus Test ===\n");

    println!("Merkle Tree Structure:");
    println!("  Chunk A ─┐");
    println!("  Chunk B ─┼─→ Midpoint M ─→ Merkle Candidates");
    println!("  Chunk C ─┘");
    println!();
    println!("Per-Leaf: Each chunk needs 3 storing nodes with mutual membership");
    println!("Per-Midpoint: ALL storing nodes must agree on merkle candidates");
    println!();

    // Connect to live network
    println!("Connecting to live network...");
    let start = Instant::now();
    let client = Client::init().await?;
    println!("Connected in {:?}\n", start.elapsed());

    // Create multiple test chunks that would map to the same midpoint
    let chunk_a = xor_name::XorName::from_content(b"test_chunk_a");
    let chunk_b = xor_name::XorName::from_content(b"test_chunk_b");
    let chunk_c = xor_name::XorName::from_content(b"test_chunk_c");
    let chunk_d = xor_name::XorName::from_content(b"test_chunk_d");
    let chunk_addresses = vec![chunk_a, chunk_b, chunk_c, chunk_d];

    // For testing, we'll use a fake midpoint address
    // In real usage, the midpoint comes from the merkle tree
    let fake_midpoint = xor_name::XorName::from_content(b"fake_midpoint_for_testing");

    println!("Test setup:");
    println!("  {} chunks mapping to 1 midpoint", chunk_addresses.len());
    println!("  Midpoint address: {:?}", fake_midpoint);
    println!();

    // =========================================================================
    // Step 1: RT-based consensus (uses local routing tables - may be inaccurate)
    // =========================================================================
    println!("=== Step 1: RT-Based Midpoint Consensus ===");
    println!("For each chunk:");
    println!("  1. Find 3 storing nodes with mutual membership");
    println!("  2. Query their view of merkle candidates for the midpoint");
    println!("Then find consensus across ALL storing nodes from ALL chunks.\n");

    let start = Instant::now();
    match client
        .get_midpoint_consensus(chunk_addresses.clone(), fake_midpoint)
        .await
    {
        Ok(consensus) => {
            println!("Found consensus in {:?}!", start.elapsed());
            println!();
            println!("CHUNK TRIPLETS (3 storing nodes per chunk with mutual membership):");
            for (i, triplet) in consensus.chunk_triplets.iter().enumerate() {
                println!(
                    "  Chunk {}: {:?}",
                    i,
                    triplet.storing_nodes.iter().map(|p| format!("{p:?}")).collect::<Vec<_>>().join(", ")
                );
            }
            println!();
            println!(
                "TOTAL STORING NODES: {} (from {} chunks)",
                consensus.all_storing_nodes.len(),
                consensus.chunk_triplets.len()
            );
            println!();
            println!("CONSENSUS MERKLE CANDIDATES (agreed by all storing nodes):");
            println!("  Count: {}", consensus.consensus_merkle_candidates.len());
            for (i, candidate) in consensus
                .consensus_merkle_candidates
                .iter()
                .enumerate()
                .take(5)
            {
                println!("  {}: {:?}", i + 1, candidate);
            }
            if consensus.consensus_merkle_candidates.len() > 5 {
                println!(
                    "  ... and {} more",
                    consensus.consensus_merkle_candidates.len() - 5
                );
            }
            println!();
            println!("WARNING: This uses local routing tables. Actual merkle validation");
            println!("         uses network lookup which may give different results!");
        }
        Err(e) => {
            println!("RT-based consensus failed: {}", e);
            println!("\nThis might happen if:");
            println!("  - Network is too small (not enough peers)");
            println!("  - No mutual triplet found for some chunk");
            println!("  - Insufficient overlap in merkle candidate views");
        }
    }

    // =========================================================================
    // Step 2: Topology Error Consensus Flow (the accurate method)
    // =========================================================================
    println!();
    println!("=== Step 2: Topology Error Consensus (Accurate Method) ===");
    println!();
    println!("To get ACCURATE merkle candidates:");
    println!();
    println!("  1. INITIAL PAYMENT: Pay with client-predicted candidates");
    println!();
    println!("  2. UPLOAD ATTEMPT: Upload chunks to their storing nodes");
    println!("     - Storing nodes do NETWORK LOOKUP to verify payment");
    println!();
    println!("  3. COLLECT ERRORS: On TopologyVerificationFailed:");
    println!("     - error.node_peers = actual network lookup result");
    println!("     - This is the storing node's TRUE view of merkle candidates");
    println!();
    println!("  4. FIND CONSENSUS: Intersect node_peers from all errors");
    println!();
    println!("  5. RETRY: Pay the correct candidates and re-upload");
    println!();

    let errors = TopologyErrorCollection::new();
    println!("TopologyErrorCollection API:");
    println!("  errors.add_from_network_error(&err);  // Collect errors");
    println!("  errors.len() -> {}  // {} errors collected", errors.len(), errors.len());
    println!("  client.find_consensus_from_topology_errors(&errors)?;  // Find intersection");

    // =========================================================================
    // Step 3: Optional - test actual payment if SECRET_KEY is provided
    // =========================================================================
    if let Ok(secret_key) = std::env::var("SECRET_KEY") {
        println!();
        println!("=== Step 3: Testing Actual Payment ===");
        println!("SECRET_KEY found, attempting payment with consensus...\n");

        let wallet =
            EvmWallet::new_from_private_key(client.evm_network().clone(), &secret_key)?;
        let balance = wallet.balance_of_tokens().await?;
        println!("Wallet balance: {} (raw tokens)", balance);

        // Create actual test data for payment
        let test_data = Bytes::from("Hello from consensus-based merkle payment test!");
        let chunk_address = xor_name::XorName::from_content(&test_data);
        let addresses = vec![chunk_address];
        let start = Instant::now();

        match client
            .pay_for_merkle_batch(
                DataTypes::Chunk,
                addresses.into_iter(),
                test_data.len(),
                &wallet,
            )
            .await
        {
            Ok(receipt) => {
                println!("Payment successful in {:?}!", start.elapsed());
                println!("  Amount paid: {}", receipt.amount_paid);
                println!("  Proofs generated: {}", receipt.proofs.len());
                println!();
                println!("Next: Upload and handle TopologyVerificationFailed if it occurs.");
            }
            Err(e) => {
                println!("Payment failed: {}", e);
                println!();
                println!("On upload failure, collect topology errors:");
                println!("  errors.add_from_network_error(&network_err);");
                println!("  let consensus = client.find_consensus_from_topology_errors(&errors)?;");
            }
        }
    } else {
        println!();
        println!("=== Step 3: Skipped (no SECRET_KEY) ===");
        println!(
            "To test: SECRET_KEY=<key> cargo run --example test_consensus_payment"
        );
    }

    println!();
    println!("=== Test Complete ===");
    Ok(())
}
