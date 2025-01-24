use ant_node::spawn::network_spawner::NetworkSpawner;
use ant_protocol::storage::{ChunkAddress, DataTypes};
use ant_protocol::NetworkAddress;
use autonomi::Client;
use xor_name::XorName;

#[allow(clippy::unwrap_used)]
#[tokio::main]
async fn main() {
    let network = NetworkSpawner::new()
        .with_local(true)
        .with_size(20)
        .spawn()
        .await
        .unwrap();

    let peer = network.bootstrap_peer().await;

    let client = Client::init_with_peers(vec![peer]).await.unwrap();

    let data_type = DataTypes::Chunk.get_index();
    let data_size = 1_000_000;

    for _ in 0..1_000_000 {
        let bytes = rand::random::<[u8; 32]>();

        let record =
            NetworkAddress::from_chunk_address(ChunkAddress::new(XorName::from_content(&bytes)));

        let responses = client
            .clone()
            .network
            .get_raw_quote_responses_from_nodes(&record, data_type, data_size, vec![])
            .await
            .unwrap();

        for (peer, response) in responses {
            if let Err(err) = response {
                panic!("Error in peer ({peer}) response: {err:?}");
            }
        }
    }

    println!("Done");
}
