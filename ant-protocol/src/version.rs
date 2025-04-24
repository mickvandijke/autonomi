// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// Network ID of the mainnet.
pub const MAIN_NETWORK_ID: u8 = 1;

/// Network ID of the Alpha Network.
pub const ALPHA_NETWORK_ID: u8 = 2;

/// The node version used during Identify Behaviour.
pub fn identify_node_version_str(network_id: u8) -> String {
    format!("ant/node/{}/{network_id}", get_truncate_version_str())
}

/// The client version used during Identify Behaviour.
pub fn identify_client_version_str(network_id: u8) -> String {
    format!("ant/client/{}/{network_id}", get_truncate_version_str())
}

/// The req/response protocol version
pub fn req_response_version_str(network_id: u8) -> String {
    format!("/ant/{}/{}", get_truncate_version_str(), network_id)
}

/// The identify protocol version
pub fn identify_protocol_str(network_id: u8) -> String {
    format!("ant/{}/{}", get_truncate_version_str(), network_id)
}

// Protocol support shall be downward compatible for patch only version update.
// i.e. versions of `A.B.X` or `A.B.X-alpha.Y` shall be considered as a same protocol of `A.B`
pub fn get_truncate_version_str() -> String {
    let version_str = env!("CARGO_PKG_VERSION");
    let parts = version_str.split('.').collect::<Vec<_>>();
    if parts.len() >= 2 {
        format!("{}.{}", parts[0], parts[1])
    } else {
        panic!("Cannot obtain truncated version str for {version_str:?}: {parts:?}");
    }
}
