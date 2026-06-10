use std::sync::Arc;
use nomad_p2p_common::{NatType, PeerEndpoint};
use crate::AgentState;

pub async fn try_relay(
    _state: &Arc<AgentState>,
    _target_ip: &str,
) -> Option<PeerEndpoint> {
    // TODO: find relay-capable peer via seed and return their endpoint
    None
}
