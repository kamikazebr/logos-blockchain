use std::collections::{HashMap, HashSet};

use lb_blend_message::MessageIdentifier;
use libp2p::PeerId;

#[derive(Debug, Default)]
pub struct MessageCache {
    processed_messages: HashSet<MessageIdentifier>,
    received_messages: HashMap<PeerId, HashSet<MessageIdentifier>>,
}

impl MessageCache {
    pub fn new_with_peer_capacity(capacity: usize) -> Self {
        Self {
            processed_messages: HashSet::new(),
            received_messages: HashMap::with_capacity(capacity),
        }
    }

    /// Mark a message with the given identifier as processed, and return
    /// whether it was the first time we marked it as such.
    ///
    /// This function does not keep into account whether we already registered a
    /// message as seen from a peer, but only whether the message was already
    /// processed by us or not.
    pub fn mark_message_as_processed(&mut self, message_id: MessageIdentifier) -> bool {
        self.processed_messages.insert(message_id)
    }

    pub fn is_message_processed(&self, message_id: &MessageIdentifier) -> bool {
        self.processed_messages.contains(message_id)
    }

    pub fn mark_message_as_seen_from_peer(
        &mut self,
        message_id: MessageIdentifier,
        peer_id: PeerId,
    ) -> bool {
        self.received_messages
            .entry(peer_id)
            .or_default()
            .insert(message_id)
    }

    pub fn is_message_seen_from_peer(
        &self,
        message_id: &MessageIdentifier,
        peer_id: &PeerId,
    ) -> bool {
        self.received_messages
            .get(peer_id)
            .map_or(false, |message_set| message_set.contains(message_id))
    }

    pub fn remove_peer_info(&mut self, peer_id: &PeerId) {
        self.received_messages.remove(peer_id);
    }
}
