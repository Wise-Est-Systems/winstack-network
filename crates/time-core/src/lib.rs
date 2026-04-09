use canon_types::{ChainedTimeEvent, TimeSource};

pub mod tsa;
use std::collections::HashMap;
use uuid::Uuid;
use winstack_crypto::{self as crypto, KeyPair};

#[derive(Debug, thiserror::Error)]
pub enum TimeError {
    #[error("predecessor not found: {0}")]
    PredecessorMissing(Uuid),
    #[error("predecessor hash mismatch")]
    PredecessorHashMismatch,
    #[error("time chain broken")]
    ChainBroken,
    #[error("signature invalid")]
    SignatureInvalid,
}

pub struct TimeAuthority {
    authority_id: Uuid,
    key: KeyPair,
    chain: Vec<Uuid>,
    events: HashMap<Uuid, ChainedTimeEvent>,
}

impl TimeAuthority {
    pub fn new(authority_id: Uuid, key: KeyPair) -> Self {
        Self {
            authority_id,
            key,
            chain: Vec::new(),
            events: HashMap::new(),
        }
    }

    pub fn authority_id(&self) -> Uuid {
        self.authority_id
    }

    pub fn attest_time(&mut self, payload_hash: &str) -> ChainedTimeEvent {
        let event_id = Uuid::new_v4();
        let now = chrono::Utc::now().to_rfc3339();

        let (pred_id, pred_hash) = if let Some(last_id) = self.chain.last() {
            let last_evt = &self.events[last_id];
            let hash = crypto::sha256_hex(crypto::canonical_json(last_evt).as_bytes());
            (Some(*last_id), Some(hash))
        } else {
            (None, None)
        };

        #[derive(serde::Serialize)]
        struct SignPayload<'a> {
            time_event_id: &'a Uuid,
            timestamp: &'a str,
            time_authority_identity_id: &'a Uuid,
            predecessor_event_id: &'a Option<Uuid>,
            predecessor_hash: &'a Option<String>,
            payload_hash: &'a str,
            time_source: &'a TimeSource,
            rfc3161_token: &'a Option<String>,
            anchored_time: &'a Option<String>,
        }

        let ts = TimeSource::Local;
        let no_token: Option<String> = None;
        let no_anchor: Option<String> = None;
        let payload = SignPayload {
            time_event_id: &event_id,
            timestamp: &now,
            time_authority_identity_id: &self.authority_id,
            predecessor_event_id: &pred_id,
            predecessor_hash: &pred_hash,
            payload_hash,
            time_source: &ts,
            rfc3161_token: &no_token,
            anchored_time: &no_anchor,
        };
        let sig = self.key.sign_json(&payload);

        let event = ChainedTimeEvent {
            time_event_id: event_id,
            timestamp: now,
            time_authority_identity_id: self.authority_id,
            predecessor_event_id: pred_id,
            predecessor_hash: pred_hash,
            payload_hash: payload_hash.to_string(),
            signature: sig,
            time_source: TimeSource::Local,
            rfc3161_token: None,
            anchored_time: None,
        };

        self.chain.push(event_id);
        self.events.insert(event_id, event.clone());
        event
    }

    /// Re-sign a time event after fields have been modified (e.g. TSA attachment).
    pub fn re_sign_event(&self, event: &mut ChainedTimeEvent) {
        #[derive(serde::Serialize)]
        struct SignPayload<'a> {
            time_event_id: &'a Uuid,
            timestamp: &'a str,
            time_authority_identity_id: &'a Uuid,
            predecessor_event_id: &'a Option<Uuid>,
            predecessor_hash: &'a Option<String>,
            payload_hash: &'a str,
            time_source: &'a TimeSource,
            rfc3161_token: &'a Option<String>,
            anchored_time: &'a Option<String>,
        }

        let payload = SignPayload {
            time_event_id: &event.time_event_id,
            timestamp: &event.timestamp,
            time_authority_identity_id: &event.time_authority_identity_id,
            predecessor_event_id: &event.predecessor_event_id,
            predecessor_hash: &event.predecessor_hash,
            payload_hash: &event.payload_hash,
            time_source: &event.time_source,
            rfc3161_token: &event.rfc3161_token,
            anchored_time: &event.anchored_time,
        };
        event.signature = self.key.sign_json(&payload);
    }

    pub fn get_event(&self, id: &Uuid) -> Option<&ChainedTimeEvent> {
        self.events.get(id)
    }

    pub fn get_predecessor(&self, event: &ChainedTimeEvent) -> Option<&ChainedTimeEvent> {
        event
            .predecessor_event_id
            .as_ref()
            .and_then(|pid| self.events.get(pid))
    }
}

pub fn verify_time_signature(
    event: &ChainedTimeEvent,
    authority_public_key: &str,
) -> Result<(), TimeError> {
    #[derive(serde::Serialize)]
    struct SignPayload<'a> {
        time_event_id: &'a Uuid,
        timestamp: &'a str,
        time_authority_identity_id: &'a Uuid,
        predecessor_event_id: &'a Option<Uuid>,
        predecessor_hash: &'a Option<String>,
        payload_hash: &'a str,
        time_source: &'a TimeSource,
        rfc3161_token: &'a Option<String>,
        anchored_time: &'a Option<String>,
    }

    let payload = SignPayload {
        time_event_id: &event.time_event_id,
        timestamp: &event.timestamp,
        time_authority_identity_id: &event.time_authority_identity_id,
        predecessor_event_id: &event.predecessor_event_id,
        predecessor_hash: &event.predecessor_hash,
        payload_hash: &event.payload_hash,
        time_source: &event.time_source,
        rfc3161_token: &event.rfc3161_token,
        anchored_time: &event.anchored_time,
    };

    crypto::verify_json_signature(authority_public_key, &payload, &event.signature)
        .map_err(|_| TimeError::SignatureInvalid)
}

pub fn verify_time_chain(
    event: &ChainedTimeEvent,
    predecessor: Option<&ChainedTimeEvent>,
) -> Result<(), TimeError> {
    if event.is_genesis() {
        return Ok(());
    }

    let pred_id = event.predecessor_event_id.ok_or(TimeError::ChainBroken)?;

    let pred = predecessor.ok_or(TimeError::PredecessorMissing(pred_id))?;

    if pred.time_event_id != pred_id {
        return Err(TimeError::PredecessorMissing(pred_id));
    }

    let expected_hash = crypto::sha256_hex(crypto::canonical_json(pred).as_bytes());
    let actual_hash = event
        .predecessor_hash
        .as_ref()
        .ok_or(TimeError::PredecessorHashMismatch)?;

    if *actual_hash != expected_hash {
        return Err(TimeError::PredecessorHashMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_authority() -> (TimeAuthority, String) {
        let kp = KeyPair::generate();
        let pk = kp.public_key_hex();
        let id = Uuid::new_v4();
        (TimeAuthority::new(id, kp), pk)
    }

    #[test]
    fn genesis_event() {
        let (mut ta, pk) = make_authority();
        let evt = ta.attest_time("hash1");
        assert!(evt.is_genesis());
        assert!(verify_time_signature(&evt, &pk).is_ok());
        assert!(verify_time_chain(&evt, None).is_ok());
    }

    #[test]
    fn chained_events() {
        let (mut ta, pk) = make_authority();
        let e1 = ta.attest_time("hash1");
        let e2 = ta.attest_time("hash2");
        assert!(!e2.is_genesis());
        assert!(verify_time_signature(&e2, &pk).is_ok());
        assert!(verify_time_chain(&e2, Some(&e1)).is_ok());
    }

    #[test]
    fn wrong_predecessor_fails() {
        let (mut ta, _pk) = make_authority();
        let _e1 = ta.attest_time("hash1");
        let _e2 = ta.attest_time("hash2");
        let e3 = ta.attest_time("hash3");
        // e3 expects e2 as predecessor, giving e1 (wrong id) fails
        let result = verify_time_chain(&e3, Some(ta.get_event(&ta.chain[0]).unwrap()));
        assert!(result.is_err());
    }

    #[test]
    fn missing_predecessor_fails() {
        let (mut ta, _pk) = make_authority();
        let _e1 = ta.attest_time("hash1");
        let e2 = ta.attest_time("hash2");
        assert!(verify_time_chain(&e2, None).is_err());
    }
}
