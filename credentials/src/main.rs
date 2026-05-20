use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const TRUST_TTL_DAYS: i64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Trusted,
    Untrusted,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub public_key_b64: String,
    pub public_key_hash_hex: String,
    pub did: String,
    pub status: DeviceStatus,
    pub last_evidence_at: Option<DateTime<Utc>>,
    pub last_valid_evidence_at: Option<DateTime<Utc>>,
    pub evidence_hash_hex: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub did_document: Value,
}

impl DeviceRecord {
    pub fn new(public_key_b64: String, public_key_hash_hex: String) -> Self {
        let did = format!("did:iota:tst:0x{public_key_hash_hex}");
        Self {
            public_key_b64,
            public_key_hash_hex,
            did,
            status: DeviceStatus::Untrusted,
            last_evidence_at: None,
            last_valid_evidence_at: None,
            evidence_hash_hex: None,
            updated_at: Utc::now(),
            did_document: Value::Null,
        }
    }

    pub fn should_expire(&self, now: DateTime<Utc>) -> bool {
        if self.status != DeviceStatus::Trusted {
            return false;
        }

        self.last_valid_evidence_at
            .map(|last_valid| {
                now.signed_duration_since(last_valid) > Duration::days(TRUST_TTL_DAYS)
            })
            .unwrap_or(true)
    }
}
