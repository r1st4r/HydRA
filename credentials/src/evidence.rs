use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEvidence {
    pub message_b64: String,
    pub signature_b64: String,
    pub produced_at: DateTime<Utc>,
}

impl DeviceEvidence {
    pub fn sha256_hex(&self) -> Result<String, EvidenceError> {
        let bytes = serde_json::to_vec(self)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("public key must be 32 bytes, got {0}")]
    InvalidPublicKeyLength(usize),

    #[error("signature must be 64 bytes, got {0}")]
    InvalidSignatureLength(usize),

    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,

    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub fn verify_device_evidence(
    public_key_b64: &str,
    evidence: &DeviceEvidence,
) -> Result<bool, EvidenceError> {
    let public_key_bytes = STANDARD.decode(public_key_b64)?;
    let message = STANDARD.decode(&evidence.message_b64)?;
    let signature_bytes = STANDARD.decode(&evidence.signature_b64)?;

    let public_key_array: [u8; 32] = public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| EvidenceError::InvalidPublicKeyLength(public_key_bytes.len()))?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| EvidenceError::InvalidSignatureLength(signature_bytes.len()))?;

    let verifying_key =
        VerifyingKey::from_bytes(&public_key_array).map_err(|_| EvidenceError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(&signature_array);

    Ok(verifying_key.verify(&message, &signature).is_ok())
}
