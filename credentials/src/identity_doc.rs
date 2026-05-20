use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use identity_iota::core::ToJson;
use identity_iota::iota::{IotaDocument, NetworkName};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::model::DeviceRecord;

pub fn public_key_hash_hex(public_key_bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key_bytes))
}

pub fn build_device_did_document(network: &str, record: &DeviceRecord) -> anyhow::Result<Value> {
    let network_name: NetworkName = NetworkName::try_from(network.to_owned())?;
    let mut document_json = IotaDocument::new(&network_name).to_json_value()?;
    let did = format!("did:iota:{network}:0x{}", record.public_key_hash_hex);
    let public_key_bytes = STANDARD.decode(&record.public_key_b64)?;
    let public_key_jwk_x = URL_SAFE_NO_PAD.encode(public_key_bytes);

    document_json["id"] = json!(did);
    document_json["verificationMethod"] = json!([
        {
            "id": format!("{did}#device-key"),
            "type": "JsonWebKey",
            "controller": did,
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "kid": "device-key",
                "x": public_key_jwk_x
            }
        }
    ]);
    document_json["authentication"] = json!([format!("{did}#device-key")]);
    document_json["service"] = json!([
        {
            "id": format!("{did}#trust-state"),
            "type": "DeviceTrustState",
            "serviceEndpoint": format!("urn:iota-device-state:{}", record.public_key_hash_hex),
            "publicKeyHash": record.public_key_hash_hex,
            "status": record.status,
            "lastEvidenceAt": record.last_evidence_at,
            "lastValidEvidenceAt": record.last_valid_evidence_at,
            "evidenceHash": record.evidence_hash_hex,
            "updatedAt": record.updated_at
        }
    ]);

    Ok(document_json)
}

