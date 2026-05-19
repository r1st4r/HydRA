
use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use getrandom::getrandom;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const HEADER_JSON: &str = r#"{"alg":"HS256","typ":"RATS_CHALLENGE"}"#;
const DEFAULT_RANDOM_SEED_LEN: usize = 32;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeTokenClaims {
    pub tee: i32,
    pub mode: i32,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl ChallengeTokenClaims {
    pub fn nonce_bytes(&self) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(self.nonce.as_bytes())
            .context("decode challenge nonce")
    }

    pub fn challenge_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.tee.to_be_bytes());
        hasher.update(self.mode.to_be_bytes());
        hasher.update(self.nonce.as_bytes());
        hasher.update(self.issued_at.to_be_bytes());
        hasher.update(self.expires_at.to_be_bytes());
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    }
}

pub fn issue(
    tee: i32,
    mode: i32,
    requested_nonce: Option<&[u8]>,
    ttl_secs: u64,
    signing_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let nonce = match requested_nonce {
        Some(raw) if !raw.is_empty() => {
            validate_nonce(raw)?;
            raw.to_vec()
        }
        _ => {
            let mut seed = vec![0u8; DEFAULT_RANDOM_SEED_LEN];
            getrandom(&mut seed).context("generate random nonce")?;
            URL_SAFE_NO_PAD.encode(seed).into_bytes()
        }
    };

    let now = unix_now()?;
    let claims = ChallengeTokenClaims {
        tee,
        mode,
        nonce: URL_SAFE_NO_PAD.encode(&nonce),
        issued_at: now,
        expires_at: now + ttl_secs as i64,
    };
    let payload_json = serde_json::to_vec(&claims).context("serialize challenge claims")?;
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(HEADER_JSON.as_bytes()),
        URL_SAFE_NO_PAD.encode(payload_json)
    );
    let signature = hmac_sha256(signing_key, signing_input.as_bytes())?;
    let token = format!("{}.{}", signing_input, URL_SAFE_NO_PAD.encode(signature)).into_bytes();

    Ok((nonce, token))
}

pub fn decode(token: &[u8]) -> Result<ChallengeTokenClaims> {
    let token = std::str::from_utf8(token).context("challenge token is not valid UTF-8")?;
    let mut parts = token.split('.');
    let _header = parts.next().context("missing challenge header")?;
    let payload = parts.next().context("missing challenge payload")?;
    let _signature = parts.next().context("missing challenge signature")?;
    if parts.next().is_some() {
        bail!("invalid challenge token format");
    }

    let payload = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .context("decode challenge payload")?;
    let claims = serde_json::from_slice::<ChallengeTokenClaims>(&payload)
        .context("parse challenge payload")?;
    validate_nonce(&claims.nonce_bytes()?)?;
    Ok(claims)
}

pub fn verify(
    token: &[u8],
    expected_tee: Option<i32>,
    expected_mode: Option<i32>,
    signing_key: &[u8],
) -> Result<ChallengeTokenClaims> {
    let token = std::str::from_utf8(token).context("challenge token is not valid UTF-8")?;
    let mut parts = token.split('.');
    let header = parts.next().context("missing challenge header")?;
    let payload = parts.next().context("missing challenge payload")?;
    let signature = parts.next().context("missing challenge signature")?;
    if parts.next().is_some() {
        bail!("invalid challenge token format");
    }

    let signing_input = format!("{}.{}", header, payload);
    let actual_signature = URL_SAFE_NO_PAD
        .decode(signature.as_bytes())
        .context("decode challenge signature")?;
    let mut mac =
        HmacSha256::new_from_slice(signing_key).context("create challenge signing key")?;
    mac.update(signing_input.as_bytes());
    if mac.verify_slice(&actual_signature).is_err() {
        bail!("invalid challenge token signature");
    }

    let claims = decode(token.as_bytes())?;
    let now = unix_now()?;
    if now > claims.expires_at {
        bail!("challenge token expired");
    }
    if let Some(tee) = expected_tee
        && tee != claims.tee
    {
        bail!("challenge token tee mismatch");
    }
    if let Some(mode) = expected_mode
        && mode != claims.mode
    {
        bail!("challenge token mode mismatch");
    }

    Ok(claims)
}

fn hmac_sha256(signing_key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let mut mac =
        HmacSha256::new_from_slice(signing_key).context("create challenge signing key")?;
    mac.update(input);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn unix_now() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system time before unix epoch")?
        .as_secs() as i64)
}

fn validate_nonce(nonce: &[u8]) -> Result<()> {
    if !(8..=64).contains(&nonce.len()) {
        bail!("nonce must be between 8 and 64 bytes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_rejects_tampered_payload() -> Result<()> {
        let (_nonce, token) = issue(1, 1, Some(b"expected-nonce"), 60, b"test-key")?;
        let mut parts = std::str::from_utf8(&token)?
            .split('.')
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let mut claims = decode(&token)?;
        claims.mode = 2;
        parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let tampered = parts.join(".");

        let result = verify(tampered.as_bytes(), Some(1), Some(2), b"test-key");

        assert!(result.is_err());
        assert!(
            result
                .expect_err("tampered token should fail")
                .to_string()
                .contains("invalid challenge token signature")
        );
        Ok(())
    }

    #[test]
    fn verify_rejects_tampered_signature() -> Result<()> {
        let (_nonce, token) = issue(1, 1, Some(b"expected-nonce"), 60, b"test-key")?;
        let mut token = token;
        let last = token.last_mut().expect("token should not be empty");
        *last = if *last == b'A' { b'B' } else { b'A' };

        let result = verify(&token, Some(1), Some(1), b"test-key");

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn challenge_id_is_stable_for_same_claims() -> Result<()> {
        let (_nonce, token) = issue(1, 1, Some(b"expected-nonce"), 60, b"test-key")?;
        let first = decode(&token)?;
        let second = decode(&token)?;

        assert_eq!(first.challenge_id(), second.challenge_id());
        assert!(!first.challenge_id().is_empty());
        Ok(())
    }
}
