
use anyhow::Result;
use async_trait::async_trait;
use protos::{Mode, Tee};
use std::sync::Arc;
use tracing::{info, warn};

use crate::core::{AttestationChallenge, Attester, AttesterEvidence, decode_attestation_challenge};

const DEFAULT_EVIDENCE_SOURCE: &str = "file-backed";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedChallenge {
    pub nonce: Vec<u8>,
    pub challenge_token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationOutcome {
    AttestationToken(Vec<u8>),
    EvidenceList(Vec<AttesterEvidence>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    pub attestation_token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceErrorKind {
    InvalidArgument,
    UnsupportedMode,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    kind: ServiceErrorKind,
    message: String,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ServiceError {}

impl ServiceError {
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self {
            kind: ServiceErrorKind::InvalidArgument,
            message: message.into(),
        }
    }

    pub fn unsupported_mode(message: impl Into<String>) -> Self {
        Self {
            kind: ServiceErrorKind::UnsupportedMode,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            kind: ServiceErrorKind::Internal,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> &ServiceErrorKind {
        &self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[async_trait]
pub trait VerifierGateway: Send + Sync {
    async fn issue_challenge(
        &self,
        tee: Tee,
        mode: Mode,
        requested_nonce: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)>;

    async fn verify(
        &self,
        tee: Tee,
        raw_evidence: &[u8],
        challenge_token: &[u8],
        evidence_source: &str,
    ) -> Result<String>;
}

pub struct AttesterApplicationService {
    tee: Tee,
    evidence_source: String,
    attester: Arc<dyn Attester>,
    verifier_gateway: Arc<dyn VerifierGateway>,
}

impl AttesterApplicationService {
    pub fn new(
        tee: Tee,
        attester: Arc<dyn Attester>,
        verifier_gateway: Arc<dyn VerifierGateway>,
    ) -> Self {
        Self::new_with_evidence_source(tee, DEFAULT_EVIDENCE_SOURCE, attester, verifier_gateway)
    }

    pub fn new_with_evidence_source(
        tee: Tee,
        evidence_source: impl Into<String>,
        attester: Arc<dyn Attester>,
        verifier_gateway: Arc<dyn VerifierGateway>,
    ) -> Self {
        Self {
            tee,
            evidence_source: evidence_source.into(),
            attester,
            verifier_gateway,
        }
    }

    pub async fn issue_challenge(
        &self,
        mode: Mode,
        requested_nonce: Vec<u8>,
    ) -> std::result::Result<IssuedChallenge, ServiceError> {
        if mode == Mode::Unspecified {
            warn!(tee = ?self.tee, mode = ?mode, "rejected challenge request");
            return Err(ServiceError::invalid_argument("unsupported mode"));
        }

        info!(
            tee = ?self.tee,
            mode = ?mode,
            requested_nonce_len = requested_nonce.len(),
            "requesting verifier challenge"
        );
        let (nonce, challenge_token) = match self
            .verifier_gateway
            .issue_challenge(self.tee, mode, &requested_nonce)
            .await
        {
            Ok(challenge) => challenge,
            Err(err) => {
                warn!(
                    tee = ?self.tee,
                    mode = ?mode,
                    error = %err,
                    "failed to issue verifier challenge"
                );
                return Err(ServiceError::internal(err.to_string()));
            }
        };
        info!(
            tee = ?self.tee,
            mode = ?mode,
            nonce_len = nonce.len(),
            challenge_token_len = challenge_token.len(),
            "issued verifier challenge"
        );

        Ok(IssuedChallenge {
            nonce,
            challenge_token,
        })
    }

    pub async fn attestation_evaluate(
        &self,
        mode: Mode,
        challenge_token: Vec<u8>,
    ) -> std::result::Result<AttestationOutcome, ServiceError> {
        let challenge = self.decode_challenge(Some(mode as i32), &challenge_token)?;
        info!(
            tee = ?self.tee,
            mode = ?challenge.mode,
            evidence_source = %self.evidence_source,
            runtime_data_len = challenge.nonce.len(),
            "collecting attestation evidence"
        );
        let evidence = match self.attester.get_evidence(self.tee, &challenge).await {
            Ok(evidence) => evidence,
            Err(err) => {
                warn!(
                    tee = ?self.tee,
                    mode = ?challenge.mode,
                    evidence_source = %self.evidence_source,
                    error = %err,
                    "failed to collect attestation evidence"
                );
                return Err(ServiceError::internal(err.to_string()));
            }
        };
        info!(
            tee = ?self.tee,
            mode = ?challenge.mode,
            evidence_source = %self.evidence_source,
            evidence_count = evidence.len(),
            first_evidence_len = ?evidence.first().map(|evidence| evidence.runtime_data.len()),
            "collected attestation evidence"
        );

        match challenge.mode {
            Mode::Passport => {
                let raw = evidence
                    .first()
                    .ok_or_else(|| ServiceError::internal("missing evidence"))?;
                let token = match self
                    .verifier_gateway
                    .verify(
                        self.tee,
                        &raw.runtime_data,
                        &challenge.challenge_token,
                        &self.evidence_source,
                    )
                    .await
                {
                    Ok(token) => token,
                    Err(err) => {
                        warn!(
                            tee = ?self.tee,
                            mode = ?challenge.mode,
                            evidence_source = %self.evidence_source,
                            evidence_len = raw.runtime_data.len(),
                            error = %err,
                            "passport verification failed"
                        );
                        return Err(ServiceError::internal(err.to_string()));
                    }
                };
                info!(
                    tee = ?self.tee,
                    mode = ?challenge.mode,
                    evidence_source = %self.evidence_source,
                    attestation_token_len = token.len(),
                    "passport verification accepted"
                );
                Ok(AttestationOutcome::AttestationToken(token.into_bytes()))
            }
            Mode::BackgroundCheck | Mode::Mix => {
                info!(
                    tee = ?self.tee,
                    mode = ?challenge.mode,
                    evidence_source = %self.evidence_source,
                    "returning evidence list for deferred verification"
                );
                Ok(AttestationOutcome::EvidenceList(evidence))
            }
            Mode::Unspecified => {
                warn!(tee = ?self.tee, mode = ?challenge.mode, "rejected unsupported mode");
                Err(ServiceError::unsupported_mode("unsupported mode"))
            }
        }
    }

    pub async fn verification_evaluate(
        &self,
        evidence: Vec<AttesterEvidence>,
        challenge_token: Vec<u8>,
    ) -> std::result::Result<VerificationResult, ServiceError> {
        self.decode_challenge(None, &challenge_token)?;
        let evidence = evidence
            .first()
            .ok_or_else(|| ServiceError::invalid_argument("missing evidence"))?;

        info!(
            tee = ?self.tee,
            evidence_source = %self.evidence_source,
            evidence_len = evidence.runtime_data.len(),
            "requesting verifier evaluation"
        );
        let token = match self
            .verifier_gateway
            .verify(
                self.tee,
                &evidence.runtime_data,
                &challenge_token,
                &self.evidence_source,
            )
            .await
        {
            Ok(token) => token,
            Err(err) => {
                warn!(
                    tee = ?self.tee,
                    evidence_source = %self.evidence_source,
                    evidence_len = evidence.runtime_data.len(),
                    error = %err,
                    "verifier evaluation failed"
                );
                return Err(ServiceError::internal(err.to_string()));
            }
        };
        info!(
            tee = ?self.tee,
            evidence_source = %self.evidence_source,
            attestation_token_len = token.len(),
            "verifier evaluation accepted"
        );

        Ok(VerificationResult {
            attestation_token: token.into_bytes(),
        })
    }

    fn decode_challenge(
        &self,
        expected_mode: Option<i32>,
        challenge_token: &[u8],
    ) -> std::result::Result<AttestationChallenge, ServiceError> {
        decode_attestation_challenge(self.tee, expected_mode, challenge_token)
            .map_err(|err| ServiceError::invalid_argument(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, anyhow};
    use protos::challenge;
    use std::sync::Mutex;

    struct FakeAttester {
        result: Mutex<Option<Result<Vec<AttesterEvidence>>>>,
    }

    impl FakeAttester {
        fn new(result: Result<Vec<AttesterEvidence>>) -> Self {
            Self {
                result: Mutex::new(Some(result)),
            }
        }
    }

    #[async_trait]
    impl Attester for FakeAttester {
        async fn get_evidence(
            &self,
            _tee: Tee,
            _challenge: &AttestationChallenge,
        ) -> Result<Vec<AttesterEvidence>> {
            self.result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(anyhow!("missing attester result")))
        }
    }

    struct FakeVerifierGateway {
        issue_result: Mutex<Option<Result<IssueResult>>>,
        verify_result: Mutex<Option<Result<String>>>,
        seen_evidence_source: Mutex<Option<String>>,
    }

    type IssueResult = (Vec<u8>, Vec<u8>);

    impl FakeVerifierGateway {
        fn new(issue_result: Result<IssueResult>, verify_result: Result<String>) -> Self {
            Self {
                issue_result: Mutex::new(Some(issue_result)),
                verify_result: Mutex::new(Some(verify_result)),
                seen_evidence_source: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl VerifierGateway for FakeVerifierGateway {
        async fn issue_challenge(
            &self,
            _tee: Tee,
            _mode: Mode,
            _requested_nonce: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>)> {
            self.issue_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(anyhow!("missing issue result")))
        }

        async fn verify(
            &self,
            _tee: Tee,
            _raw_evidence: &[u8],
            _challenge_token: &[u8],
            evidence_source: &str,
        ) -> Result<String> {
            *self.seen_evidence_source.lock().unwrap() = Some(evidence_source.to_string());
            self.verify_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(anyhow!("missing verify result")))
        }
    }

    fn challenge_token(mode: Mode) -> Result<Vec<u8>> {
        let (_nonce, token) = challenge::issue(
            Tee::Csv as i32,
            mode as i32,
            Some(b"expected-nonce"),
            60,
            b"test-key",
        )?;
        Ok(token)
    }

    #[tokio::test]
    async fn issue_challenge_rejects_unspecified_mode() {
        let service = AttesterApplicationService::new(
            Tee::Csv,
            Arc::new(FakeAttester::new(Ok(Vec::new()))),
            Arc::new(FakeVerifierGateway::new(
                Ok((Vec::new(), Vec::new())),
                Ok(String::new()),
            )),
        );

        let result = service.issue_challenge(Mode::Unspecified, Vec::new()).await;
        assert_eq!(
            result.expect_err("mode should be rejected").kind(),
            &ServiceErrorKind::InvalidArgument
        );
    }

    #[tokio::test]
    async fn attestation_evaluate_returns_token_for_passport() -> Result<()> {
        let gateway = Arc::new(FakeVerifierGateway::new(
            Ok((Vec::new(), Vec::new())),
            Ok("signed-token".to_string()),
        ));
        let service = AttesterApplicationService::new_with_evidence_source(
            Tee::Csv,
            "guest-components-rest",
            Arc::new(FakeAttester::new(Ok(vec![AttesterEvidence {
                init_data: b"nonce".to_vec(),
                runtime_data: b"evidence".to_vec(),
            }]))),
            gateway.clone(),
        );

        let result = service
            .attestation_evaluate(Mode::Passport, challenge_token(Mode::Passport)?)
            .await?;

        assert_eq!(
            result,
            AttestationOutcome::AttestationToken(b"signed-token".to_vec())
        );
        assert_eq!(
            gateway.seen_evidence_source.lock().unwrap().as_deref(),
            Some("guest-components-rest")
        );
        Ok(())
    }

    #[tokio::test]
    async fn attestation_evaluate_returns_evidence_for_background_check() -> Result<()> {
        let evidence = AttesterEvidence {
            init_data: b"nonce".to_vec(),
            runtime_data: b"evidence".to_vec(),
        };
        let service = AttesterApplicationService::new(
            Tee::Csv,
            Arc::new(FakeAttester::new(Ok(vec![evidence.clone()]))),
            Arc::new(FakeVerifierGateway::new(
                Ok((Vec::new(), Vec::new())),
                Ok("unused".to_string()),
            )),
        );

        let result = service
            .attestation_evaluate(
                Mode::BackgroundCheck,
                challenge_token(Mode::BackgroundCheck)?,
            )
            .await?;

        assert_eq!(result, AttestationOutcome::EvidenceList(vec![evidence]));
        Ok(())
    }

    #[tokio::test]
    async fn verification_evaluate_rejects_missing_evidence() -> Result<()> {
        let service = AttesterApplicationService::new(
            Tee::Csv,
            Arc::new(FakeAttester::new(Ok(Vec::new()))),
            Arc::new(FakeVerifierGateway::new(
                Ok((Vec::new(), Vec::new())),
                Ok("unused".to_string()),
            )),
        );

        let result = service
            .verification_evaluate(Vec::new(), challenge_token(Mode::Passport)?)
            .await;

        assert_eq!(
            result.expect_err("missing evidence should fail").kind(),
            &ServiceErrorKind::InvalidArgument
        );
        Ok(())
    }
}
