use anyhow::{Result, bail};
use async_trait::async_trait;
use protos::Mode;

use crate::core::CliArgs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedChallenge {
    pub nonce: Vec<u8>,
    pub challenge_token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingPartyEvidence {
    pub init_data: Vec<u8>,
    pub runtime_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationOutcome {
    AttestationToken(Vec<u8>),
    EvidenceList(Vec<RelyingPartyEvidence>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowResult {
    pub mode: Mode,
    pub final_token: Vec<u8>,
}

#[async_trait]
pub trait AttestationGateway {
    async fn get_challenge(&mut self, mode: Mode, nonce: Vec<u8>) -> Result<IssuedChallenge>;
    async fn attest(&mut self, mode: Mode, challenge_token: Vec<u8>) -> Result<AttestationOutcome>;
    async fn verify(
        &mut self,
        evidence: Vec<RelyingPartyEvidence>,
        challenge_token: Vec<u8>,
    ) -> Result<Vec<u8>>;
}

pub struct RelyingPartyApplicationService<G> {
    gateway: G,
}

impl<G> RelyingPartyApplicationService<G> {
    pub fn new(gateway: G) -> Self {
        Self { gateway }
    }
}

impl<G> RelyingPartyApplicationService<G>
where
    G: AttestationGateway,
{
    pub async fn run(&mut self, args: CliArgs) -> Result<WorkflowResult> {
        let requested_nonce = args.requested_nonce()?;
        let challenge = self
            .gateway
            .get_challenge(args.mode, requested_nonce)
            .await?;
        let attestation = self
            .gateway
            .attest(args.mode, challenge.challenge_token.clone())
            .await?;

        let final_token = match attestation {
            AttestationOutcome::AttestationToken(token) => token,
            AttestationOutcome::EvidenceList(evidence) => {
                self.gateway
                    .verify(evidence, challenge.challenge_token)
                    .await?
            }
        };

        if final_token.is_empty() {
            bail!("verification returned empty token");
        }

        Ok(WorkflowResult {
            mode: args.mode,
            final_token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, anyhow};

    struct FakeGateway {
        get_challenge_result: Option<Result<IssuedChallenge>>,
        attest_result: Option<Result<AttestationOutcome>>,
        verify_result: Option<Result<Vec<u8>>>,
    }

    impl FakeGateway {
        fn new(
            get_challenge_result: Result<IssuedChallenge>,
            attest_result: Result<AttestationOutcome>,
            verify_result: Result<Vec<u8>>,
        ) -> Self {
            Self {
                get_challenge_result: Some(get_challenge_result),
                attest_result: Some(attest_result),
                verify_result: Some(verify_result),
            }
        }
    }

    #[async_trait]
    impl AttestationGateway for FakeGateway {
        async fn get_challenge(&mut self, _mode: Mode, _nonce: Vec<u8>) -> Result<IssuedChallenge> {
            self.get_challenge_result
                .take()
                .unwrap_or_else(|| Err(anyhow!("missing challenge result")))
        }

        async fn attest(
            &mut self,
            _mode: Mode,
            _challenge_token: Vec<u8>,
        ) -> Result<AttestationOutcome> {
            self.attest_result
                .take()
                .unwrap_or_else(|| Err(anyhow!("missing attest result")))
        }

        async fn verify(
            &mut self,
            _evidence: Vec<RelyingPartyEvidence>,
            _challenge_token: Vec<u8>,
        ) -> Result<Vec<u8>> {
            self.verify_result
                .take()
                .unwrap_or_else(|| Err(anyhow!("missing verify result")))
        }
    }

    fn cli_args(mode: Mode) -> CliArgs {
        CliArgs {
            addr: "127.0.0.1:50051".to_string(),
            mode,
            nonce: "expected".to_string(),
            nonce_b64: None,
        }
    }

    #[tokio::test]
    async fn run_uses_attestation_token_for_passport() -> Result<()> {
        let gateway = FakeGateway::new(
            Ok(IssuedChallenge {
                nonce: b"nonce".to_vec(),
                challenge_token: b"challenge".to_vec(),
            }),
            Ok(AttestationOutcome::AttestationToken(
                b"signed-token".to_vec(),
            )),
            Ok(Vec::new()),
        );
        let mut service = RelyingPartyApplicationService::new(gateway);

        let result = service.run(cli_args(Mode::Passport)).await?;
        assert_eq!(result.final_token, b"signed-token");
        Ok(())
    }

    #[tokio::test]
    async fn run_verifies_evidence_for_background_check() -> Result<()> {
        let gateway = FakeGateway::new(
            Ok(IssuedChallenge {
                nonce: b"nonce".to_vec(),
                challenge_token: b"challenge".to_vec(),
            }),
            Ok(AttestationOutcome::EvidenceList(vec![
                RelyingPartyEvidence {
                    init_data: b"nonce".to_vec(),
                    runtime_data: b"evidence".to_vec(),
                },
            ])),
            Ok(b"verified-token".to_vec()),
        );
        let mut service = RelyingPartyApplicationService::new(gateway);

        let result = service.run(cli_args(Mode::BackgroundCheck)).await?;
        assert_eq!(result.final_token, b"verified-token");
        Ok(())
    }

    #[tokio::test]
    async fn run_rejects_empty_final_token() {
        let gateway = FakeGateway::new(
            Ok(IssuedChallenge {
                nonce: b"nonce".to_vec(),
                challenge_token: b"challenge".to_vec(),
            }),
            Ok(AttestationOutcome::AttestationToken(Vec::new())),
            Ok(Vec::new()),
        );
        let mut service = RelyingPartyApplicationService::new(gateway);

        let err = service
            .run(cli_args(Mode::Passport))
            .await
            .expect_err("empty token should fail");
        assert!(err.to_string().contains("empty token"));
    }
}

