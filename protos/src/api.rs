
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use protos::attestation_response;
use protos::attestation_service_server::{
    AttestationService as AttestationServiceApi, AttestationServiceServer,
};
use protos::verifier_service_client::VerifierServiceClient;
use protos::{
    AttestationRequest, AttestationResponse, ChallengeRequest, ChallengeResponse, ErrorCode,
    EvidenceList, Mode, Tee, VerificationRequest, VerificationResponse, VerifierChallengeRequest,
    VerifierRequest,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::core::AttesterEvidence;
use crate::service::{
    AttestationOutcome, AttesterApplicationService, ServiceError, ServiceErrorKind, VerifierGateway,
};

pub fn into_grpc_service(
    service: Arc<AttesterApplicationService>,
) -> AttestationServiceServer<GrpcAttesterService> {
    AttestationServiceServer::new(GrpcAttesterService { service })
}

pub struct GrpcVerifierGateway {
    verifier_addr: String,
}

impl GrpcVerifierGateway {
    pub fn new(verifier_addr: String) -> Self {
        Self { verifier_addr }
    }

    async fn connect(&self) -> Result<VerifierServiceClient<tonic::transport::Channel>> {
        let endpoint = format!("http://{}", self.verifier_addr);
        Ok(VerifierServiceClient::connect(endpoint).await?)
    }
}

#[async_trait]
impl VerifierGateway for GrpcVerifierGateway {
    async fn issue_challenge(
        &self,
        tee: Tee,
        mode: Mode,
        requested_nonce: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut client = self.connect().await?;
        let req = VerifierChallengeRequest {
            tee: tee as i32,
            mode: mode as i32,
            nonce: requested_nonce.to_vec(),
        };
        let response = client
            .issue_challenge(Request::new(req))
            .await?
            .into_inner();
        if response.error_code != ErrorCode::Ok as i32 {
            return Err(anyhow!(
                "verifier issue challenge failed with code {}",
                response.error_code
            ));
        }
        Ok((response.nonce, response.challenge_token))
    }

    async fn verify(
        &self,
        tee: Tee,
        raw_evidence: &[u8],
        challenge_token: &[u8],
        evidence_source: &str,
    ) -> Result<String> {
        let mut client = self.connect().await?;
        let req = VerifierRequest {
            tee: tee as i32,
            evidence: raw_evidence.to_vec(),
            challenge_token: challenge_token.to_vec(),
            evidence_source: evidence_source.to_string(),
        };
        let response = client.verify(Request::new(req)).await?.into_inner();
        if response.error_code != ErrorCode::Ok as i32 {
            return Err(anyhow!(
                "verifier service failed with code {}",
                response.error_code
            ));
        }
        Ok(String::from_utf8(response.attestation_token)?)
    }
}

pub struct GrpcAttesterService {
    service: Arc<AttesterApplicationService>,
}

#[tonic::async_trait]
impl AttestationServiceApi for GrpcAttesterService {
    async fn get_challenge(
        &self,
        request: Request<ChallengeRequest>,
    ) -> Result<Response<ChallengeResponse>, Status> {
        let req = request.into_inner();
        let mode = Mode::try_from(req.mode).unwrap_or(Mode::Unspecified);
        Ok(Response::new(
            match self.service.issue_challenge(mode, req.nonce).await {
                Ok(response) => ChallengeResponse {
                    error_code: ErrorCode::Ok as i32,
                    nonce: response.nonce,
                    challenge_token: response.challenge_token,
                },
                Err(err) => ChallengeResponse {
                    error_code: error_code_for(&err) as i32,
                    nonce: Vec::new(),
                    challenge_token: Vec::new(),
                },
            },
        ))
    }

    async fn attestation_evaluate(
        &self,
        request: Request<AttestationRequest>,
    ) -> Result<Response<AttestationResponse>, Status> {
        let req = request.into_inner();
        let mode = Mode::try_from(req.mode).unwrap_or(Mode::Unspecified);
        Ok(Response::new(
            match self
                .service
                .attestation_evaluate(mode, req.challenge_token)
                .await
            {
                Ok(AttestationOutcome::AttestationToken(token)) => AttestationResponse {
                    error_code: ErrorCode::Ok as i32,
                    result: Some(attestation_response::Result::AttestationToken(token)),
                },
                Ok(AttestationOutcome::EvidenceList(evidence)) => AttestationResponse {
                    error_code: ErrorCode::Ok as i32,
                    result: Some(attestation_response::Result::EvidenceList(EvidenceList {
                        evidence: evidence.iter().map(AttesterEvidence::to_proto).collect(),
                    })),
                },
                Err(err) => AttestationResponse {
                    error_code: error_code_for(&err) as i32,
                    result: None,
                },
            },
        ))
    }

    async fn verification_evaluate(
        &self,
        request: Request<VerificationRequest>,
    ) -> Result<Response<VerificationResponse>, Status> {
        let req = request.into_inner();
        let evidence = req
            .evidence
            .into_iter()
            .map(|item| AttesterEvidence {
                init_data: item.init_data,
                runtime_data: item.runtime_data,
            })
            .collect();

        Ok(Response::new(
            match self
                .service
                .verification_evaluate(evidence, req.challenge_token)
                .await
            {
                Ok(response) => VerificationResponse {
                    error_code: ErrorCode::Ok as i32,
                    attestation_token: response.attestation_token,
                },
                Err(err) => VerificationResponse {
                    error_code: error_code_for(&err) as i32,
                    attestation_token: Vec::new(),
                },
            },
        ))
    }
}

fn error_code_for(err: &ServiceError) -> ErrorCode {
    match err.kind() {
        ServiceErrorKind::InvalidArgument => ErrorCode::InvalidArgument,
        ServiceErrorKind::UnsupportedMode => ErrorCode::UnsupportedMode,
        ServiceErrorKind::Internal => ErrorCode::Internal,
    }
}
