use anyhow::{Result, bail};
use protos::Tee;
use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceSource {
    File,
    GuestComponentsRest,
    GuestComponentsGrpc,
}

impl EvidenceSource {
    pub fn as_token_value(self) -> &'static str {
        match self {
            Self::File => "file-backed",
            Self::GuestComponentsRest => "guest-components-rest",
            Self::GuestComponentsGrpc => "guest-components-grpc",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct AttesterConfig {
    pub addr: String,
    pub tee: String,
    pub verifier_addr: String,
    #[serde(default = "default_evidence_source")]
    pub evidence_source: String,
    #[serde(default = "default_aa_evidence_url")]
    pub aa_evidence_url: String,
    pub cca_evidence_path: String,
    pub tdx_evidence_path: String,
    pub csv_evidence_path: String,
    pub kunpeng_evidence_path: String,
}

fn default_evidence_source() -> String {
    "file".to_string()
}

fn default_aa_evidence_url() -> String {
    "http://127.0.0.1:8006/aa/evidence".to_string()
}

impl AttesterConfig {
    pub fn load() -> Result<Self> {
        let path = std::env::var("RATS_ATTESTER_CONFIG")
            .or_else(|_| std::env::var("RATS_ATTESTATION_CONFIG"))
            .unwrap_or("configs/attester.toml".to_string());
        let content = std::fs::read_to_string(path)?;
        let mut config = toml::from_str::<Self>(&content)?;
        if let Ok(addr) = std::env::var("RATS_ATTESTER_ADDR") {
            config.addr = addr;
        }
        if let Ok(addr) = std::env::var("RATS_ATTESTATION_ADDR") {
            config.addr = addr;
        }
        if let Ok(tee) = std::env::var("RATS_TEE") {
            config.tee = tee;
        }
        if let Ok(verifier_addr) = std::env::var("RATS_VERIFIER_ADDR") {
            config.verifier_addr = verifier_addr;
        }
        if let Ok(evidence_source) = std::env::var("RATS_EVIDENCE_SOURCE") {
            config.evidence_source = evidence_source;
        }
        if let Ok(aa_evidence_url) = std::env::var("RATS_AA_EVIDENCE_URL") {
            config.aa_evidence_url = aa_evidence_url;
        }
        if let Ok(cca_evidence_path) = std::env::var("RATS_CCA_EVIDENCE_PATH") {
            config.cca_evidence_path = cca_evidence_path;
        }
        if let Ok(tdx_evidence_path) = std::env::var("RATS_TDX_EVIDENCE_PATH") {
            config.tdx_evidence_path = tdx_evidence_path;
        }
        if let Ok(csv_evidence_path) = std::env::var("RATS_CSV_EVIDENCE_PATH") {
            config.csv_evidence_path = csv_evidence_path;
        }
        if let Ok(kunpeng_evidence_path) = std::env::var("RATS_KUNPENG_EVIDENCE_PATH") {
            config.kunpeng_evidence_path = kunpeng_evidence_path;
        }
        Ok(config)
    }

    pub fn parse_tee(&self) -> Result<Tee> {
        match self.tee.to_ascii_lowercase().as_str() {
            "cca" => Ok(Tee::Cca),
            "tdx" => Ok(Tee::Tdx),
            "csv" => Ok(Tee::Csv),
            "kunpeng" => Ok(Tee::Kunpeng),
            _ => bail!("unsupported tee in attester config"),
        }
    }

    pub fn parse_evidence_source(&self) -> Result<EvidenceSource> {
        match self.evidence_source.to_ascii_lowercase().as_str() {
            "file" | "fixture" | "file-backed" => Ok(EvidenceSource::File),
            "guest-components-rest" | "guest_components_rest" | "coco-rest" | "aa-rest" => {
                Ok(EvidenceSource::GuestComponentsRest)
            }
            "guest-components-grpc" | "guest_components_grpc" | "aa-grpc" => {
                Ok(EvidenceSource::GuestComponentsGrpc)
            }
            _ => bail!("unsupported evidence_source in attester config"),
        }
    }
}
