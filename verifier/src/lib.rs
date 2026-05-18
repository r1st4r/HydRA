use identity_iota::core::{Url, Timestamp};
use identity_iota::credential::{CredentialBuilder, Subject};
use identity_iota::did::{CoreDID, DIDUrl};
use identity_iota::document::{DocumentBuilder, CoreDocument};
use identity_iota::verification::{VerificationMethod, MethodScope};
use identity_iota::verification::jwk::{Jwk, JwkParams, JwkParamsOkp};
use identity_iota::credential::Credential;
use iota_client::Client;
use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::consts::True;
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use base64_url::encode;
use tokio;
use hex::encode as Encode;
use chrono::Utc;
use identity_iota::credential::Status;
use k256::elliptic_curve::sec1::ToEncodedPoint;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let expiration = Timestamp::from_unix(Utc::now().timestamp() + 30 * 24 * 60 * 60)?;

    // STEP 1: 设备生成 Secp256k1 公钥
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // STEP 2: 创建 DID Document
    let encoded_point = verifying_key.to_encoded_point(true); // true=压缩，false=未压缩
    let did_iota = format!("did:bid:{}", Encode(encoded_point.as_bytes()));
    let validator_did: CoreDID = CoreDID::parse(did_iota)?;
    let mut document: CoreDocument = DocumentBuilder::default()
        .id(validator_did.clone())
        .build()?;

    let method_id = DIDUrl::parse(&format!("{}#device-key", document.id()))?;

    // 构造 JWK (最新 Okp)
    let key_bytes = verifying_key.to_bytes();
    let jwk_okp = JwkParamsOkp {
        crv: "secp256k1".to_string(),
        d: None,
        x: encode(&key_bytes), // Base64URL
    };
    let jwk = Jwk::from_params(JwkParams::Okp(jwk_okp));

    let vm: VerificationMethod = VerificationMethod::new_from_jwk(
        document.id().clone(),
        jwk,
        Some("device-key"),
    )?;

    //document.insert_method(vm.clone(), MethodScope::authentication())?;
    document.insert_method(vm, MethodScope::assertion_method())?;
    


    println!("DID Document created:\n{:#?}", document);

    // STEP 3: 创建 VC
    let device_did = document.id().to_string();
    let mut properties = BTreeMap::new();
    properties.insert("status".to_string(), "trusted".into());
    let subject = Subject::with_id_and_properties(Url::parse(&device_did)?, properties);

    let mut properties = BTreeMap::new();
    properties.insert("status".to_string(), "trusted".into()); // 或 "expired"/"revoked"
    let subject = Subject::with_id_and_properties(Url::parse(&device_did)?, properties);

    let vc: Credential<()> = CredentialBuilder::<()>::default()
        .issuer(Url::parse(&validator_did.to_string())?)
        .subject(subject)
        .issuance_date(Timestamp::now_utc())
        .expiration_date(expiration)
        .build()?;

    println!("Generated VC:\n{:#?}", vc);

    //STEP 4: 构造 IOTA 客户端并发布
    let iota_client = Client::builder()
        .with_node("api.testnet.iota.cafe:443")?
        .finish()
        .await?;
// let iota_client = Client::builder()
//     .with_node("https://rpc.testnet.sui.io")?
//     .with_node("https://sui-testnet.nodeinfra.io")?
//     .with_node("https://sui-testnet-rpc.alltheblocks.net")?
//     .finish()
//     .await?;

    // STEP 6: 更新状态为 expired
    let mut expired_properties = BTreeMap::new();
    expired_properties.insert("status".to_string(), "expired".into());
    let expired_subject = Subject::with_id_and_properties(Url::parse(&device_did)?, expired_properties);

    let expired_vc: Credential<()> = CredentialBuilder::default()
        .issuer(Url::parse(&validator_did.to_string())?)
        .subject(expired_subject)
        .issuance_date(Timestamp::now_utc())
        .build()?;

    let expired_payload = serde_json::to_string(&expired_vc)?;
    let _ = iota_client
        .message()
        .with_index("DEVICE_VC")
        .with_data(expired_payload.into_bytes())
        .finish()
        .await?;
    println!("Published expired VC");

    // STEP 7: 撤销 VC
    let mut revoked_properties = BTreeMap::new();
    revoked_properties.insert("status".to_string(), "revoked".into());
    let revoked_subject = Subject::with_id_and_properties(Url::parse(&device_did)?, revoked_properties);

    let revoked_vc: Credential<()> = CredentialBuilder::default()
        .issuer(Url::parse(&validator_did.to_string())?)
        .subject(revoked_subject)
        .issuance_date(Timestamp::now_utc())
        .build()?;

    let revoked_payload = serde_json::to_string(&revoked_vc)?;
    let _ = iota_client
        .message()
        .with_index("DEVICE_VC")
        .with_data(revoked_payload.into_bytes())
        .finish()
        .await?;
    println!("Revoked VC on Tangle");

    Ok(())
}
