use anyhow::{Context, Result};
use hydra_sys::{
    decode_evidence_message, decode_public_context_message, decode_signed_device_client_infor_message,
    encode_relying_party_signed_device_client_infor_message, load_public_context,
    rely_party_verification, save_public_context, sign_relying_party_device_client_infor_to_wire,
    tcp_read_frame, tcp_send_frame, verify_evidence_reply_attester_signature,
    verify_signed_device_client_infor_wire, DATA_DIR_NAME, DEFAULT_RELYING_PARTY_ADDR,
    DEFAULT_VERIFIER_ADDR, KeyInfor, Model, PublicContext, MSG_DEVICE_INFOR, MSG_EVIDENCE,
    MSG_PUBLIC_CONTEXT, PUBLIC_CONTEXT_FILE,
};
use std::path::PathBuf;
use tokio::net::{TcpListener, TcpStream};

struct RelyingPartyState {
    public_context: Option<PublicContext>,
}

impl RelyingPartyState {
    fn new(public_context: Option<PublicContext>) -> Self {
        Self { public_context }
    }
}

fn role_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DATA_DIR_NAME)
}

fn role_data_file(name: &str) -> PathBuf {
    role_data_dir().join(name)
}

fn parse_args() -> Result<(String, String)> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let relying_party_addr = args
        .first()
        .cloned()
        .unwrap_or_else(|| DEFAULT_RELYING_PARTY_ADDR.to_string());

    let verifier_addr = match args.get(1) {
        Some(value) if Model::from_arg(value).is_ok() => args
            .get(2)
            .cloned()
            .unwrap_or_else(|| DEFAULT_VERIFIER_ADDR.to_string()),
        Some(value) => value.clone(),
        None => DEFAULT_VERIFIER_ADDR.to_string(),
    };

    Ok((relying_party_addr, verifier_addr))
}

#[tokio::main]
async fn main() -> Result<()> {
    let (relying_party_addr, verifier_addr) = parse_args()?;
    let listener = TcpListener::bind(&relying_party_addr)
        .await
        .with_context(|| format!("relying-party listen failed: {}", relying_party_addr))?;

    println!("relying-party started, listening on: {}", relying_party_addr);
    println!("verifier address: {}", verifier_addr);
    println!("mode is detected from incoming messages");

    let public_context_path = role_data_file(PUBLIC_CONTEXT_FILE);
    let initial_public_context = match load_public_context(&public_context_path) {
        Ok(ctx) => {
            println!(
                "loaded local verifier public context; root element count: {}",
                ctx.root.len()
            );
            Some(ctx)
        }
        Err(_) => None,
    };

    let mut state = RelyingPartyState::new(initial_public_context);
    let relying_party_key = KeyInfor::new();

    loop {
        let (mut socket, peer) = listener.accept().await.context("accept TCP failed")?;
        println!("accepted connection from {}", peer);

        if let Err(err) =
            handle_message(&mut socket, &mut state, &verifier_addr, &relying_party_key).await
        {
            eprintln!("handle relying-party message failed: {:#}", err);
            let _ = tcp_send_frame(&mut socket, format!("error: {:#}", err).as_bytes()).await;
        }
    }
}

async fn handle_message(
    socket: &mut TcpStream,
    state: &mut RelyingPartyState,
    verifier_addr: &str,
    relying_party_key: &KeyInfor,
) -> Result<()> {
    let message = tcp_read_frame(socket).await?;

    if message.starts_with(MSG_PUBLIC_CONTEXT) {
        let ctx =
            decode_public_context_message(&message).context("decode verifier PublicContext failed")?;
        println!("received verifier public root and public key");
        println!("root element count: {}", ctx.root.len());
        save_public_context(role_data_file(PUBLIC_CONTEXT_FILE), &ctx)
            .context("save verifier PublicContext failed")?;
        state.public_context = Some(ctx);
        println!("local verifier public context saved/replaced");
        return Ok(());
    }

    if message.starts_with(MSG_DEVICE_INFOR) {
        let signed_dev_infor = decode_signed_device_client_infor_message(&message)
            .context("decode signed DeviceClientInfor failed")?;
        let dev_infor = verify_signed_device_client_infor_wire(&signed_dev_infor)
            .context("verify attester DeviceClientInfor signature failed")?;
        println!("attester DeviceClientInfor signature verified");
        if dev_infor.mode != Model::BackgroundCheck {
            anyhow::bail!(
                "relying-party accepts DeviceClientInfor only in background_check mode; passport mode must send EvidenceReply"
            );
        }

        let relying_party_signed =
            sign_relying_party_device_client_infor_to_wire(signed_dev_infor, relying_party_key)?;
        let relying_party_message =
            encode_relying_party_signed_device_client_infor_message(&relying_party_signed)?;
        let mut verifier_stream = TcpStream::connect(verifier_addr)
            .await
            .with_context(|| format!("connect verifier failed: {}", verifier_addr))?;
        tcp_send_frame(&mut verifier_stream, &relying_party_message)
            .await
            .context("forward relying-party signed DeviceClientInfor to verifier failed")?;
        let ack = tcp_read_frame(&mut verifier_stream)
            .await
            .context("read verifier DeviceClientInfor ack failed")?;
        tcp_send_frame(socket, &ack).await?;
        println!(
            "{:?} DeviceClientInfor signed by relying-party and forwarded to verifier",
            dev_infor.mode
        );
        return Ok(());
    }

    if message.starts_with(MSG_EVIDENCE) {
        let (reply, sig) =
            decode_evidence_message(&message).context("decode attester Evidence failed")?;
        verify_evidence_reply_attester_signature(&reply, &sig)
            .context("verify attester EvidenceReply signature failed")?;
        println!("attester EvidenceReply signature verified");

        let Some(ctx) = state.public_context.as_ref() else {
            tcp_send_frame(socket, b"verification failed: missing public root/verifier_pk").await?;
            anyhow::bail!("missing verifier public root and verifier public key");
        };

        println!("received Evidence; starting relying-party verification");
        let verified = rely_party_verification(&ctx.root, &reply, sig, &ctx.verifier_pk)
            .context("relying-party proof verification failed")?;
        let ack = if verified {
            b"verification success".as_slice()
        } else {
            b"verification failed".as_slice()
        };
        tcp_send_frame(socket, ack).await?;
        return Ok(());
    }

    anyhow::bail!("unknown message type, first 4 bytes: {:?}", message.get(..4));
}
