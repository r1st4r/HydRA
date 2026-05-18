use anyhow::{Context, Result};
use hydra_sys::{
    decode_evidence_message, decode_public_context_message, rely_party_verification,
    tcp_read_frame, tcp_send_frame, DEFAULT_RELYING_PARTY_ADDR, MSG_EVIDENCE,
    MSG_PUBLIC_CONTEXT, PublicContext,
};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<()> {
    let relying_party_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_RELYING_PARTY_ADDR.to_string());

    let listener = TcpListener::bind(&relying_party_addr)
        .await
        .with_context(|| format!("relying-party 监听失败: {}", relying_party_addr))?;

    println!("relying-party 已启动，监听地址: {}", relying_party_addr);
    println!("等待 verifier 发布公开 root/verifier_pk，或等待 attester 发送 evidence ...");

    let mut public_context: Option<PublicContext> = None;

    loop {
        let (mut socket, peer) = listener.accept().await.context("接收 TCP 连接失败")?;
        println!("收到来自 {} 的连接", peer);

        if let Err(err) = handle_message(&mut socket, &mut public_context).await {
            eprintln!("处理 relying-party 消息失败: {:#}", err);
            let _ = tcp_send_frame(&mut socket, format!("error: {:#}", err).as_bytes()).await;
        }
    }
}

async fn handle_message(
    socket: &mut TcpStream,
    public_context: &mut Option<PublicContext>,
) -> Result<()> {
    let message = tcp_read_frame(socket).await?;

    if message.starts_with(MSG_PUBLIC_CONTEXT) {
        let ctx = decode_public_context_message(&message)
            .context("解析 verifier 发布的 PublicContext 失败")?;
        println!("已接收 verifier 发布的公开 root 和 verifier 公钥");
        println!("root 元素数量: {}", ctx.root.len());
        *public_context = Some(ctx);
        return Ok(());
    }

    if message.starts_with(MSG_EVIDENCE) {
        let (reply, sig) = decode_evidence_message(&message)
            .context("解析 attester 发送的 Evidence 消息失败")?;

        let Some(ctx) = public_context.as_ref() else {
            tcp_send_frame(socket, b"verification failed: missing public root/verifier_pk").await?;
            anyhow::bail!("尚未收到 verifier 发布的公开 root 和 verifier 公钥，请先让 verifier 处理一次 attester 请求");
        };

        println!("已接收 attester 发送的 reply 和 sig，开始验证 ...");
        rely_party_verification(&ctx.root, &reply, sig, &ctx.verifier_pk);
        tcp_send_frame(socket, b"verification finished; check relying-party console output").await?;
        return Ok(());
    }

    anyhow::bail!("未知消息类型，前 4 字节: {:?}", message.get(..4));
}
