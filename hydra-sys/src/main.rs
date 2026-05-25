use anyhow::{Context, Result};
use hydra_sys::{
    decode_verifier_response, default_hasher, encode_device_client_infor, encode_evidence_message,
    generate_device_client_infor, generate_device_evidence, tcp_read_frame, tcp_send_frame,
    DEFAULT_RELYING_PARTY_ADDR, DEFAULT_VERIFIER_ADDR, KeyInfor,
};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<()> {
    let verifier_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_VERIFIER_ADDR.to_string());
    let relying_party_addr = std::env::args()
        .nth(2)
        .unwrap_or_else(|| DEFAULT_RELYING_PARTY_ADDR.to_string());

    println!("attester 启动");
    println!("verifier 地址: {}", verifier_addr);
    println!("relying-party 地址: {}", relying_party_addr);

    let hasher_dev = default_hasher();
    let dev_key = KeyInfor::new();
    let dev_infor = generate_device_client_infor(&dev_key, &hasher_dev);

    println!("已生成 dev_key 和 dev_infor，准备发送给 verifier ...");

    let mut verifier_stream = TcpStream::connect(&verifier_addr)
        .await
        .with_context(|| format!("连接 verifier 失败: {}。请先启动 verifier", verifier_addr))?;

    let dev_infor_bytes = encode_device_client_infor(&dev_infor)?;
    tcp_send_frame(&mut verifier_stream, &dev_infor_bytes)
        .await
        .context("发送 dev_infor 给 verifier 失败")?;

    let verifier_response_bytes = tcp_read_frame(&mut verifier_stream)
        .await
        .context("接收 verifier 返回的 dev_res 失败")?;
    let (dev_res, public_context) = decode_verifier_response(&verifier_response_bytes)
        .context("解析 verifier 返回的 dev_res/public_context 失败")?;

    println!("已收到 verifier 返回的 dev_res，开始生成 reply 和 sig ...");

    let (reply, sig) = generate_device_evidence(
        &public_context.root,
        &dev_key,
        &dev_infor,
        &dev_res,
        &hasher_dev,
    );

    println!("已生成 attester 证据，准备发送给 relying-party ...");

    let mut relying_party_stream = TcpStream::connect(&relying_party_addr)
        .await
        .with_context(|| format!("连接 relying-party 失败: {}。请先启动 relying-party", relying_party_addr))?;

    let evidence_message = encode_evidence_message(&reply, &sig)?;
    tcp_send_frame(&mut relying_party_stream, &evidence_message)
        .await
        .context("发送 reply 和 sig 给 relying-party 失败")?;

    let ack = tcp_read_frame(&mut relying_party_stream)
        .await
        .context("读取 relying-party 返回结果失败")?;
    println!("relying-party 返回: {}", String::from_utf8_lossy(&ack));

    Ok(())
}
