use anyhow::{Context, Result};
use hydra_sys::shurbstree::create_batch_devices;
use hydra_sys::{
    decode_device_client_infor, default_hasher, encode_public_context_message,
    encode_verifier_response, find_device_shrubs_path_tag, gen_new_leaves,
    generate_verifier_resonse_infor_1, tcp_read_frame, tcp_send_frame,
    DEFAULT_RELYING_PARTY_ADDR, DEFAULT_VERIFIER_ADDR, KeyInfor, PublicContext,
};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<()> {
    let verifier_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_VERIFIER_ADDR.to_string());
    let relying_party_addr = std::env::args()
        .nth(2)
        .unwrap_or_else(|| DEFAULT_RELYING_PARTY_ADDR.to_string());

    let listener = TcpListener::bind(&verifier_addr)
        .await
        .with_context(|| format!("verifier 监听失败: {}", verifier_addr))?;

    println!("verifier 已启动，监听地址: {}", verifier_addr);
    println!("relying-party 默认地址: {}", relying_party_addr);
    println!("等待 attester 发送 dev_infor ...");

    loop {
        let (mut socket, peer) = listener.accept().await.context("接收 TCP 连接失败")?;
        println!("收到来自 {} 的连接", peer);

        if let Err(err) = handle_attester(&mut socket, &relying_party_addr).await {
            eprintln!("处理 attester 请求失败: {:#}", err);
        }
    }
}

async fn handle_attester(socket: &mut TcpStream, relying_party_addr: &str) -> Result<()> {
    let dev_infor_bytes = tcp_read_frame(socket).await?;
    let dev_infor = decode_device_client_infor(&dev_infor_bytes)
        .context("解析 attester 发送的 dev_infor 失败")?;

    println!("已接收 dev_infor，开始生成 dev_res、root 和 verifier 公钥 ...");

    let hasher_vfy = default_hasher();
    let mut oldleaves = gen_new_leaves();
    let verifierkey = KeyInfor::new();

    let mut dev_res =
        generate_verifier_resonse_infor_1(&dev_infor, &verifierkey, &mut oldleaves, &hasher_vfy);

    let mut root = vec![];
    let mut newleaves = gen_new_leaves();
    oldleaves.append(&mut newleaves);
    create_batch_devices(&mut root, &oldleaves, &hasher_vfy);

    let (merkel_path, merkel_tag) =
        find_device_shrubs_path_tag(&root, &oldleaves, &dev_infor.merkle_leaf, &hasher_vfy);
    dev_res.shrubs_path = merkel_path;
    dev_res.shrubs_tag = merkel_tag;

    let public_context = PublicContext {
        root,
        verifier_pk: verifierkey.verifying_key,
    };

    let response = encode_verifier_response(&dev_res, &public_context)?;
    tcp_send_frame(socket, &response)
        .await
        .context("发送 dev_res 给 attester 失败")?;
    println!("已将 dev_res 和公开上下文返回给 attester");

    publish_public_context(relying_party_addr, &public_context).await?;
    Ok(())
}

async fn publish_public_context(addr: &str, public_context: &PublicContext) -> Result<()> {
    let mut stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("连接 relying-party 失败: {}。请先启动 relying-party", addr))?;
    let message = encode_public_context_message(public_context)?;
    tcp_send_frame(&mut stream, &message)
        .await
        .context("向 relying-party 发布 root 和 verifier 公钥失败")?;
    println!("已向 relying-party 发布公开 root 和 verifier 公钥");
    Ok(())
}
