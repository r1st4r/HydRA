use anyhow::{Context, Result};
use hydra_sys::shurbstree::create_batch_devices;
use hydra_sys::{
    BlsScalar, DEFAULT_RELYING_PARTY_ADDR, DEFAULT_VERIFIER_ADDR, KeyInfor, MSG_DEVICE_INFOR,
    MSG_RELYING_PARTY_DEVICE_INFOR, Model, Poseidon, PublicContext,
    decode_relying_party_signed_device_client_infor_message,
    decode_signed_device_client_infor_message, default_hasher, encode_encrypted_verifier_response,
    encode_public_context_message, find_device_shrubs_path_tag, generate_device_authoried_infor,
    insert_batch_devices, save_response_device_infor, tcp_read_frame, tcp_send_frame,
    verifier_compute_sig, DATA_DIR_NAME,
    verify_relying_party_signed_device_client_infor_wire, verify_signed_device_client_infor_wire,
};
use rayon::prelude::*;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const BATCH_INTERVAL: Duration = Duration::from_secs(2 * 60);

fn role_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DATA_DIR_NAME)
}

#[derive(Clone)]
struct AttesterSession {
    socket: Arc<Mutex<TcpStream>>,
    dev_infor: hydra_sys::DeviceClientInfor,
    merkle_leaf: BlsScalar,
    response: Option<hydra_sys::ResponseDeviceInfor>,
    attester_addr: String,
}

struct VerifierState {
    root: Vec<BlsScalar>,
    old_leaves: Vec<BlsScalar>,
    pending: Vec<AttesterSession>,
    active: Vec<AttesterSession>,
    has_created_tree: bool,
    batch_timer_running: bool,
}

impl VerifierState {
    fn new() -> Self {
        Self {
            root: Vec::new(),
            old_leaves: Vec::new(),
            pending: Vec::new(),
            active: Vec::new(),
            has_created_tree: false,
            batch_timer_running: false,
        }
    }
}

fn parse_args() -> (String, Vec<String>) {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verifier_addr = args
        .first()
        .cloned()
        .unwrap_or_else(|| DEFAULT_VERIFIER_ADDR.to_string());
    let relying_party_addrs = if args.len() > 1 {
        args[1..].to_vec()
    } else {
        vec![DEFAULT_RELYING_PARTY_ADDR.to_string()]
    };
    (verifier_addr, relying_party_addrs)
}

#[tokio::main]
async fn main() -> Result<()> {
    let (verifier_addr, relying_party_addrs) = parse_args();

    let listener = TcpListener::bind(&verifier_addr)
        .await
        .with_context(|| format!("verifier listen failed: {}", verifier_addr))?;

    let state = Arc::new(Mutex::new(VerifierState::new()));
    let verifier_key = Arc::new(KeyInfor::new());

    println!("verifier started, listening on: {}", verifier_addr);
    println!("relying-party addresses: {:?}", relying_party_addrs);
    println!("batch interval: {} seconds", BATCH_INTERVAL.as_secs());

    loop {
        let (socket, peer) = listener.accept().await.context("accept TCP failed")?;
        println!("accepted attester/relying-party connection from {}", peer);

        tokio::spawn(handle_request(
            socket,
            Arc::clone(&state),
            Arc::clone(&verifier_key),
            relying_party_addrs.clone(),
        ));
    }
}

async fn handle_request(
    mut socket: TcpStream,
    state: Arc<Mutex<VerifierState>>,
    verifier_key: Arc<KeyInfor>,
    relying_party_addrs: Vec<String>,
) -> Result<()> {
    let peer_addr = socket
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let message = tcp_read_frame(&mut socket).await?;

    if message.starts_with(MSG_DEVICE_INFOR) {
        let signed_dev_infor = decode_signed_device_client_infor_message(&message)
            .context("decode signed attester DeviceClientInfor failed")?;

        match signed_dev_infor.device.mode {
            Model::Passport => {
                let dev_infor = verify_signed_device_client_infor_wire(&signed_dev_infor)
                    .context("verify attester DeviceClientInfor signature failed")?;
                return queue_passport_attester(
                    socket,
                    state,
                    verifier_key,
                    relying_party_addrs,
                    dev_infor,
                    peer_addr,
                )
                .await;
            }
            Model::BackgroundCheck => {
                anyhow::bail!(
                    "background_check DeviceClientInfor must be signed and forwarded by relying-party"
                );
            }
        }
    }

    if message.starts_with(MSG_RELYING_PARTY_DEVICE_INFOR) {
        let relying_party_signed =
            decode_relying_party_signed_device_client_infor_message(&message)
                .context("decode relying-party signed DeviceClientInfor failed")?;

        if relying_party_signed.signed_device.device.mode != Model::BackgroundCheck {
            anyhow::bail!(
                "relying-party signed DeviceClientInfor is only accepted for background_check"
            );
        }

        verify_relying_party_signed_device_client_infor_wire(&relying_party_signed)
            .context("verify relying-party DeviceClientInfor signature failed")?;
        verify_signed_device_client_infor_wire(&relying_party_signed.signed_device)
            .context("verify attester DeviceClientInfor signature failed")?;

        println!("background_check relying-party and attester signatures verified");
        tcp_send_frame(
            &mut socket,
            b"background_check relying-party and attester signatures verified by verifier",
        )
        .await
        .context("send background_check verifier ack failed")?;
        return Ok(());
    }

    anyhow::bail!("unknown verifier message type: {:?}", message.get(..4));
}

async fn queue_passport_attester(
    socket: TcpStream,
    state: Arc<Mutex<VerifierState>>,
    verifier_key: Arc<KeyInfor>,
    relying_party_addrs: Vec<String>,
    dev_infor: hydra_sys::DeviceClientInfor,
    attester_addr: String,
) -> Result<()> {
    let merkle_leaf = dev_infor
        .merkle_leaf
        .context("passport mode requires merkle_leaf")?;

    let should_start_timer = {
        let mut state = state.lock().await;
        state.pending.push(AttesterSession {
            socket: Arc::new(Mutex::new(socket)),
            dev_infor,
            merkle_leaf,
            response: None,
            attester_addr,
        });
        println!(
            "queued passport attester; pending count: {}",
            state.pending.len()
        );

        if state.batch_timer_running {
            false
        } else {
            state.batch_timer_running = true;
            true
        }
    };

    if should_start_timer {
        schedule_passport_batch(state, verifier_key, relying_party_addrs);
    }

    Ok(())
}

fn schedule_passport_batch(
    state: Arc<Mutex<VerifierState>>,
    verifier_key: Arc<KeyInfor>,
    relying_party_addrs: Vec<String>,
) {
    tokio::spawn(async move {
        tokio::time::sleep(BATCH_INTERVAL).await;
        process_passport_batch(
            Arc::clone(&state),
            Arc::clone(&verifier_key),
            relying_party_addrs,
        )
        .await;
    });
}

struct ComputedResponse {
    index: usize,
    socket: Arc<Mutex<TcpStream>>,
    response: hydra_sys::ResponseDeviceInfor,
    encrypted: Vec<u8>,
}

async fn process_passport_batch(
    state: Arc<Mutex<VerifierState>>,
    verifier_key: Arc<KeyInfor>,
    relying_party_addrs: Vec<String>,
) {
    let hasher_vfy = default_hasher();
    let (snapshots, root, leaves, public_context) = {
        let mut state = state.lock().await;

        if state.pending.is_empty() {
            state.batch_timer_running = false;
            println!("passport batch window closed; no pending passport attesters");
            return;
        }

        let mut pending = std::mem::take(&mut state.pending);
        state.batch_timer_running = false;
        let batch_leaves: Vec<BlsScalar> = pending.iter().map(|item| item.merkle_leaf).collect();

        if state.has_created_tree {
            let old_leaves_before_insert = state.old_leaves.clone();
            let mut new_leaves = batch_leaves.clone();
            insert_batch_devices(
                &mut state.root,
                &old_leaves_before_insert,
                &mut new_leaves,
                &hasher_vfy,
            );
            state.old_leaves.extend(batch_leaves);
            println!(
                "inserted batch into existing tree; total leaves: {}",
                state.old_leaves.len()
            );
        } else {
            state.old_leaves.extend(batch_leaves);
            state.root.clear();
            let leaves = state.old_leaves.clone();
            create_batch_devices(&mut state.root, &leaves, &hasher_vfy);
            state.has_created_tree = true;
            println!("created initial tree; total leaves: {}", state.old_leaves.len());
        }

        state.active.append(&mut pending);

        let public_context = PublicContext {
            root: state.root.clone(),
            verifier_pk: verifier_key.verifying_key,
        };
        let snapshots = state
            .active
            .iter()
            .cloned()
            .enumerate()
            .collect::<Vec<_>>();

        (
            snapshots,
            state.root.clone(),
            state.old_leaves.clone(),
            public_context,
        )
    };

    publish_public_context_to_all(&relying_party_addrs, &public_context).await;

    let computed: Vec<Result<ComputedResponse>> = snapshots
        .par_iter()
        .map(|(index, item)| {
            build_encrypted_attester_response(
                *index,
                item,
                &root,
                &leaves,
                &hasher_vfy,
                &verifier_key,
                &public_context,
            )
        })
        .collect();

    let mut send_jobs = Vec::new();
    {
        let mut state = state.lock().await;
        for result in computed {
            match result {
                Ok(computed) => {
                    if let Err(err) = persist_response(&computed.response) {
                        eprintln!("persist verifier response failed: {:#}", err);
                    }
                    if let Some(session) = state.active.get_mut(computed.index) {
                        session.response = Some(computed.response);
                    }
                    send_jobs.push((computed.socket, computed.encrypted));
                }
                Err(err) => eprintln!("build verifier response failed: {:#}", err),
            }
        }
    }

    for (socket, encrypted) in send_jobs {
        let mut socket = socket.lock().await;
        if let Err(err) = tcp_send_frame(&mut socket, &encrypted)
            .await
            .context("send encrypted dev_res to attester failed")
        {
            eprintln!("send verifier response failed: {:#}", err);
        } else {
            println!("sent encrypted updated verifier response to attester");
        }
    }
}

fn build_encrypted_attester_response(
    index: usize,
    item: &AttesterSession,
    root: &[BlsScalar],
    leaves: &[BlsScalar],
    hasher_vfy: &Poseidon<BlsScalar>,
    verifier_key: &KeyInfor,
    public_context: &PublicContext,
) -> Result<ComputedResponse> {
    let mut dev_res = item.response.clone().unwrap_or_else(|| {
        hydra_sys::ResponseDeviceInfor::new_with_mode(item.dev_infor.mode, item.dev_infor.verifying_key)
    });
    dev_res.attester_addr = item.attester_addr.clone();

    let (merkel_path, merkel_tag) =
        find_device_shrubs_path_tag(root, leaves, &item.merkle_leaf, hasher_vfy);
    dev_res.shrubs_path = merkel_path;
    dev_res.shrubs_tag = merkel_tag;

    let device_author_infor = generate_device_authoried_infor(&item.dev_infor, &dev_res, hasher_vfy);
    let sig = verifier_compute_sig(verifier_key, &dev_res, &device_author_infor);
    dev_res.set_signature(&sig);

    let encrypted =
        encode_encrypted_verifier_response(&dev_res, public_context, &item.dev_infor.verifying_key)?;

    Ok(ComputedResponse {
        index,
        socket: Arc::clone(&item.socket),
        response: dev_res,
        encrypted,
    })
}

fn response_store_path(attester_addr: &str) -> PathBuf {
    let safe_name: String = attester_addr
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();
    role_data_dir()
        .join("verifier-responses")
        .join(format!("{}.bin", safe_name))
}

fn persist_response(response: &hydra_sys::ResponseDeviceInfor) -> Result<()> {
    let dir = role_data_dir().join("verifier-responses");
    fs::create_dir_all(&dir).context("create verifier response store failed")?;
    save_response_device_infor(response_store_path(&response.attester_addr), response)
}

async fn publish_public_context_to_all(addrs: &[String], public_context: &PublicContext) {
    for addr in addrs {
        if let Err(err) = publish_public_context(addr, public_context).await {
            eprintln!("publish public context to {} failed: {:#}", addr, err);
        }
    }
}

async fn publish_public_context(addr: &str, public_context: &PublicContext) -> Result<()> {
    let mut stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connect relying-party failed: {}", addr))?;
    let message = encode_public_context_message(public_context)?;
    tcp_send_frame(&mut stream, &message)
        .await
        .context("publish root/verifier public key to relying-party failed")?;
    println!("published public root and verifier public key to {}", addr);
    Ok(())
}
