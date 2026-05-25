use anyhow::{bail, Context, Result};
use hydra_sys::{
    decode_encrypted_verifier_response, default_hasher, encode_evidence_message,
    encode_signed_device_client_infor_message, generate_device_client_infor_with_mode,
    generate_device_evidence_from_config, load_device_config_infor, load_public_context,
    save_device_client_infor, save_device_config_infor,
    save_evidence_bundle, save_key_infor, save_public_context, save_response_device_infor,
    sign_device_client_infor_to_wire, tcp_read_frame, tcp_send_frame,
    ATTESTER_KEY_FILE, DEFAULT_RELYING_PARTY_ADDR, DEFAULT_VERIFIER_ADDR, DEVICE_CONFIG_FILE,
    DEVICE_INFOR_FILE, EVIDENCE_FILE, KeyInfor, Model, PUBLIC_CONTEXT_FILE, VERIFIER_RESPONSE_FILE,
    DATA_DIR_NAME,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;

const ATTESTER_RUNS_DIR: &str = "attester-runs";
const LATEST_SESSION_FILE: &str = "attester_latest_session.txt";

fn role_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DATA_DIR_NAME)
}

fn role_data_file(name: &str) -> PathBuf {
    role_data_dir().join(name)
}

enum Command {
    PassportDemo {
        verifier_addr: String,
        relying_party_addrs: Vec<String>,
    },
    PassportSubmit { verifier_addr: String },
    PassportEvidence {
        relying_party_addrs: Vec<String>,
        session_dir: Option<PathBuf>,
    },
    BackgroundCheck { relying_party_addrs: Vec<String> },
}

fn parse_args() -> Result<Command> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("passport") => parse_passport_first_args(&args[1..]),
        Some("submit") => {
            let verifier_addr = args
                .get(1)
                .cloned()
                .unwrap_or_else(|| DEFAULT_VERIFIER_ADDR.to_string());
            let mode_arg = args.get(2).map(String::as_str).unwrap_or("passport");
            let mode = Model::from_arg(mode_arg)?;
            if mode != Model::Passport {
                bail!("submit command is only for passport mode");
            }
            Ok(Command::PassportSubmit { verifier_addr })
        }
        Some("evidence") => {
            let tail = &args[1..];
            let (mode, relying_party_addrs) = match tail.last() {
                Some(last) => match Model::from_arg(last) {
                    Ok(mode) => (mode, collect_addrs(&tail[..tail.len() - 1])),
                    Err(_) => (Model::Passport, collect_addrs(tail)),
                },
                None => (Model::Passport, collect_addrs(&[])),
            };
            if mode != Model::Passport {
                bail!("evidence command is only for passport mode");
            }
            let (session_dir, relying_party_addrs) = split_session_arg(&relying_party_addrs)?;
            Ok(Command::PassportEvidence {
                relying_party_addrs,
                session_dir,
            })
        }
        Some("background_check") | Some("background-check") => {
            let relying_party_addrs = collect_addrs(&args[1..]);
            Ok(Command::BackgroundCheck { relying_party_addrs })
        }
        _ => parse_legacy_args(args),
    }
}

fn parse_passport_first_args(args: &[String]) -> Result<Command> {
    match args.first().map(String::as_str) {
        Some("submit") => {
            let verifier_addr = args
                .get(1)
                .cloned()
                .unwrap_or_else(|| DEFAULT_VERIFIER_ADDR.to_string());
            Ok(Command::PassportSubmit { verifier_addr })
        }
        Some("evidence") => Ok(Command::PassportEvidence {
            relying_party_addrs: {
                let (_, addrs) = split_session_arg(&args[1..])?;
                addrs
            },
            session_dir: {
                let (session_dir, _) = split_session_arg(&args[1..])?;
                session_dir
            },
        }),
        Some(verifier_addr) => Ok(Command::PassportDemo {
            verifier_addr: verifier_addr.to_string(),
            relying_party_addrs: collect_addrs(&args[1..]),
        }),
        None => Ok(Command::PassportDemo {
            verifier_addr: DEFAULT_VERIFIER_ADDR.to_string(),
            relying_party_addrs: collect_addrs(&[]),
        }),
    }
}

fn parse_legacy_args(args: Vec<String>) -> Result<Command> {
    if args.is_empty() {
        return Ok(Command::PassportSubmit {
            verifier_addr: DEFAULT_VERIFIER_ADDR.to_string(),
        });
    }

    let Some(last) = args.last() else {
        unreachable!("empty args already handled");
    };
    let mode = Model::from_arg(last).unwrap_or(Model::Passport);
    match mode {
        Model::Passport => Ok(Command::PassportSubmit {
            verifier_addr: args
                .first()
                .cloned()
                .unwrap_or_else(|| DEFAULT_VERIFIER_ADDR.to_string()),
        }),
        Model::BackgroundCheck => {
            let relying_party_args = if args.len() > 2 {
                &args[1..args.len() - 1]
            } else {
                &[][..]
            };
            Ok(Command::BackgroundCheck {
                relying_party_addrs: collect_addrs(relying_party_args),
            })
        }
    }
}

fn split_session_arg(values: &[String]) -> Result<(Option<PathBuf>, Vec<String>)> {
    let mut session_dir = None;
    let mut addrs = Vec::new();
    let mut index = 0;
    while index < values.len() {
        if values[index] == "--session" {
            let Some(path) = values.get(index + 1) else {
                bail!("--session requires a path");
            };
            session_dir = Some(PathBuf::from(path));
            index += 2;
        } else {
            addrs.push(values[index].clone());
            index += 1;
        }
    }
    Ok((session_dir, collect_addrs(&addrs)))
}

fn collect_addrs(values: &[String]) -> Vec<String> {
    if values.is_empty() {
        vec![DEFAULT_RELYING_PARTY_ADDR.to_string()]
    } else {
        values.to_vec()
    }
}

fn create_attester_session_dir() -> Result<PathBuf> {
    let base = role_data_file(ATTESTER_RUNS_DIR);
    fs::create_dir_all(&base).context("create attester-runs directory failed")?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before UNIX_EPOCH")?
        .as_nanos();
    let pid = std::process::id();

    for counter in 0..1000u32 {
        let session_dir = base.join(format!("attester-{}-{}-{}", now, pid, counter));
        if !session_dir.exists() {
            fs::create_dir_all(&session_dir).context("create attester session directory failed")?;
            write_latest_session_dir(&session_dir)?;
            return Ok(session_dir);
        }
    }

    bail!("failed to create a unique attester session directory")
}

fn write_latest_session_dir(session_dir: &Path) -> Result<()> {
    fs::write(
        role_data_file(LATEST_SESSION_FILE),
        session_dir.to_string_lossy().as_bytes(),
    )
    .context("write latest attester session path failed")
}

fn read_latest_session_dir() -> Result<PathBuf> {
    let path = fs::read_to_string(role_data_file(LATEST_SESSION_FILE))
        .context("read latest attester session path failed; pass --session <path> or run passport submit first")?;
    let session_dir = PathBuf::from(path.trim());
    if !session_dir.exists() {
        bail!(
            "latest attester session path does not exist: {}",
            session_dir.display()
        );
    }
    Ok(session_dir)
}

fn resolve_session_dir(session_dir: Option<PathBuf>) -> Result<PathBuf> {
    match session_dir {
        Some(path) => {
            if !path.exists() {
                bail!("attester session path does not exist: {}", path.display());
            }
            Ok(path)
        }
        None => read_latest_session_dir(),
    }
}

fn session_file(session_dir: &Path, file_name: &str) -> PathBuf {
    session_dir.join(file_name)
}

fn unique_session_file(session_dir: &Path, file_name: &str) -> Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before UNIX_EPOCH")?
        .as_nanos();
    let pid = std::process::id();
    let path = Path::new(file_name);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(file_name);
    let extension = path.extension().and_then(|value| value.to_str());

    for counter in 0..1000u32 {
        let candidate = match extension {
            Some(extension) => {
                session_dir.join(format!("{}-{}-{}-{}.{}", stem, now, pid, counter, extension))
            }
            None => session_dir.join(format!("{}-{}-{}-{}", stem, now, pid, counter)),
        };
        if !candidate.exists() {
            return Ok(candidate);
        }
    }

    bail!("failed to create a unique session file name for {}", file_name)
}

#[tokio::main]
async fn main() -> Result<()> {
    match parse_args()? {
        Command::PassportDemo {
            verifier_addr,
            relying_party_addrs,
        } => passport_demo(&verifier_addr, &relying_party_addrs).await,
        Command::PassportSubmit { verifier_addr } => passport_submit(&verifier_addr).await,
        Command::PassportEvidence {
            relying_party_addrs,
            session_dir,
        } => passport_evidence(&relying_party_addrs, session_dir).await,
        Command::BackgroundCheck {
            relying_party_addrs,
        } => background_check(&relying_party_addrs).await,
    }
}

async fn passport_demo(verifier_addr: &str, relying_party_addrs: &[String]) -> Result<()> {
    println!("attester passport demo started");
    println!("verifier address: {}", verifier_addr);
    println!("relying-party addresses: {:?}", relying_party_addrs);
    println!("mode: {:?}", Model::Passport);

    let session_dir = create_attester_session_dir()?;
    println!("attester session path: {}", session_dir.display());

    let hasher_dev = default_hasher();
    let dev_key = KeyInfor::new();
    let dev_infor = generate_device_client_infor_with_mode(&dev_key, &hasher_dev, Model::Passport);
    save_key_infor(session_file(&session_dir, ATTESTER_KEY_FILE), &dev_key)
        .context("save attester key failed")?;
    save_device_client_infor(session_file(&session_dir, DEVICE_INFOR_FILE), &dev_infor)
        .context("save DeviceClientInfor failed")?;

    let signed_dev_infor = sign_device_client_infor_to_wire(&dev_infor, &dev_key)?;
    let signed_dev_infor_message = encode_signed_device_client_infor_message(&signed_dev_infor)?;

    println!("passport: sending signed DeviceClientInfor to verifier ...");
    let mut verifier_stream = TcpStream::connect(verifier_addr)
        .await
        .with_context(|| format!("connect verifier failed: {}", verifier_addr))?;
    tcp_send_frame(&mut verifier_stream, &signed_dev_infor_message)
        .await
        .context("send signed DeviceClientInfor to verifier failed")?;

    read_and_store_verifier_response(
        &mut verifier_stream,
        &dev_key,
        &dev_infor,
        &hasher_dev,
        &session_dir,
    )
        .await
        .context("read encrypted verifier response failed")?;
    println!("initial DeviceConfigInfor saved locally; generating evidence ...");

    passport_evidence_from_session(relying_party_addrs, &session_dir).await?;
    println!("passport evidence sent; keeping verifier connection open for future updates ...");
    wait_for_verifier_updates(
        &mut verifier_stream,
        &dev_key,
        &dev_infor,
        &hasher_dev,
        &session_dir,
    )
    .await
}

async fn passport_submit(verifier_addr: &str) -> Result<()> {
    println!("attester submit started");
    println!("verifier address: {}", verifier_addr);
    println!("mode: {:?}", Model::Passport);

    let session_dir = create_attester_session_dir()?;
    println!("attester session path: {}", session_dir.display());

    let hasher_dev = default_hasher();
    let dev_key = KeyInfor::new();
    let dev_infor = generate_device_client_infor_with_mode(&dev_key, &hasher_dev, Model::Passport);
    save_key_infor(session_file(&session_dir, ATTESTER_KEY_FILE), &dev_key)
        .context("save attester key failed")?;
    save_device_client_infor(session_file(&session_dir, DEVICE_INFOR_FILE), &dev_infor)
        .context("save DeviceClientInfor failed")?;

    let signed_dev_infor = sign_device_client_infor_to_wire(&dev_infor, &dev_key)?;
    let signed_dev_infor_message = encode_signed_device_client_infor_message(&signed_dev_infor)?;

    println!("passport: sending signed DeviceClientInfor to verifier ...");
    let mut verifier_stream = TcpStream::connect(verifier_addr)
        .await
        .with_context(|| format!("connect verifier failed: {}", verifier_addr))?;
    tcp_send_frame(&mut verifier_stream, &signed_dev_infor_message)
        .await
        .context("send signed DeviceClientInfor to verifier failed")?;

    read_and_store_verifier_response(
        &mut verifier_stream,
        &dev_key,
        &dev_infor,
        &hasher_dev,
        &session_dir,
    )
        .await
        .context("read initial encrypted verifier response failed")?;

    println!("initial DeviceConfigInfor saved locally");
    println!("waiting for future encrypted verifier updates ...");
    wait_for_verifier_updates(
        &mut verifier_stream,
        &dev_key,
        &dev_infor,
        &hasher_dev,
        &session_dir,
    )
    .await
}

async fn wait_for_verifier_updates(
    verifier_stream: &mut TcpStream,
    dev_key: &KeyInfor,
    dev_infor: &hydra_sys::DeviceClientInfor,
    hasher_dev: &hydra_sys::Poseidon<hydra_sys::BlsScalar>,
    session_dir: &Path,
) -> Result<()> {
    loop {
        match read_and_store_verifier_response(
            verifier_stream,
            dev_key,
            dev_infor,
            hasher_dev,
            session_dir,
        )
        .await
        {
            Ok(()) => println!("local ResponseDeviceInfor and DeviceConfigInfor updated"),
            Err(err) => {
                eprintln!("verifier update loop stopped: {:#}", err);
                return Ok(());
            }
        }
    }
}

async fn read_and_store_verifier_response(
    verifier_stream: &mut TcpStream,
    dev_key: &KeyInfor,
    dev_infor: &hydra_sys::DeviceClientInfor,
    hasher_dev: &hydra_sys::Poseidon<hydra_sys::BlsScalar>,
    session_dir: &Path,
) -> Result<()> {
    let verifier_response_bytes = tcp_read_frame(verifier_stream)
        .await
        .context("read encrypted verifier response failed")?;
    let (dev_res, public_context) =
        decode_encrypted_verifier_response(&verifier_response_bytes, dev_key)
            .context("decrypt and decode verifier response failed")?;

    save_response_device_infor(session_file(session_dir, VERIFIER_RESPONSE_FILE), &dev_res)
        .context("save ResponseDeviceInfor failed")?;
    save_public_context(session_file(session_dir, PUBLIC_CONTEXT_FILE), &public_context)
        .context("save PublicContext failed")?;

    let dev_config = hydra_sys::DeviceConfigInfor::new(dev_key, dev_infor, &dev_res, hasher_dev);
    save_device_config_infor(session_file(session_dir, DEVICE_CONFIG_FILE), &dev_config)
        .context("save DeviceConfigInfor failed")?;

    println!(
        "received encrypted verifier response; attester_addr={}, root_len={}, has_path={}, has_tag={}, has_sig={}",
        dev_res.attester_addr,
        public_context.root.len(),
        dev_res.shrubs_path.is_some(),
        dev_res.shrubs_tag.is_some(),
        dev_res.sig.is_some()
    );
    println!("updated attester session path: {}", session_dir.display());

    Ok(())
}

async fn passport_evidence(
    relying_party_addrs: &[String],
    session_dir: Option<PathBuf>,
) -> Result<()> {
    let session_dir = resolve_session_dir(session_dir)?;
    passport_evidence_from_session(relying_party_addrs, &session_dir).await
}

async fn passport_evidence_from_session(
    relying_party_addrs: &[String],
    session_dir: &Path,
) -> Result<()> {
    println!("attester evidence started");
    println!("relying-party addresses: {:?}", relying_party_addrs);
    println!("mode: {:?}", Model::Passport);
    println!("attester session path: {}", session_dir.display());

    let hasher_dev = default_hasher();
    let dev_config = load_device_config_infor(session_file(session_dir, DEVICE_CONFIG_FILE))
        .context("load DeviceConfigInfor failed; run submit first")?;
    let public_context = load_public_context(session_file(session_dir, PUBLIC_CONTEXT_FILE))
        .context("load PublicContext failed; run submit first")?;

    let (reply, sig) =
        generate_device_evidence_from_config(&public_context.root, &dev_config, &hasher_dev);
    let evidence_path = unique_session_file(session_dir, EVIDENCE_FILE)?;
    save_evidence_bundle(&evidence_path, &reply, &sig)
        .context("save EvidenceReply failed")?;
    println!("EvidenceReply saved to: {}", evidence_path.display());
    let evidence_message = encode_evidence_message(&reply, &sig)?;

    for relying_party_addr in relying_party_addrs {
        println!("passport: sending evidence to {}", relying_party_addr);
        send_evidence(relying_party_addr, &evidence_message).await?;
    }

    Ok(())
}

async fn background_check(relying_party_addrs: &[String]) -> Result<()> {
    println!("attester background_check started");
    println!("relying-party addresses: {:?}", relying_party_addrs);
    println!("mode: {:?}", Model::BackgroundCheck);

    let session_dir = create_attester_session_dir()?;
    println!("attester session path: {}", session_dir.display());

    let hasher_dev = default_hasher();
    let dev_key = KeyInfor::new();
    let dev_infor =
        generate_device_client_infor_with_mode(&dev_key, &hasher_dev, Model::BackgroundCheck);
    save_key_infor(session_file(&session_dir, ATTESTER_KEY_FILE), &dev_key)
        .context("save attester key failed")?;
    save_device_client_infor(session_file(&session_dir, DEVICE_INFOR_FILE), &dev_infor)
        .context("save DeviceClientInfor failed")?;
    let signed_dev_infor = sign_device_client_infor_to_wire(&dev_infor, &dev_key)?;
    let signed_dev_infor_message = encode_signed_device_client_infor_message(&signed_dev_infor)?;

    for relying_party_addr in relying_party_addrs {
        println!(
            "background_check: sending signed DeviceClientInfor to {}",
            relying_party_addr
        );
        send_signed_device_infor(relying_party_addr, &signed_dev_infor_message).await?;
    }

    Ok(())
}

async fn send_signed_device_infor(addr: &str, message: &[u8]) -> Result<()> {
    let mut stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connect relying-party failed: {}", addr))?;
    tcp_send_frame(&mut stream, message)
        .await
        .context("send signed DeviceClientInfor to relying-party failed")?;
    let ack = tcp_read_frame(&mut stream)
        .await
        .context("read relying-party DeviceClientInfor ack failed")?;
    println!("relying-party {} ack: {}", addr, String::from_utf8_lossy(&ack));
    Ok(())
}

async fn send_evidence(addr: &str, message: &[u8]) -> Result<()> {
    let mut stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connect relying-party failed: {}", addr))?;
    tcp_send_frame(&mut stream, message)
        .await
        .context("send evidence to relying-party failed")?;
    let ack = tcp_read_frame(&mut stream)
        .await
        .context("read relying-party evidence ack failed")?;
    println!(
        "relying-party {} evidence result: {}",
        addr,
        String::from_utf8_lossy(&ack)
    );
    Ok(())
}
