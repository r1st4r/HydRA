pub mod poseidon;
pub mod zkcircuit;
pub mod shurbstree;

use ark_bls12_381::{Bls12_381, Fr as BlsScalar};
use shurbstree::{find_shrubs_path,find_interval_index,insert_shrubs_tree,exponents_of_two};
use arkworks_native_gadgets::poseidon::{Poseidon,FieldHasher};
use rand_core::OsRng;
use ecdsa::{SigningKey, VerifyingKey};
use k256::Secp256k1;
use num_bigint::BigUint;
use std::fs;
use std::time::{Duration,SystemTime, UNIX_EPOCH};
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature,
};
use ark_groth16::{Groth16, VerifyingKey as ArkVerifyingKey, Proof};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_crypto_primitives::SNARK;
use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;
use ark_std::UniformRand;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::io::{Cursor, Read};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use anyhow::{Context, Result, bail};



type GrothSetup = Groth16<Bls12_381>;
type RACircuit<'a> = crate::zkcircuit::AttestationCircuit<'a, PoseidonGadget<BlsScalar>>;

pub const DATA_DIR_NAME: &str = "workspace-data";
pub const ATTESTER_KEY_FILE: &str = "attester_key.bin";
pub const DEVICE_INFOR_FILE: &str = "dev_infor.bin";
pub const VERIFIER_KEY_FILE: &str = "verifier_key.bin";
pub const VERIFIER_RESPONSE_FILE: &str = "dev_res.bin";
pub const PUBLIC_CONTEXT_FILE: &str = "public_context.bin";
pub const EVIDENCE_FILE: &str = "evidence.bin";

pub const DEFAULT_VERIFIER_ADDR: &str = "127.0.0.1:7001";
pub const DEFAULT_RELYING_PARTY_ADDR: &str = "127.0.0.1:7002";
pub const MAX_TCP_FRAME_LEN: u64 = 512 * 1024 * 1024;
pub const MSG_PUBLIC_CONTEXT: &[u8; 4] = b"PUBC";
pub const MSG_EVIDENCE: &[u8; 4] = b"EVID";

pub fn project_root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn workspace_data_dir() -> PathBuf {
    project_root_dir().join(DATA_DIR_NAME)
}

pub fn workspace_data_file(name: &str) -> PathBuf {
    workspace_data_dir().join(name)
}

pub fn ensure_workspace_data_dir() -> Result<()> {
    fs::create_dir_all(workspace_data_dir()).context("创建 workspace-data 目录失败")
}

pub fn read_measurement_file() -> String {
    fs::read_to_string(project_root_dir().join("example.txt")).expect("度量信息读取错误")
}

pub fn default_hasher() -> Poseidon<BlsScalar> {
    crate::poseidon::poseidon_setup(arkworks_utils::Curve::Bls381, 5, 3)
}


#[derive(Debug)]
pub struct EvidenceReply {
    pub proof: Proof<Bls12_381>,
    pub vk:  ArkVerifyingKey<Bls12_381>,
    pub sig:   Signature,
    pub pk:  VerifyingKey<Secp256k1>,
    pub timestamp:Duration,
    pub period: Duration,
    pub authorized_infor: BlsScalar,

}

impl EvidenceReply {
    pub fn new(proof: Proof<Bls12_381>,vk: ArkVerifyingKey<Bls12_381>, dev_config: &DeviceConfigInfor  ) -> EvidenceReply {
            EvidenceReply{
                proof,
                vk,
                sig: dev_config.signature.unwrap(),
                pk: dev_config.verifying_key,
                timestamp: dev_config.timestamp,
                period: dev_config.period,
                authorized_infor: dev_config.authorized_infor,
            }

    }
    pub fn gen_public_inputs(&self, root: &[BlsScalar]) -> Vec<BlsScalar> {
        let mut public_inputs = vec![];
        public_inputs.push(BlsScalar::from(BigUint::from_bytes_be(self.pk.to_encoded_point(true).as_bytes()))); 
        public_inputs.extend_from_slice(&root);
        public_inputs.push(self.authorized_infor);
        public_inputs.push(BlsScalar::from(self.timestamp.as_secs()));
        public_inputs.push(BlsScalar::from(self.period.as_secs()));

        public_inputs
    }


       pub fn to_signing_bytes_all_fields(&self) -> Result<Vec<u8>, SerializationError> {
        let mut out = Vec::new();

        let proof_bytes = serialize_ark(&self.proof)?;
        append_field(&mut out, &b"proof"[..], &proof_bytes);

        let vk_bytes = serialize_ark(&self.vk)?;
        append_field(&mut out, &b"vk"[..], &vk_bytes);

        let sig_der = self.sig.to_der();
        append_field(&mut out, &b"sig"[..], sig_der.as_bytes());

        let pk_encoded = self.pk.to_encoded_point(true);
        append_field(&mut out, &b"pk"[..], pk_encoded.as_bytes());

        let timestamp_bytes = serialize_duration(&self.timestamp);
        append_field(&mut out, &b"timestamp"[..], &timestamp_bytes);

        let period_bytes = serialize_duration(&self.period);
        append_field(&mut out, &b"period"[..], &period_bytes);

        let authorized_infor_bytes = serialize_ark(&self.authorized_infor)?;
        append_field(&mut out, &b"authorized_infor"[..], &authorized_infor_bytes);

        Ok(out)
    }

}

fn append_field(out: &mut Vec<u8>, field_name: &[u8], field_data: &[u8]) {
    out.extend_from_slice(&(field_name.len() as u64).to_be_bytes());
    out.extend_from_slice(field_name);

    out.extend_from_slice(&(field_data.len() as u64).to_be_bytes());
    out.extend_from_slice(field_data);
}

fn serialize_ark<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, SerializationError> {
    let mut bytes = Vec::new();
    value.serialize_uncompressed(&mut bytes)?;
    Ok(bytes)
}

fn serialize_duration(duration: &Duration) -> Vec<u8> {
    let mut bytes = Vec::new();

    bytes.extend_from_slice(&duration.as_secs().to_be_bytes());

    bytes.extend_from_slice(&duration.subsec_nanos().to_be_bytes());

    bytes
}

#[derive(Debug)]
pub struct DeviceClientInfor {
    pub verifying_key: VerifyingKey<Secp256k1>,
    pub measured_value: String,
    pub merkle_leaf: BlsScalar,
    pub evidence: Vec<u8>,
}
impl DeviceClientInfor  {
    pub fn new(vk: VerifyingKey<Secp256k1>,leaf: BlsScalar) -> DeviceClientInfor {
        let measure = read_measurement_file();
        DeviceClientInfor {
            verifying_key: vk,
            merkle_leaf: leaf,
            measured_value: measure,
            evidence: vec![32,35,35],
        }
    }
}



pub fn find_device_shrubs_path_tag(
    root: &[BlsScalar],
    leaves: &[BlsScalar],
    leaf: &BlsScalar,
    hasher: &Poseidon<BlsScalar>,
) -> (Option<Vec<BlsScalar>>, Option<Vec<bool>>) {
    match find_interval_index(&leaves, &leaf) {
        Some((vect, index)) => {
            let inx = 0;

            match find_shrubs_path(&root, &vect, inx, index, hasher) {
                Some((path, tag)) => {
                    // for i in path.iter() {
                    //     println!("path: {}", i);
                    // }

                    (Some(path), Some(tag))
                }

                None => {
                    (None, None)
                }
            }
        }

        None => {
            println!("110");
            (None, None)
        }
    }
}

pub fn verifier_compute_sig(verifier_key: &KeyInfor, device_time: &ResponseDeviceInfor,device_author_infor: &BlsScalar) -> Signature {
    let mut msg = Vec::new();
    msg.extend_from_slice(device_time.verifying_key.to_encoded_point(true).as_bytes());
    msg.extend_from_slice(device_author_infor.to_string().as_bytes());
    msg.extend_from_slice(&device_time.timestamp.as_secs().to_be_bytes());
    msg.extend_from_slice(&device_time.period.as_secs().to_be_bytes());
    //println!("{:?}", msg);
    let sig = verifier_key.signing_key.sign(msg.as_slice());
    sig 
}

pub fn rely_party_verifier_sig(evidence_reply: &EvidenceReply, verifier_pk:&VerifyingKey<Secp256k1> )  {
    let mut msg = Vec::new();
    msg.extend_from_slice(evidence_reply.pk.to_encoded_point(true).as_bytes());
    msg.extend_from_slice(&evidence_reply.authorized_infor.to_string().as_bytes());
    msg.extend_from_slice(&evidence_reply.timestamp.as_secs().to_be_bytes());
    msg.extend_from_slice(&evidence_reply.period.as_secs().to_be_bytes());
    //println!("{:?}", msg);
   // verifier_pk.verify(msg.as_slice(), &evidence_reply.sig);

    match verifier_pk.verify(msg.as_slice(), &evidence_reply.sig) {
        Ok(_) => {
            println!("设备签名验证成功");
        }
        Err(e) => {
            println!("设备签名验证失败: {:?}", e);
        }
    }
}


#[derive(Debug)]
pub struct DeviceConfigInfor {
    pub signing_key: SigningKey<Secp256k1>,
    pub verifying_key: VerifyingKey<Secp256k1>,
    pub measured_value: BlsScalar,
    pub timestamp: Duration,
    pub period: Duration,
    pub merkle_leaf: BlsScalar,
    pub merkle_path: Option<Vec<BlsScalar>>,
    pub merkle_tag: Option<Vec<bool>>,
    pub authorized_infor: BlsScalar,
    pub signature: Option<Signature>,
}

impl DeviceConfigInfor {

    pub fn gen_public_inputs(&self, root: &[BlsScalar]) -> Vec<BlsScalar> {
        let mut public_inputs = vec![];
        public_inputs.push(BlsScalar::from(BigUint::from_bytes_be(self.verifying_key.to_encoded_point(true).as_bytes()))); 
        public_inputs.extend_from_slice(&root);
        public_inputs.push(self.authorized_infor);
        public_inputs.push(BlsScalar::from(self.timestamp.as_secs()));
        public_inputs.push(BlsScalar::from(self.period.as_secs()) );

        public_inputs
    }

    pub fn new(
        dev_key: &KeyInfor,
        dev_cli: &DeviceClientInfor,
        dec_res: &ResponseDeviceInfor,
        hasher: &Poseidon<BlsScalar>,
    ) -> DeviceConfigInfor {
        
        let sk = BlsScalar::from(BigUint::from_bytes_be(&dev_key.signing_key.to_bytes()[..]));
        let pk = BlsScalar::from(BigUint::from_bytes_be(
            &dev_key.verifying_key.to_encoded_point(true).as_bytes(),
        ));
        let ar = BlsScalar::from(BigUint::from_bytes_be(dev_cli.measured_value.as_bytes()));
        let time = BlsScalar::from(dec_res.timestamp.as_secs());
        let peri = BlsScalar::from(dec_res.period.as_secs());
        let leaf = dev_cli.merkle_leaf;
        let output = generate_verifier_authoried_infor(ar, pk, time, peri, hasher);

        DeviceConfigInfor {
            signing_key: dev_key.signing_key.clone(),
            verifying_key: dev_key.verifying_key,
            measured_value: ar,
            timestamp: dec_res.timestamp,
            period: dec_res.period,
            merkle_leaf: leaf,
            authorized_infor: output,
            merkle_path: dec_res.shrubs_path.clone(),
            merkle_tag: dec_res.shrubs_tag.clone(),
            signature: dec_res.sig,
        }
    }
}

pub struct  KeyInfor {
    pub signing_key: SigningKey<Secp256k1>,
    pub verifying_key: VerifyingKey<Secp256k1>,
}

impl KeyInfor {
    pub fn new() -> Self{
        let signing_key: SigningKey<Secp256k1> = SigningKey::<Secp256k1>::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        Self {
            signing_key,
            verifying_key
        }
    }
}


pub fn generate_device_merkle_leaf(
    device_key: &KeyInfor,
    hasher: &Poseidon<BlsScalar>,
) -> BlsScalar {
    let measure = read_measurement_file();
    let sk = BlsScalar::from(BigUint::from_bytes_be(&device_key.signing_key.to_bytes()[..]));
    let pk = BlsScalar::from(BigUint::from_bytes_be(
            &device_key.verifying_key.to_encoded_point(true).as_bytes(),
        ));
    let ar = BlsScalar::from(BigUint::from_bytes_be(measure.as_bytes()));

    let c = hasher.hash(&[ar, sk][..]).unwrap();
    let leaf = hasher.hash(&[c, pk][..]).unwrap();

    leaf
}
pub struct ResponseDeviceInfor {
    pub verifying_key: VerifyingKey<Secp256k1>,
    pub timestamp: Duration,
    pub period: Duration,
    pub sig : Option<Signature>,
    pub shrubs_path: Option<Vec<BlsScalar>>,
    pub shrubs_tag: Option<Vec<bool>>,
}

impl ResponseDeviceInfor {
    pub fn new(pk: VerifyingKey<Secp256k1>) ->  ResponseDeviceInfor {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("获取系统时间失败");
        let period = Duration::from_secs(8640000 as u64);
         ResponseDeviceInfor {
            timestamp,
            period, 
            verifying_key:pk,
            sig: None,
            shrubs_path: None,
            shrubs_tag: None,
         }
    }
    pub fn set_signature(&mut self,sig: &Signature) {
        self.sig = Some(*sig);
    }

    pub fn set_shrubs_path_and_tag(&mut self, path: Vec<BlsScalar>, tag: Vec<bool> ) {
            self.shrubs_path = Some(path);
            self.shrubs_tag = Some(tag);
    }

}

pub fn generate_device_authoried_infor(
    devices_infor: &DeviceClientInfor,
    devices_time: &ResponseDeviceInfor,
    hasher: &Poseidon<BlsScalar>,
) -> BlsScalar {

    let pk = BlsScalar::from(BigUint::from_bytes_be(
            devices_infor.verifying_key.to_encoded_point(true).as_bytes(),
        ));
    let ar = BlsScalar::from(BigUint::from_bytes_be(devices_infor.measured_value.as_bytes()));
    let time = BlsScalar::from(devices_time.timestamp.as_secs());
    let peri = BlsScalar::from(devices_time.period.as_secs());

    let temp_1 = hasher.hash(&[pk, ar][..]).unwrap();
    let temp_2 = hasher.hash(&[temp_1, time][..]).unwrap();
    let output = hasher.hash(&[temp_2, peri][..]).unwrap();

    output
}

pub fn generate_verifier_authoried_infor(
    ar: BlsScalar,
    pk: BlsScalar,
    time: BlsScalar,
    peri: BlsScalar,
    hasher: &Poseidon<BlsScalar>,
) -> BlsScalar {
    let temp_1 = hasher.hash(&[pk, ar][..]).unwrap();
    let temp_2 = hasher.hash(&[temp_1, time][..]).unwrap();
    let output = hasher.hash(&[temp_2, peri][..]).unwrap();

    output
}

pub fn insert_batch_devices(
    mut root: &mut Vec<BlsScalar>,
    old_leaves: &[BlsScalar],
    new_leaves: &mut Vec<BlsScalar>,
    hasher: &Poseidon<BlsScalar>,
) {
    let k: isize = -1;
    let ll: usize = 0;

    let exps = exponents_of_two(old_leaves.len());

    if exps[0] == 0 {
        let mut n_leaf = Vec::with_capacity(new_leaves.len() + 1);
        n_leaf.push(root[0]);
        n_leaf.append(new_leaves);

        insert_shrubs_tree(&mut root, &n_leaf, k, &exps, ll + 1, &hasher);
    } else {
        insert_shrubs_tree(&mut root, &new_leaves, k, &exps, ll, &hasher);
    }
}
pub fn generate_device_client_infor(
    device_key: &KeyInfor,
    hasher: &Poseidon<BlsScalar>,
) -> DeviceClientInfor {
    let device_leaf = generate_device_merkle_leaf(device_key, hasher);
    DeviceClientInfor::new(device_key.verifying_key, device_leaf)
}

pub fn generate_verifier_resonse_infor_1(
    devices_infor: &DeviceClientInfor,
    verifier_key: &KeyInfor,
    leaves: &mut Vec<BlsScalar>,
    hasher: &Poseidon<BlsScalar>,
) -> ResponseDeviceInfor {
    let mut device_resp = ResponseDeviceInfor::new(devices_infor.verifying_key);
    let device_author_infor = generate_device_authoried_infor(devices_infor, &device_resp, hasher);
    let sig = verifier_compute_sig(verifier_key, &device_resp, &device_author_infor);
    device_resp.set_signature(&sig);
    leaves.push(devices_infor.merkle_leaf);
    device_resp
}

pub fn generate_device_evidence(
    root: &[BlsScalar],
    device_key: &KeyInfor,
    device_client_infor: &DeviceClientInfor,
    device_resp: &ResponseDeviceInfor,
    hasher: &Poseidon<BlsScalar>,
) -> (EvidenceReply, Signature) {
    let dev_config = DeviceConfigInfor::new(device_key, device_client_infor, device_resp, hasher);
    let merkel_path_ref = dev_config.merkle_path.as_deref();
    let merkel_tag_ref = dev_config.merkle_tag.as_deref();

    let circuit = RACircuit::new(&dev_config, root, merkel_path_ref, merkel_tag_ref, hasher);
    let (pkk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), &mut OsRng).unwrap();
    let proof = GrothSetup::prove(&pkk, circuit.clone(), &mut OsRng).unwrap();

    let evidence_reply = EvidenceReply::new(proof, vk, &dev_config);
    let msg: Vec<u8> = evidence_reply
        .to_signing_bytes_all_fields()
        .expect("serialize EvidenceReply failed");
    let signature = dev_config.signing_key.sign(&msg[..]);

    (evidence_reply, signature)
}

pub fn rely_party_verification(
    root: &[BlsScalar],
    evidence_reply: &EvidenceReply,
    signature: Signature,
    verifier_pk: &VerifyingKey<Secp256k1>,
) {
    let public_inputs = evidence_reply.gen_public_inputs(root);
    let msg: Vec<u8> = evidence_reply
        .to_signing_bytes_all_fields()
        .expect("serialize EvidenceReply failed");

    match evidence_reply.pk.verify(&msg[..], &signature) {
        Ok(_) => println!("设备证据签名验证成功"),
        Err(e) => println!("设备证据签名验证失败: {:?}", e),
    }

    rely_party_verifier_sig(evidence_reply, verifier_pk);

    let res = GrothSetup::verify(&evidence_reply.vk, &public_inputs, &evidence_reply.proof).unwrap();
    if res {
        println!("设备证据验证成功！");
    } else {
        println!("设备证据验收失败！");
    }
}

pub fn gen_leaves() -> Vec<BlsScalar> {
    let n = 1usize << 11;
    (0..n - 1)
        .into_par_iter()
        .map_init(
            || OsRng,
            |rng, _| BlsScalar::rand(rng),
        )
        .collect()
}

pub fn gen_new_leaves() -> Vec<BlsScalar> {
    let n = 1usize << 12;
    (0..n - 1)
        .into_par_iter()
        .map_init(
            || OsRng,
            |rng, _| BlsScalar::rand(rng),
        )
        .collect()
}

#[derive(Debug, Clone)]
pub struct PublicContext {
    pub root: Vec<BlsScalar>,
    pub verifier_pk: VerifyingKey<Secp256k1>,
}

fn append_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn read_exact<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    cursor.read_exact(&mut buf).context("读取二进制字段失败")?;
    Ok(buf)
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64> {
    Ok(u64::from_be_bytes(read_exact::<8>(cursor)?))
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32> {
    Ok(u32::from_be_bytes(read_exact::<4>(cursor)?))
}

fn read_len_bytes(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u8>> {
    let len = read_u64(cursor)? as usize;
    let mut bytes = vec![0u8; len];
    cursor.read_exact(&mut bytes).context("读取变长二进制字段失败")?;
    Ok(bytes)
}

fn append_string(out: &mut Vec<u8>, value: &str) {
    append_len_bytes(out, value.as_bytes());
}

fn read_string(cursor: &mut Cursor<&[u8]>) -> Result<String> {
    String::from_utf8(read_len_bytes(cursor)?).context("解析 UTF-8 字符串失败")
}

fn append_duration(out: &mut Vec<u8>, value: Duration) {
    out.extend_from_slice(&value.as_secs().to_be_bytes());
    out.extend_from_slice(&value.subsec_nanos().to_be_bytes());
}

fn read_duration(cursor: &mut Cursor<&[u8]>) -> Result<Duration> {
    let secs = read_u64(cursor)?;
    let nanos = read_u32(cursor)?;
    Ok(Duration::new(secs, nanos))
}

fn encode_scalar(value: &BlsScalar) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_uncompressed(&mut bytes)
        .context("序列化 BlsScalar 失败")?;
    Ok(bytes)
}

fn decode_scalar(bytes: &[u8]) -> Result<BlsScalar> {
    let mut cursor = Cursor::new(bytes);
    BlsScalar::deserialize_uncompressed(&mut cursor).context("反序列化 BlsScalar 失败")
}

fn append_scalar(out: &mut Vec<u8>, value: &BlsScalar) -> Result<()> {
    append_len_bytes(out, &encode_scalar(value)?);
    Ok(())
}

fn read_scalar(cursor: &mut Cursor<&[u8]>) -> Result<BlsScalar> {
    decode_scalar(&read_len_bytes(cursor)?)
}

fn append_scalar_vec(out: &mut Vec<u8>, values: &[BlsScalar]) -> Result<()> {
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        append_scalar(out, value)?;
    }
    Ok(())
}

fn read_scalar_vec(cursor: &mut Cursor<&[u8]>) -> Result<Vec<BlsScalar>> {
    let len = read_u64(cursor)? as usize;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(read_scalar(cursor)?);
    }
    Ok(values)
}

fn append_bool_vec(out: &mut Vec<u8>, values: &[bool]) {
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        out.push(u8::from(*value));
    }
}

fn read_bool_vec(cursor: &mut Cursor<&[u8]>) -> Result<Vec<bool>> {
    let len = read_u64(cursor)? as usize;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        let b = read_exact::<1>(cursor)?[0];
        match b {
            0 => values.push(false),
            1 => values.push(true),
            _ => bail!("bool 字段非法: {}", b),
        }
    }
    Ok(values)
}

fn append_option_scalar_vec(out: &mut Vec<u8>, values: &Option<Vec<BlsScalar>>) -> Result<()> {
    match values {
        Some(values) => {
            out.push(1);
            append_scalar_vec(out, values)?;
        }
        None => out.push(0),
    }
    Ok(())
}

fn read_option_scalar_vec(cursor: &mut Cursor<&[u8]>) -> Result<Option<Vec<BlsScalar>>> {
    match read_exact::<1>(cursor)?[0] {
        0 => Ok(None),
        1 => Ok(Some(read_scalar_vec(cursor)?)),
        other => bail!("Option<Vec<BlsScalar>> 标记非法: {}", other),
    }
}

fn append_option_bool_vec(out: &mut Vec<u8>, values: &Option<Vec<bool>>) {
    match values {
        Some(values) => {
            out.push(1);
            append_bool_vec(out, values);
        }
        None => out.push(0),
    }
}

fn read_option_bool_vec(cursor: &mut Cursor<&[u8]>) -> Result<Option<Vec<bool>>> {
    match read_exact::<1>(cursor)?[0] {
        0 => Ok(None),
        1 => Ok(Some(read_bool_vec(cursor)?)),
        other => bail!("Option<Vec<bool>> 标记非法: {}", other),
    }
}

fn encode_signature(value: &Signature) -> Vec<u8> {
    value.to_der().as_bytes().to_vec()
}

fn decode_signature(bytes: &[u8]) -> Result<Signature> {
    Signature::from_der(bytes).context("反序列化 secp256k1 签名失败")
}

fn append_signature(out: &mut Vec<u8>, value: &Signature) {
    append_len_bytes(out, &encode_signature(value));
}

fn read_signature(cursor: &mut Cursor<&[u8]>) -> Result<Signature> {
    decode_signature(&read_len_bytes(cursor)?)
}

fn append_option_signature(out: &mut Vec<u8>, value: &Option<Signature>) {
    match value {
        Some(sig) => {
            out.push(1);
            append_signature(out, sig);
        }
        None => out.push(0),
    }
}

fn read_option_signature(cursor: &mut Cursor<&[u8]>) -> Result<Option<Signature>> {
    match read_exact::<1>(cursor)?[0] {
        0 => Ok(None),
        1 => Ok(Some(read_signature(cursor)?)),
        other => bail!("Option<Signature> 标记非法: {}", other),
    }
}

fn append_verifying_key(out: &mut Vec<u8>, value: &VerifyingKey<Secp256k1>) {
    append_len_bytes(out, value.to_encoded_point(true).as_bytes());
}

fn read_verifying_key(cursor: &mut Cursor<&[u8]>) -> Result<VerifyingKey<Secp256k1>> {
    VerifyingKey::<Secp256k1>::from_sec1_bytes(&read_len_bytes(cursor)?)
        .context("反序列化 secp256k1 公钥失败")
}

fn encode_proof(value: &Proof<Bls12_381>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_uncompressed(&mut bytes)
        .context("序列化 Groth16 proof 失败")?;
    Ok(bytes)
}

fn decode_proof(bytes: &[u8]) -> Result<Proof<Bls12_381>> {
    let mut cursor = Cursor::new(bytes);
    Proof::<Bls12_381>::deserialize_uncompressed(&mut cursor)
        .context("反序列化 Groth16 proof 失败")
}

fn append_proof(out: &mut Vec<u8>, value: &Proof<Bls12_381>) -> Result<()> {
    append_len_bytes(out, &encode_proof(value)?);
    Ok(())
}

fn read_proof(cursor: &mut Cursor<&[u8]>) -> Result<Proof<Bls12_381>> {
    decode_proof(&read_len_bytes(cursor)?)
}

fn encode_ark_vk(value: &ArkVerifyingKey<Bls12_381>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_uncompressed(&mut bytes)
        .context("序列化 Groth16 verifying key 失败")?;
    Ok(bytes)
}

fn decode_ark_vk(bytes: &[u8]) -> Result<ArkVerifyingKey<Bls12_381>> {
    let mut cursor = Cursor::new(bytes);
    ArkVerifyingKey::<Bls12_381>::deserialize_uncompressed(&mut cursor)
        .context("反序列化 Groth16 verifying key 失败")
}

fn append_ark_vk(out: &mut Vec<u8>, value: &ArkVerifyingKey<Bls12_381>) -> Result<()> {
    append_len_bytes(out, &encode_ark_vk(value)?);
    Ok(())
}

fn read_ark_vk(cursor: &mut Cursor<&[u8]>) -> Result<ArkVerifyingKey<Bls12_381>> {
    decode_ark_vk(&read_len_bytes(cursor)?)
}


pub fn encode_key_infor(key: &KeyInfor) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_len_bytes(&mut out, &key.signing_key.to_bytes()[..]);
    Ok(out)
}

pub fn decode_key_infor(bytes: &[u8]) -> Result<KeyInfor> {
    let mut cursor = Cursor::new(bytes);
    let sk_bytes = read_len_bytes(&mut cursor)?;
    if sk_bytes.len() != 32 {
        bail!("secp256k1 私钥长度应为 32 字节，实际为 {} 字节", sk_bytes.len());
    }
    let signing_key = SigningKey::<Secp256k1>::from_bytes(k256::FieldBytes::from_slice(&sk_bytes))
        .context("反序列化 secp256k1 私钥失败")?;
    let verifying_key = VerifyingKey::from(&signing_key);
    Ok(KeyInfor {
        signing_key,
        verifying_key,
    })
}

pub fn encode_device_client_infor(value: &DeviceClientInfor) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_verifying_key(&mut out, &value.verifying_key);
    append_string(&mut out, &value.measured_value);
    append_scalar(&mut out, &value.merkle_leaf)?;
    append_len_bytes(&mut out, &value.evidence);
    Ok(out)
}

pub fn decode_device_client_infor(bytes: &[u8]) -> Result<DeviceClientInfor> {
    let mut cursor = Cursor::new(bytes);
    Ok(DeviceClientInfor {
        verifying_key: read_verifying_key(&mut cursor)?,
        measured_value: read_string(&mut cursor)?,
        merkle_leaf: read_scalar(&mut cursor)?,
        evidence: read_len_bytes(&mut cursor)?,
    })
}

pub fn encode_response_device_infor(value: &ResponseDeviceInfor) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_verifying_key(&mut out, &value.verifying_key);
    append_duration(&mut out, value.timestamp);
    append_duration(&mut out, value.period);
    append_option_signature(&mut out, &value.sig);
    append_option_scalar_vec(&mut out, &value.shrubs_path)?;
    append_option_bool_vec(&mut out, &value.shrubs_tag);
    Ok(out)
}

pub fn decode_response_device_infor(bytes: &[u8]) -> Result<ResponseDeviceInfor> {
    let mut cursor = Cursor::new(bytes);
    Ok(ResponseDeviceInfor {
        verifying_key: read_verifying_key(&mut cursor)?,
        timestamp: read_duration(&mut cursor)?,
        period: read_duration(&mut cursor)?,
        sig: read_option_signature(&mut cursor)?,
        shrubs_path: read_option_scalar_vec(&mut cursor)?,
        shrubs_tag: read_option_bool_vec(&mut cursor)?,
    })
}

pub fn encode_public_context(value: &PublicContext) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_scalar_vec(&mut out, &value.root)?;
    append_verifying_key(&mut out, &value.verifier_pk);
    Ok(out)
}

pub fn decode_public_context(bytes: &[u8]) -> Result<PublicContext> {
    let mut cursor = Cursor::new(bytes);
    Ok(PublicContext {
        root: read_scalar_vec(&mut cursor)?,
        verifier_pk: read_verifying_key(&mut cursor)?,
    })
}

pub fn encode_evidence_bundle(
    evidence_reply: &EvidenceReply,
    device_signature: &Signature,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_proof(&mut out, &evidence_reply.proof)?;
    append_ark_vk(&mut out, &evidence_reply.vk)?;
    append_signature(&mut out, &evidence_reply.sig);
    append_verifying_key(&mut out, &evidence_reply.pk);
    append_duration(&mut out, evidence_reply.timestamp);
    append_duration(&mut out, evidence_reply.period);
    append_scalar(&mut out, &evidence_reply.authorized_infor)?;
    append_signature(&mut out, device_signature);
    Ok(out)
}

pub fn decode_evidence_bundle(bytes: &[u8]) -> Result<(EvidenceReply, Signature)> {
    let mut cursor = Cursor::new(bytes);
    let evidence_reply = EvidenceReply {
        proof: read_proof(&mut cursor)?,
        vk: read_ark_vk(&mut cursor)?,
        sig: read_signature(&mut cursor)?,
        pk: read_verifying_key(&mut cursor)?,
        timestamp: read_duration(&mut cursor)?,
        period: read_duration(&mut cursor)?,
        authorized_infor: read_scalar(&mut cursor)?,
    };
    let device_signature = read_signature(&mut cursor)?;
    Ok((evidence_reply, device_signature))
}

pub fn encode_verifier_response(
    dev_res: &ResponseDeviceInfor,
    public_context: &PublicContext,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append_len_bytes(&mut out, &encode_response_device_infor(dev_res)?);
    append_len_bytes(&mut out, &encode_public_context(public_context)?);
    Ok(out)
}

pub fn decode_verifier_response(bytes: &[u8]) -> Result<(ResponseDeviceInfor, PublicContext)> {
    let mut cursor = Cursor::new(bytes);
    let dev_res_bytes = read_len_bytes(&mut cursor)?;
    let public_context_bytes = read_len_bytes(&mut cursor)?;
    Ok((
        decode_response_device_infor(&dev_res_bytes)?,
        decode_public_context(&public_context_bytes)?,
    ))
}

fn encode_typed_message(kind: &[u8; 4], payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(kind);
    out.extend_from_slice(&payload);
    out
}

pub fn encode_public_context_message(public_context: &PublicContext) -> Result<Vec<u8>> {
    Ok(encode_typed_message(MSG_PUBLIC_CONTEXT, encode_public_context(public_context)?))
}

pub fn decode_public_context_message(bytes: &[u8]) -> Result<PublicContext> {
    if !bytes.starts_with(MSG_PUBLIC_CONTEXT) {
        bail!("不是 PublicContext 消息");
    }
    decode_public_context(&bytes[MSG_PUBLIC_CONTEXT.len()..])
}

pub fn encode_evidence_message(
    evidence_reply: &EvidenceReply,
    device_signature: &Signature,
) -> Result<Vec<u8>> {
    Ok(encode_typed_message(
        MSG_EVIDENCE,
        encode_evidence_bundle(evidence_reply, device_signature)?,
    ))
}

pub fn decode_evidence_message(bytes: &[u8]) -> Result<(EvidenceReply, Signature)> {
    if !bytes.starts_with(MSG_EVIDENCE) {
        bail!("不是 Evidence 消息");
    }
    decode_evidence_bundle(&bytes[MSG_EVIDENCE.len()..])
}

pub async fn tcp_send_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    let len = payload.len() as u64;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .context("TCP 发送消息长度失败")?;
    stream
        .write_all(payload)
        .await
        .context("TCP 发送消息体失败")?;
    stream.flush().await.context("TCP flush 失败")?;
    Ok(())
}

pub async fn tcp_read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 8];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("TCP 读取消息长度失败")?;
    let len = u64::from_be_bytes(len_buf);
    if len > MAX_TCP_FRAME_LEN {
        bail!("TCP 消息过大: {} bytes", len);
    }

    let mut payload = vec![0u8; len as usize];
    stream
        .read_exact(&mut payload)
        .await
        .context("TCP 读取消息体失败")?;
    Ok(payload)
}

pub fn save_key_infor(path: impl AsRef<Path>, key: &KeyInfor) -> Result<()> {
    ensure_workspace_data_dir()?;
    let mut out = Vec::new();
    append_len_bytes(&mut out, &key.signing_key.to_bytes()[..]);
    fs::write(path, out).context("保存 KeyInfor 失败")
}

pub fn load_key_infor(path: impl AsRef<Path>) -> Result<KeyInfor> {
    let bytes = fs::read(path).context("读取 KeyInfor 失败")?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let sk_bytes = read_len_bytes(&mut cursor)?;
    if sk_bytes.len() != 32 {
        bail!("secp256k1 私钥长度应为 32 字节，实际为 {} 字节", sk_bytes.len());
    }
    let signing_key = SigningKey::<Secp256k1>::from_bytes(k256::FieldBytes::from_slice(&sk_bytes))
        .context("反序列化 secp256k1 私钥失败")?;
    let verifying_key = VerifyingKey::from(&signing_key);
    Ok(KeyInfor {
        signing_key,
        verifying_key,
    })
}

pub fn save_device_client_infor(path: impl AsRef<Path>, value: &DeviceClientInfor) -> Result<()> {
    ensure_workspace_data_dir()?;
    let mut out = Vec::new();
    append_verifying_key(&mut out, &value.verifying_key);
    append_string(&mut out, &value.measured_value);
    append_scalar(&mut out, &value.merkle_leaf)?;
    append_len_bytes(&mut out, &value.evidence);
    fs::write(path, out).context("保存 DeviceClientInfor 失败")
}

pub fn load_device_client_infor(path: impl AsRef<Path>) -> Result<DeviceClientInfor> {
    let bytes = fs::read(path).context("读取 DeviceClientInfor 失败")?;
    let mut cursor = Cursor::new(bytes.as_slice());
    Ok(DeviceClientInfor {
        verifying_key: read_verifying_key(&mut cursor)?,
        measured_value: read_string(&mut cursor)?,
        merkle_leaf: read_scalar(&mut cursor)?,
        evidence: read_len_bytes(&mut cursor)?,
    })
}

pub fn save_response_device_infor(path: impl AsRef<Path>, value: &ResponseDeviceInfor) -> Result<()> {
    ensure_workspace_data_dir()?;
    let mut out = Vec::new();
    append_verifying_key(&mut out, &value.verifying_key);
    append_duration(&mut out, value.timestamp);
    append_duration(&mut out, value.period);
    append_option_signature(&mut out, &value.sig);
    append_option_scalar_vec(&mut out, &value.shrubs_path)?;
    append_option_bool_vec(&mut out, &value.shrubs_tag);
    fs::write(path, out).context("保存 ResponseDeviceInfor 失败")
}

pub fn load_response_device_infor(path: impl AsRef<Path>) -> Result<ResponseDeviceInfor> {
    let bytes = fs::read(path).context("读取 ResponseDeviceInfor 失败")?;
    let mut cursor = Cursor::new(bytes.as_slice());
    Ok(ResponseDeviceInfor {
        verifying_key: read_verifying_key(&mut cursor)?,
        timestamp: read_duration(&mut cursor)?,
        period: read_duration(&mut cursor)?,
        sig: read_option_signature(&mut cursor)?,
        shrubs_path: read_option_scalar_vec(&mut cursor)?,
        shrubs_tag: read_option_bool_vec(&mut cursor)?,
    })
}

pub fn save_public_context(path: impl AsRef<Path>, value: &PublicContext) -> Result<()> {
    ensure_workspace_data_dir()?;
    let mut out = Vec::new();
    append_scalar_vec(&mut out, &value.root)?;
    append_verifying_key(&mut out, &value.verifier_pk);
    fs::write(path, out).context("保存 PublicContext 失败")
}

pub fn load_public_context(path: impl AsRef<Path>) -> Result<PublicContext> {
    let bytes = fs::read(path).context("读取 PublicContext 失败")?;
    let mut cursor = Cursor::new(bytes.as_slice());
    Ok(PublicContext {
        root: read_scalar_vec(&mut cursor)?,
        verifier_pk: read_verifying_key(&mut cursor)?,
    })
}

pub fn save_evidence_bundle(
    path: impl AsRef<Path>,
    evidence_reply: &EvidenceReply,
    device_signature: &Signature,
) -> Result<()> {
    ensure_workspace_data_dir()?;
    let mut out = Vec::new();
    append_proof(&mut out, &evidence_reply.proof)?;
    append_ark_vk(&mut out, &evidence_reply.vk)?;
    append_signature(&mut out, &evidence_reply.sig);
    append_verifying_key(&mut out, &evidence_reply.pk);
    append_duration(&mut out, evidence_reply.timestamp);
    append_duration(&mut out, evidence_reply.period);
    append_scalar(&mut out, &evidence_reply.authorized_infor)?;
    append_signature(&mut out, device_signature);
    fs::write(path, out).context("保存 EvidenceReply 与设备签名失败")
}

pub fn load_evidence_bundle(path: impl AsRef<Path>) -> Result<(EvidenceReply, Signature)> {
    let bytes = fs::read(path).context("读取 EvidenceReply 与设备签名失败")?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let evidence_reply = EvidenceReply {
        proof: read_proof(&mut cursor)?,
        vk: read_ark_vk(&mut cursor)?,
        sig: read_signature(&mut cursor)?,
        pk: read_verifying_key(&mut cursor)?,
        timestamp: read_duration(&mut cursor)?,
        period: read_duration(&mut cursor)?,
        authorized_infor: read_scalar(&mut cursor)?,
    };
    let device_signature = read_signature(&mut cursor)?;
    Ok((evidence_reply, device_signature))
}
