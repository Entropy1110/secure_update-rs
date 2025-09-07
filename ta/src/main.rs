#![no_std]
#![no_main]

extern crate alloc;

use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::{Parameters, Result, Error, ErrorKind};
use optee_utee::{Asymmetric, AlgorithmId, DataFlag, ObjectStorageConstants, PersistentObject, TransientObject, TransientObjectType, GenericObject, AttributeId};
use proto::Command;

const TA_RSA_PUB_OBJ_ID: &[u8] = b"ta_root_rsa_pub_v1";
const TA_RSA_PRIV_OBJ_ID: &[u8] = b"ta_root_rsa_priv_v1";
const SERVER_PUB_OBJ_ID: &[u8] = b"server_ed25519_pub_v1";

#[ta_create]
fn create() -> Result<()> {
    trace_println!("[+] TA create");
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters) -> Result<()> {
    trace_println!("[+] TA open session");
    Ok(())
}

#[ta_close_session]
fn close_session() {
    trace_println!("[+] TA close session");
}

#[ta_destroy]
fn destroy() {
    trace_println!("[+] TA destroy");
}

#[ta_invoke_command]
fn invoke_command(cmd_id: u32, params: &mut Parameters) -> Result<()> {
    match Command::from(cmd_id) {
        Command::GenKey => cmd_genkey(),
        Command::GetPub => cmd_getpub(params),
        Command::SetServerPub => cmd_set_server_pub(params),
        Command::VerifyServer => cmd_verify_server(params),
        _ => Err(Error::new(ErrorKind::NotSupported)),
    }
}

fn gen_and_store_rsa() -> Result<()> {
    let mut key = TransientObject::allocate(TransientObjectType::RsaKeypair, 2048)?;
    key.generate_key(2048, &[])?;
    let mut n = [0u8; 256];
    let mut e = [0u8; 8];
    let n_len = key.ref_attribute(AttributeId::RsaModulus, &mut n)?;
    let e_len = key.ref_attribute(AttributeId::RsaPublicExponent, &mut e)?;
    // store pub
    let flags = DataFlag::ACCESS_READ | DataFlag::ACCESS_WRITE | DataFlag::ACCESS_WRITE_META | DataFlag::OVERWRITE;
    let mut init: [u8;0] = [];
    let mut obj_pub = PersistentObject::create(ObjectStorageConstants::Private, TA_RSA_PUB_OBJ_ID, flags, None, &mut init)?;
    let mut buf = [0u8; 4+256+4+8];
    let total = 4 + n_len + 4 + e_len;
    buf[0..4].copy_from_slice(&(n_len as u32).to_le_bytes());
    buf[4..4+n_len].copy_from_slice(&n[..n_len]);
    let off = 4+n_len;
    buf[off..off+4].copy_from_slice(&(e_len as u32).to_le_bytes());
    buf[off+4..off+4+e_len].copy_from_slice(&e[..e_len]);
    obj_pub.write(&buf[..total])?;
    // store private exponent (optional; placeholder for future import)
    let mut d = [0u8; 256];
    if let Ok(d_len) = key.ref_attribute(AttributeId::RsaPrivateExponent, &mut d) {
        let mut obj_priv = PersistentObject::create(ObjectStorageConstants::Private, TA_RSA_PRIV_OBJ_ID, flags, None, &mut init)?;
        let mut hdr = [0u8;4]; hdr.copy_from_slice(&(d_len as u32).to_le_bytes());
        obj_priv.write(&hdr)?;
        obj_priv.write(&d[..d_len])?;
    }
    Ok(())
}

fn cmd_genkey() -> Result<()> { gen_and_store_rsa() }

fn cmd_getpub(params: &mut Parameters) -> Result<()> {
    // Open pub object; if missing, generate
    let obj = match PersistentObject::open(ObjectStorageConstants::Private, TA_RSA_PUB_OBJ_ID, DataFlag::ACCESS_READ) {
        Ok(o) => o,
        Err(_) => { gen_and_store_rsa()?; PersistentObject::open(ObjectStorageConstants::Private, TA_RSA_PUB_OBJ_ID, DataFlag::ACCESS_READ)? }
    };
    let info = obj.info()?;
    let mut tmp = [0u8; 4+256+4+8];
    if info.data_size() as usize > tmp.len() { return Err(Error::new(ErrorKind::ShortBuffer)); }
    let read = obj.read(&mut tmp).unwrap();
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    if p1.buffer().len() < read as usize { p1.set_updated_size(read as usize); return Err(Error::new(ErrorKind::ShortBuffer)); }
    p1.buffer()[..read as usize].copy_from_slice(&tmp[..read as usize]);
    p1.set_updated_size(read as usize);
    Ok(())
}

fn cmd_set_server_pub(params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    let key = p0.buffer();
    if key.len() != 32 { return Err(Error::new(ErrorKind::ShortBuffer)); }
    // Store/overwrite
    let flags = DataFlag::ACCESS_READ | DataFlag::ACCESS_WRITE | DataFlag::ACCESS_WRITE_META | DataFlag::OVERWRITE;
    let mut init: [u8;0] = [];
    let mut obj = PersistentObject::create(ObjectStorageConstants::Private, SERVER_PUB_OBJ_ID, flags, None, &mut init)?;
    obj.write(key).map_err(|_| Error::new(ErrorKind::Generic))?;
    Ok(())
}

fn cmd_verify_server(params: &mut Parameters) -> Result<()> {
    // Load server pubkey (32 bytes)
    let obj = PersistentObject::open(ObjectStorageConstants::Private, SERVER_PUB_OBJ_ID, DataFlag::ACCESS_READ)
        .map_err(|_| Error::new(ErrorKind::AccessDenied))?;
    let info = obj.info()?;
    if info.data_size() != 32 { return Err(Error::new(ErrorKind::Generic)); }
    let mut srv = [0u8;32];
    let read = obj.read(&mut srv).unwrap();
    if read != 32 { return Err(Error::new(ErrorKind::Generic)); }
    // Parse input: u32 msg_len LE | msg | 64B sig
    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    let buf = p0.buffer();
    if buf.len() < 4 + 64 { return Err(Error::new(ErrorKind::ShortBuffer)); }
    let mlen = u32::from_le_bytes([buf[0],buf[1],buf[2],buf[3]]) as usize;
    if buf.len() < 4 + mlen + 64 { return Err(Error::new(ErrorKind::ShortBuffer)); }
    let msg = &buf[4..4+mlen];
    let sig = &buf[4+mlen..4+mlen+64];
    // Verify using OP-TEE Ed25519 verify
    let pubobj = TransientObject::allocate(TransientObjectType::Ed25519PublicKey, 256)?;
    // populate requires mutable self, pubobj is not mutable; allocate returns immutable. But TransientObject methods: populate(&mut self,...). So make mutable.
    let mut pubobj = pubobj;
    let attr = optee_utee::AttributeMemref::from_ref(AttributeId::Ed25519PublicValue, &srv);
    pubobj.populate(&[attr.into()])?;
    let op = Asymmetric::allocate(AlgorithmId::Ed25519, optee_utee::OperationMode::Verify, 256)?;
    op.set_key(&pubobj)?;
    // For Ed25519, use verify_digest with the message directly
    match op.verify_digest(&[], msg, sig) {
        Ok(()) => Ok(()),
        Err(_) => Err(Error::new(ErrorKind::AccessDenied)),
    }
}

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
