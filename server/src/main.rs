use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use ed25519_dalek::{Keypair, SecretKey, PublicKey, Signer};
use rand::rngs::OsRng;
use rand_core::RngCore;

fn handle(mut stream: TcpStream, kp: &Keypair) -> std::io::Result<()> {
    // Protocol: send u32 len(msg)|msg|64B sig
    let mut msg = [0u8; 32];
    OsRng.fill_bytes(&mut msg);
    let sig = kp.sign(&msg);
    stream.write_all(&(msg.len() as u32).to_le_bytes())?;
    stream.write_all(&msg)?;
    stream.write_all(&sig.to_bytes())?;
    Ok(())
}

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or("127.0.0.1:7888".into());
    let key_path = args.next().expect("server <addr> <openssh_or_raw_ed25519_secret>");
    let kp = load_keypair(&key_path).expect("load sk");
    let listener = TcpListener::bind(&addr)?;
    eprintln!("listening on {}", addr);
    for s in listener.incoming() { if let Ok(s) = s { let _ = handle(s, &kp); } }
    Ok(())
}

fn load_keypair(path: &str) -> Result<Keypair, std::io::Error> {
    let data = std::fs::read(path)?;
    if data.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----") {
        return parse_openssh_priv(&String::from_utf8_lossy(&data));
    }
    // raw bytes: accept 32 or 64
    if data.len() == 32 {
        let sk = SecretKey::from_bytes(&data[..32]).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad sk"))?;
        let pk: PublicKey = (&sk).into();
        return Ok(Keypair { secret: sk, public: pk });
    }
    if data.len() == 64 {
        let sk = SecretKey::from_bytes(&data[..32]).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad sk"))?;
        let pk: PublicKey = (&sk).into();
        return Ok(Keypair { secret: sk, public: pk });
    }
    Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unsupported key format"))
}

fn parse_openssh_priv(pem: &str) -> Result<Keypair, std::io::Error> {
    // Extract base64 body
    let mut lines = pem.lines()
        .filter(|l| !l.starts_with("-----BEGIN") && !l.starts_with("-----END"));
    let b64: String = lines.collect();
    let der = base64::decode(b64.replace('\n', "")).map_err(|_| std::io::ErrorKind::InvalidData)?;
    // Parse openssh-key-v1
    let mut off = 0usize;
    fn take<'a>(buf:&'a [u8], off:&mut usize, n:usize) -> Result<&'a [u8], std::io::Error> {
        if *off + n > buf.len() { return Err(std::io::ErrorKind::UnexpectedEof.into()); }
        let s = &buf[*off..*off+n]; *off += n; Ok(s)
    }
    fn take_u32(buf:&[u8], off:&mut usize) -> Result<u32, std::io::Error> {
        let b = take(buf, off, 4)?; Ok(u32::from_be_bytes([b[0],b[1],b[2],b[3]]))
    }
    fn take_str<'a>(buf:&'a [u8], off:&mut usize) -> Result<&'a [u8], std::io::Error> {
        let l = take_u32(buf, off)? as usize; take(buf, off, l)
    }
    // magic
    let magic = take(&der, &mut off, 15)?; // "openssh-key-v1\0"
    if magic != b"openssh-key-v1\0" { return Err(std::io::ErrorKind::InvalidData.into()); }
    let ciphername = take_str(&der, &mut off)?;
    let kdfname = take_str(&der, &mut off)?;
    let _kdfopts = take_str(&der, &mut off)?;
    if ciphername != b"none" || kdfname != b"none" { return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "encrypted key not supported")); }
    let nkeys = take_u32(&der, &mut off)?;
    if nkeys < 1 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "no keys")); }
    let _pub = take_str(&der, &mut off)?; let _ = _pub;
    let privblob = take_str(&der, &mut off)?;
    // parse private blob
    let mut poff = 0usize;
    let _check1 = u32::from_be_bytes(privblob[poff..poff+4].try_into().unwrap()); poff+=4;
    let _check2 = u32::from_be_bytes(privblob[poff..poff+4].try_into().unwrap()); poff+=4;
    // key entry
    let ktype = {
        let l = u32::from_be_bytes(privblob[poff..poff+4].try_into().unwrap()) as usize; poff+=4;
        &privblob[poff..poff+l]
    };
    poff += ktype.len();
    if ktype != b"ssh-ed25519" { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not ed25519")); }
    let _pubk = {
        let l = u32::from_be_bytes(privblob[poff..poff+4].try_into().unwrap()) as usize; poff+=4;
        &privblob[poff..poff+l]
    };
    poff += _pubk.len();
    let privk = {
        let l = u32::from_be_bytes(privblob[poff..poff+4].try_into().unwrap()) as usize; poff+=4;
        &privblob[poff..poff+l]
    };
    poff += privk.len();
    if privk.len() < 32 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "priv too short")); }
    let sk = SecretKey::from_bytes(&privk[..32]).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad sk"))?;
    let pk: PublicKey = (&sk).into();
    Ok(Keypair { secret: sk, public: pk })
}
