use optee_teec::{Context, Operation, ParamNone, ParamTmpRef, Uuid};
use proto::{Command, UUID};

fn main() -> optee_teec::Result<()> {
    // Usage:
    //   secure_update_host genkey
    //   secure_update_host getpub der_out
    //   secure_update_host set-server-pub <path_to_pub>
    //   secure_update_host verify-server <addr> <server_ed25519_secret_64_optional>
    let mut args = std::env::args().skip(1);
    let cmd = args.next().expect("usage: genkey|getpub|set-server-pub");
    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID.trim()).unwrap();
    let mut sess = ctx.open_session(uuid)?;

    match cmd.as_str() {
        "genkey" => {
            let mut op = Operation::new(0, ParamNone, ParamNone, ParamNone, ParamNone);
            sess.invoke_command(Command::GenKey as u32, &mut op)?;
            println!("TA RSA key generated/stored");
        }
        "getpub" => {
            let out_path = args.next().expect("der_out");
            let mut out = vec![0u8; 2048];
            let mut p1 = ParamTmpRef::new_output(&mut out);
            let mut op = Operation::new(0, ParamNone, p1, ParamNone, ParamNone);
            sess.invoke_command(Command::GetPub as u32, &mut op)?;
            let (_a, p1, _c, _d) = op.parameters();
            let used = p1.updated_size();
            // parse u32 len(n) LE | n | u32 len(e) LE | e
            let buf = &out[..used];
            if buf.len() < 8 { panic!("short pub"); }
            let nlen = u32::from_le_bytes([buf[0],buf[1],buf[2],buf[3]]) as usize;
            if buf.len() < 4+nlen+4 { panic!("short pub"); }
            let n = buf[4..4+nlen].to_vec();
            let off = 4+nlen;
            let elen = u32::from_le_bytes([buf[off],buf[off+1],buf[off+2],buf[off+3]]) as usize;
            if buf.len() < off+4+elen { panic!("short pub"); }
            let e = buf[off+4..off+4+elen].to_vec();
            // Build SPKI DER manually from (n,e)
            let der = build_rsa_spki_der(&n, &e);
            std::fs::write(&out_path, &der).expect("write der");
            println!("Wrote {}", out_path);
        }
        "set-server-pub" => {
            let path = args.next().expect("path to server ed25519 pub");
            let key = read_ed25519_pubkey(&path).expect("read key");
            if key.len() != 32 { panic!("need 32-byte Ed25519 pub"); }
            let p0 = ParamTmpRef::new_input(&key);
            let mut op = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
            sess.invoke_command(Command::SetServerPub as u32, &mut op)?;
            println!("Server pub set");
        }
        "verify-server" => {
            let addr = args.next().unwrap_or("127.0.0.1:7888".into());
            // Connect to local server: receive u32 len(msg)|msg|64B sig
            use std::io::{Read, Write};
            let mut s = std::net::TcpStream::connect(&addr).expect("connect server");
            let mut lenb = [0u8;4]; s.read_exact(&mut lenb).unwrap();
            let mlen = u32::from_le_bytes(lenb) as usize;
            let mut msg = vec![0u8; mlen]; s.read_exact(&mut msg).unwrap();
            let mut sig = [0u8;64]; s.read_exact(&mut sig).unwrap();
            // Send to TA for verification
            let mut ctx = Context::new()?;
            let uuid = Uuid::parse_str(UUID.trim()).unwrap();
            let mut sess = ctx.open_session(uuid)?;
            let mut buf = Vec::with_capacity(4+mlen+64);
            buf.extend_from_slice(&(mlen as u32).to_le_bytes());
            buf.extend_from_slice(&msg);
            buf.extend_from_slice(&sig);
            let p0 = ParamTmpRef::new_input(&buf);
            let mut op = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
            sess.invoke_command(Command::VerifyServer as u32, &mut op)?;
            println!("Server signature verified by TA");
        }
        _ => panic!("unknown command"),
    }

    Ok(())
}

fn read_ed25519_pubkey(path: &str) -> std::io::Result<Vec<u8>> {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    if s.starts_with("ssh-ed25519 ") {
        // OpenSSH format: ssh-ed25519 <base64> [comment]
        let b64 = s.split_whitespace().nth(1).unwrap_or("");
        let data = base64::decode(b64).map_err(|_| std::io::ErrorKind::InvalidData)?;
        // parse: uint32 len("ssh-ed25519") | b"ssh-ed25519" | uint32 len(pk=32) | pk
        if data.len() < 4 { return Err(std::io::ErrorKind::InvalidData.into()); }
        let l1 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let off = 4 + l1;
        if data.len() < off + 4 { return Err(std::io::ErrorKind::InvalidData.into()); }
        let l2 = u32::from_be_bytes([data[off], data[off+1], data[off+2], data[off+3]]) as usize;
        let pk = &data[off+4..off+4+l2];
        return Ok(pk.to_vec());
    }
    // Raw 32-byte file fallback
    let raw = std::fs::read(path)?;
    Ok(raw)
}

fn der_len(mut len: usize) -> Vec<u8> {
    if len < 128 { return vec![len as u8]; }
    let mut bytes = Vec::new();
    while len > 0 { bytes.push((len & 0xFF) as u8); len >>= 8; }
    bytes.reverse();
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(0x80 | (bytes.len() as u8));
    out.extend_from_slice(&bytes);
    out
}

fn der_integer(i_be: &[u8]) -> Vec<u8> {
    let mut v = i_be;
    while v.len() > 0 && v[0] == 0 { v = &v[1..]; }
    let mut content = Vec::new();
    if v.first().map(|b| b & 0x80 != 0).unwrap_or(false) {
        content.push(0x00);
    }
    content.extend_from_slice(v);
    let mut out = Vec::new();
    out.push(0x02);
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(&content);
    out
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x30);
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(1 + bytes.len());
    content.push(0x00);
    content.extend_from_slice(bytes);
    let mut out = Vec::new();
    out.push(0x03);
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(&content);
    out
}

fn der_null() -> Vec<u8> { vec![0x05, 0x00] }

fn der_oid_rsa_encryption() -> Vec<u8> {
    vec![0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]
}

fn build_rsa_spki_der(n_be: &[u8], e_be: &[u8]) -> Vec<u8> {
    let rsa_pk = {
        let mut seq_content = Vec::new();
        seq_content.extend_from_slice(&der_integer(n_be));
        seq_content.extend_from_slice(&der_integer(e_be));
        der_sequence(&seq_content)
    };
    let alg_id = {
        let mut content = Vec::new();
        content.extend_from_slice(&der_oid_rsa_encryption());
        content.extend_from_slice(&der_null());
        der_sequence(&content)
    };
    let spk = der_bit_string(&rsa_pk);
    let mut spki_content = Vec::new();
    spki_content.extend_from_slice(&alg_id);
    spki_content.extend_from_slice(&spk);
    der_sequence(&spki_content)
}
