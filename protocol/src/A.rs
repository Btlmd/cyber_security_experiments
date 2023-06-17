use std::{net::TcpStream, io::Write, mem};
use log::{info, trace, error};
use protocol::utils::*;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::EncodePublicKey, Pkcs1v15Encrypt};
use sha2::{Sha256, Digest};

fn main() {
    pretty_env_logger::init();
    let (addr, secret) = get_env();
    let ident = get_identifier();

    let mut stream = TcpStream::connect(&addr).expect(format!("Failed to connect to {}", &addr).as_str());
    info!("{:?}: Connected to {}", ident, addr);
    let mut rng = rand::thread_rng();

    trace!("Sending identifier to B");

    // 1: A -> B: A, E_pw(pk_A)
    let sk_A = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    trace!("Generated RSA key pair");
    let pk_A = RsaPublicKey::from(&sk_A);
    trace!("Generated RSA key pair");
    let pk_A_der = pk_A.to_public_key_der().unwrap();
    let pk_A_bytes = pk_A_der.as_bytes();
    
    info!("Generated RSA key pair, public key hash = {:?}", {
        let mut hasher = Sha256::new();
        hasher.update(pk_A_bytes);
        hasher.finalize()
    });
    let E_pw_pkA = aes_enc(&pk_A_bytes, &secret);
    let mut msg = [Vec::from(ident), E_pw_pkA].concat();
    match stream.write(&msg) {
        Ok(n) => trace!("Sent [A, E_pw(pk_A)] to B, with {} bytes", n),
        Err(e) => panic!("Failed to send [A, E_pw(pk_A)] to B: {:?}", e)
    }

    // 2: B -> A: E_pw(E_pkA(Ks)), now decode Ks
    let E_pw_E_pkA_Ks = read_stream_by_len(&mut stream, 272)
        .expect("Failed to read E_pw(E_pkA(Ks)) from B");
    let E_pkA_Ks = aes_dec(&E_pw_E_pkA_Ks, &secret);
    let K_session = sk_A.decrypt(
        Pkcs1v15Encrypt,
        &E_pkA_Ks
    ).expect("Failed to decrypt E_pkA_Ks with sk_A");
    info!("Decrypted K_session = {:?}", K_session);

    // 3: A -> B: E_Ks(N_A)
    let N_A = get_nouce();
    info!("Generated N_A = {:?}", N_A);
    let E_Ks_NA = aes_enc(&N_A, &K_session);
    match stream.write(&E_Ks_NA) {
        Ok(n) => trace!("Sent E_Ks(N_A) to B, with {} bytes", n),
        Err(e) => panic!("Failed to send E_Ks(N_A) to B: {:?}", e)
    }

    // 4: B -> A: E_Ks(N_A || N_B)
    let E_Ks_NAB = read_stream_by_len(&mut stream, 48)
        .expect("Failed to read E_Ks(N_AB) from B");
    let N_AB = aes_dec(&E_Ks_NAB, &K_session);
    let (N_A_recv, N_B) = N_AB.split_at(mem::size_of::<Nonce>());

    // 5: Check N_A_recv; A -> B: E_Ks(N_B)
    if N_A != N_A_recv {
        error!("Nouce mismatch: N_A != N_A_recv, i.e. {:?} != {:?}", N_A, N_A_recv);
        std::process::exit(1);
    }
    let E_Ks_NB = aes_enc(&N_B, &K_session);
    match stream.write(&E_Ks_NB) {
        Ok(n) => trace!("Sent E_Ks(N_B) to B, with {} bytes", n),
        Err(e) => panic!("Failed to send E_Ks(N_B) to B: {:?}", e)
    }

    // Read welcome message from B
    let welcome_msg = read_stream_by_len(&mut stream, 32)
        .expect("Failed to read welcome message from B");
    let msg = aes_dec(&welcome_msg, &K_session);
    println!("Welcome message from B: \n{:?}", String::from_utf8(msg).unwrap());
}