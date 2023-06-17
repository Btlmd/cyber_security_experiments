use std::{net::{TcpListener, TcpStream}, thread, io::Write, mem};
use protocol::utils::*;
use rand::thread_rng;
use rsa::{pkcs8::{der::Decode, DecodePublicKey}, RsaPublicKey, PublicKey, PaddingScheme, Pkcs1v15Encrypt};

use log::{info, trace, error};
use sha2::{Sha256, Digest};

fn main() -> std::io::Result<()> {
    pretty_env_logger::init();
    let (addr, secret) = get_env();
    let listener = TcpListener::bind(&addr).expect(format!("Failed to bind to {}", &addr).as_str());
    info!("Listening on {}", addr);

    // get an incoming stream
    let (mut stream, _) = listener.accept().expect("Failed to accept connection");
    trace!("Accepted connection from {:?}", stream.peer_addr()?);

    // 1: A -> B: A, E_pw(pk_A)
    let msg = read_stream_by_len(&mut stream, 308)
                                            .expect("Failed to read message from A");
    let (ident, E_pw_pkA) = msg.split_at(mem::size_of::<Identifier>());
    info!("Get request from {:?}, E_pw(pk_A) length: {}", ident, E_pw_pkA.len());

    // parse public key from A
    let pk_A_bytes = aes_dec(&E_pw_pkA, &secret);
    info!("Receive public key, hash = {:?}", {
        let mut hasher = Sha256::new();
        hasher.update(&pk_A_bytes);
        hasher.finalize()
    });
    let pk_A = RsaPublicKey::from_public_key_der(&pk_A_bytes).expect("Failed to parse public key bytes");

    // 2: B -> A: E_pw(E_pkA(Ks))
    let K_session = get_session_key();
    info!("Generated K_session = {:?}", K_session);
    let E_pkA_Ks = pk_A.encrypt(
            &mut thread_rng(),
            Pkcs1v15Encrypt,
            &K_session.clone()
        ).unwrap();
    let E_pw_E_pkA_Ks = aes_enc(&E_pkA_Ks, &secret);
    match stream.write(&E_pw_E_pkA_Ks) {
        Ok(n) => trace!("Sent E_pw(E_pkA(Ks)) to A, with {} bytes", n),
        Err(e) => panic!("Failed to send E_pw(E_pkA(Ks)) to A: {:?}", e)
    }

    // 3: A -> B: E_Ks(N_A)
    let E_Ks_NA = read_stream_by_len(&mut stream, 32)
        .expect("Failed to read E_Ks_NA from A");
    let N_A = aes_dec(&E_Ks_NA, &K_session);
    info!("Received N_A = {:?}", N_A);
    
    // 4: B -> A: E_Ks(N_A || N_B)
    let N_B = get_nouce();
    let N_AB = [N_A, Vec::from(N_B)].concat();
    let E_Ks_NAB = aes_enc(&N_AB, &K_session);
    match stream.write(&E_Ks_NAB) {
        Ok(n) => trace!("Sent E_Ks(N_AB) to A, with {} bytes", n),
        Err(e) => panic!("Failed to send E_Ks(N_AB) to A: {:?}", e)
    }

    // 5: A -> B: E_Ks(N_B)
    let N_B_back_data = read_stream_by_len(&mut stream, 32)
        .expect("Failed to read E_Ks(N_B) from A");
    let N_B_recv = aes_dec(&N_B_back_data, &K_session);
    let N_B_recv = N_B_recv.as_slice();

    if N_B != N_B_recv {
        error!("Nouce mismatch: N_B != N_B_recv, i.e. {:?} != {:?}", N_B, N_B_recv);
        std::process::exit(1);
    }

    // Last Step
    println!("Connection established!");
    println!("Hello world from peer B!");

    let message = "Hello world from peer A!".as_bytes();
    let encrypted_message = aes_enc(message, &K_session);
    // println!("Encrypted message: {:?}", encrypted_message.len());
    stream.write(&encrypted_message).expect("Failed to send message to A");

    Ok(())
}