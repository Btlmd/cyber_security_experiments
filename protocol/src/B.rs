#[allow(non_snake_case)]
use protocol::utils::*;
use rsa::{pkcs8::DecodePublicKey, RsaPublicKey};
use std::{
    mem,
    net::{TcpListener, TcpStream},
};

use log::{debug, error, info};
use sha2::{Digest, Sha256};

fn handle_requeststream(stream: &mut TcpStream, secret: &Key) -> Option<(Identifier, Key)> {
    /* Step 2 */
    debug!("Step 2");

    // A -> B: [A, E_pw(public_key_a)]
    let msg = read_message(stream).expect("Failed to read message from A");
    let (ident, encrypted_public_key_a) = msg.split_at(mem::size_of::<Identifier>());
    info!("Get request identified as {}", hex::encode(&ident));

    // parse public key from A
    let public_key_a_bytes = decrypt_aes(&encrypted_public_key_a, secret);
    info!("Receive public key, hash = {}", {
        let mut hasher = Sha256::new();
        hasher.update(&public_key_a_bytes);
        hex::encode(hasher.finalize())
    });
    let public_key_a = RsaPublicKey::from_public_key_der(&public_key_a_bytes)
        .expect("Failed to parse public key bytes");

    // B -> A: E(pw, E(public_key_a, session_key))
    let session_key = get_session_key();
    info!("Generated session_key = {}", hex::encode(&session_key));
    let rsa_encrypted_session_key = encrypt_rsa(&session_key, &public_key_a);
    let symmetric_encrypted_session_key = encrypt_aes(&rsa_encrypted_session_key, secret);
    send_message(
        stream,
        &symmetric_encrypted_session_key,
        Some("E(pw, E(public_key_a, session_key))"),
    );

    /* Step 4 */
    debug!("Step 4");

    // A -> B: E(session_key, nonce_a)
    let nonce_a = decrypt_aes(
        &read_message(stream).expect("Failed to read E(session_key, nonce_a) from A"),
        &session_key,
    );
    info!("Received nonce_a = {}", hex::encode(&nonce_a));

    // B -> A: E(session_key, nonce_a || nonce_b)
    let nonce_b = get_nouce();
    let encrypted_nonce_a_cat_nonce_b =
        encrypt_aes(&[nonce_a, Vec::from(nonce_b)].concat(), &session_key);
    send_message(
        stream,
        &encrypted_nonce_a_cat_nonce_b,
        Some("E(session_key, nonce_a || nonce_b)"),
    );

    /* Step 6 */
    debug!("Step 6");

    // A -> B: E(session_key, nonce_b)
    let nonce_b_recv = decrypt_aes(
        &read_message(stream).expect("Failed to read E(session_key, nonce_b) from A"),
        &session_key,
    );
    let nonce_b_recv = nonce_b_recv.as_slice();
    info!("Received nonce_b = {}", hex::encode(&nonce_b_recv));


    // Check nonce_b_recv
    if nonce_b != nonce_b_recv {
        error!(
            "Nouce mismatch: nonce_b != nonce_b_recv, i.e. {} != {}",
            hex::encode(&nonce_b),
            hex::encode(&nonce_b_recv)
        );
        return None;
    } else {
        info!("Nonce match. Identity confirmed.");
    }

    // convert to Identifier and Key
    let ident: Identifier = ident
        .try_into()
        .expect("Failed to convert ident to Identifier");
    let session_key: Key = session_key
        .try_into()
        .expect("Failed to convert session_key to Key");

    Some((ident, session_key))
}

fn main() {
    pretty_env_logger::init();
    let (addr, secret) = get_env();
    let listener = TcpListener::bind(&addr).expect(format!("Failed to bind to {}", &addr).as_str());
    info!("Listening on {}", addr);

    loop {
        let (mut stream, _) = listener.accept().expect("Failed to accept connection");
        info!("Accepted connection from {:?}", stream.peer_addr().unwrap());

        match handle_requeststream(&mut stream, &secret) {
            Some((_, session_key)) => {
                let test_messsage_from_a =
                    read_message(&mut stream).expect("Failed to read test message from A");
                let test_messsage_from_a = decrypt_aes(&test_messsage_from_a, &session_key);
                info!(
                    "Received test message from A: `{}`",
                    String::from_utf8(test_messsage_from_a).unwrap()
                );

                let message = "TEST MESSAGE FROM B";
                let encrypted_message = encrypt_aes(message.as_bytes(), &session_key);
                send_message(&mut stream, &encrypted_message, Some("Test Message"));
            }
            None => {
                error!(
                    "Fail to establish connection from {:?}",
                    stream.peer_addr().unwrap()
                );
            }
        }
    }
}
