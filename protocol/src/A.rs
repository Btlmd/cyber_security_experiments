#[allow(non_snake_case)]
use log::{debug, error, info, trace};
use protocol::utils::*;
use rsa::{pkcs8::EncodePublicKey, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::{mem, net::TcpStream};

fn establish_conn() -> (Identifier, Key, TcpStream) {
    pretty_env_logger::init();
    let (addr, secret) = get_env();
    let ident = get_identifier();

    let mut stream =
        TcpStream::connect(&addr).expect(format!("Failed to connect to {}", &addr).as_str());
    info!("{:?}: Connected to {}", hex::encode(&ident), addr);

    /* Step 1 */
    debug!("Step 1");

    // A -> B: [A, E(pw, public_key_a)]
    trace!("Generating RSA key pair...");
    let private_key_a = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let public_key_a = RsaPublicKey::from(&private_key_a);
    let public_key_a_der = public_key_a.to_public_key_der().unwrap();
    let public_key_a_bytes = public_key_a_der.as_bytes();
    info!("Generated RSA key pair, public key hash = {}", {
        let mut hasher = Sha256::new();
        hasher.update(public_key_a_bytes);
        hex::encode(hasher.finalize())
    });
    let encrypted_public_key_a = encrypt_aes(&public_key_a_bytes, &secret);
    let msg = [Vec::from(ident), encrypted_public_key_a].concat();
    send_message(&mut stream, &msg, Some("[A, E(pw, public_key_a)]"));

    /* Step 3 */
    debug!("Step 3");

    // B -> A: E(pw, E(pka, session_key))
    let symmetric_encrypted_session_key = read_message(&mut stream)
        .expect("Failed to read E(pw, E(public_key_a, session_key)) from B");
    let rsa_encrypted_session_key = decrypt_aes(&symmetric_encrypted_session_key, &secret);
    let session_key = decrypt_rsa(&rsa_encrypted_session_key, &private_key_a);
    let session_key: Key = session_key
        .as_slice()
        .try_into()
        .expect("Failed to convert session_key to Key");
    info!("Decrypted session_key = {}", hex::encode(&session_key));

    // A -> B: E(session_key, nonce_a)
    let nonce_a = get_nouce();
    info!("Generated nonce_a = {}", hex::encode(&nonce_a));
    send_message(
        &mut stream,
        &encrypt_aes(&nonce_a, &session_key),
        Some("E(session_key, nonce_a)"),
    );

    /* Step 5 */
    debug!("Step 5");

    // B -> A: E(session_key, nonce_a || nonce_b)
    let nonce_a_cat_nonce_b = decrypt_aes(
        &read_message(&mut stream)
            .expect("Failed to read E(session_key, nonce_a || nonce_b) from B"),
        &session_key,
    );
    let (nonce_a_recv, nonce_b) = nonce_a_cat_nonce_b.split_at(mem::size_of::<Nonce>());
    info!("Received nonce_a = {}", hex::encode(&nonce_a_recv),);
    info!("Received nonce_b = {}", hex::encode(&nonce_b));

    // Check nonce_a_recv
    if nonce_a != nonce_a_recv {
        error!(
            "Nouce mismatch: nonce_a != nonce_a_recv, i.e. {} != {}",
            hex::encode(&nonce_a),
            hex::encode(&nonce_a_recv)
        );
        std::process::exit(1);
    } else {
        info!("Nonce match. Identity confirmed.");
    }

    // A -> B: E(session_key, nonce_b)
    send_message(
        &mut stream,
        &encrypt_aes(&nonce_b, &session_key),
        Some("E(session_key, nonce_b)"),
    );

    (ident, session_key, stream)
}

fn main() {
    let (_, session_key, mut stream) = establish_conn();

    let message = "TEST MESSAGE FROM A";
    send_message(
        &mut stream,
        &encrypt_aes(message.as_bytes(), &session_key),
        Some("Test Message"),
    );

    let test_messsage_from_b = decrypt_aes(
        &read_message(&mut stream).expect("Failed to read test message from B"),
        &session_key,
    );
    info!(
        "Received test message from B: `{}`",
        String::from_utf8(test_messsage_from_b).unwrap()
    );
}
