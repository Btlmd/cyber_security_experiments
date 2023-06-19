use std::{
    env,
    io::{Read, Result, Write},
    net::TcpStream,
};

use aes::{
    cipher::generic_array::GenericArray, Aes128, BlockDecrypt, BlockEncrypt, NewBlockCipher,
};
use log::trace;
use rand::RngCore;
use rsa::{Pkcs1v15Encrypt, PublicKey, RsaPrivateKey, RsaPublicKey};

pub const BLOCK_LEN: usize = 16;
pub const IDENT_LEN: usize = 4;
pub const NONCE_LEN: usize = 32;

pub type Block = [u8; BLOCK_LEN];
pub type Key = [u8; BLOCK_LEN];
pub type Identifier = [u8; IDENT_LEN];
pub type Nonce = [u8; NONCE_LEN];

pub const IV: Block = [0; BLOCK_LEN];

pub fn get_identifier() -> Identifier {
    let mut rng = rand::thread_rng();
    let mut identifier = Identifier::default();
    rng.fill_bytes(&mut identifier);
    identifier
}

pub fn get_session_key() -> Key {
    let mut rng = rand::thread_rng();
    let mut key = Key::default();
    rng.fill_bytes(&mut key);
    key
}

pub fn get_nouce() -> Nonce {
    let mut rng = rand::thread_rng();
    let mut nonce = Nonce::default();
    rng.fill_bytes(&mut nonce);
    nonce
}

pub fn get_env() -> (String, Key) {
    // get 'ADDR' and 'SECRET' from envrioment variables
    let addr = std::env::var("ADDR").expect("Failed to get ADDR from envrioment variables");
    let secret = env::var("SECRET").expect("Failed to get SECRET from envrioment variables");

    // base64 decode secret
    let mut secret = base64::decode(secret).expect("Failed to decode secret from base64");

    // pad secret to BLOCK_LEN
    secret.resize(BLOCK_LEN, 0);

    let key: Key = secret[..BLOCK_LEN]
        .try_into()
        .expect(&format!("Failed to convert {:?} to Key", &secret));

    (addr, key)
}

pub fn encrypt_rsa(data: &[u8], key: &RsaPublicKey) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    key.encrypt(&mut rng, Pkcs1v15Encrypt, data).unwrap()
}

pub fn decrypt_rsa(data: &[u8], key: &RsaPrivateKey) -> Vec<u8> {
    key.decrypt(Pkcs1v15Encrypt, data).unwrap()
}

pub fn encrypt_aes(payload: &[u8], key: &[u8]) -> Vec<u8> {
    let mut encryption: Vec<u8> = Vec::new();
    let encrypter = Aes128::new(key.into());

    let data_length: [u8; 8] = (payload.len() as u64).to_be_bytes().try_into().unwrap();
    let mut data_length_block = Block::default();
    data_length_block[..8].clone_from_slice(&data_length);
    let mut blocks: Vec<u8> = Vec::new();
    blocks.extend(data_length_block);
    blocks.extend(payload);

    let blocks = blocks.chunks(BLOCK_LEN);

    // entrypt using CBC
    let mut prev_block = Vec::from(IV);
    for block in blocks {
        let mut block = block.to_vec();
        block.resize(BLOCK_LEN, 0);
        for i in 0..BLOCK_LEN {
            block[i] ^= prev_block[i];
        }
        encrypter.encrypt_block(GenericArray::from_mut_slice(&mut block));
        prev_block = block.clone();
        encryption.extend(block);
    }

    encryption
}

pub fn decrypt_aes(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decryption: Vec<u8> = Vec::new();
    let decrypter = Aes128::new(key.into());

    assert!(
        data.len() % BLOCK_LEN == 0,
        "data length {} is not a multiple of {}",
        data.len(),
        BLOCK_LEN
    );
    let blocks = data.chunks(BLOCK_LEN);

    // decrypt using CBC
    let mut prev_block = Vec::from(IV);
    for block in blocks {
        let mut dec_block = block.to_vec();
        decrypter.decrypt_block(GenericArray::from_mut_slice(&mut dec_block));
        for i in 0..BLOCK_LEN {
            dec_block[i] ^= prev_block[i];
        }
        prev_block = Vec::from(block);
        decryption.extend(dec_block);
    }

    // remove padding
    let data_length = usize::from_be_bytes(decryption[..8].try_into().unwrap());
    decryption.drain(..BLOCK_LEN);
    decryption.truncate(data_length);
    decryption
}

pub fn send_message(stream: &mut std::net::TcpStream, data: &[u8], desc: Option<&str>) {
    let msg_len = data.len();
    let mut msg_with_len = Vec::new();
    msg_with_len.extend(msg_len.to_be_bytes());
    msg_with_len.extend(data);
    match stream.write(&msg_with_len) {
        Ok(n) => {
            if let Some(desc) = desc {
                trace!("Sent {}, {} bytes in total", desc, n);
            } else {
                trace!("Sent {} bytes in total", n);
            }
        }
        Err(e) => panic!("Failed to send {:?} to B: {:?}", &msg_with_len, e),
    }
}

pub fn read_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut length_buffer = [0; 8];
    stream.read_exact(&mut length_buffer)?;
    let length = usize::from_be_bytes(length_buffer);
    trace!("Receive message, length = {}", length);
    let mut buffer = vec![0; length];
    stream.read_exact(&mut buffer)?;
    Ok(buffer)
}
