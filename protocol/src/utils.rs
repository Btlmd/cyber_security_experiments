use std::{fmt, env};
use std::io::Read;

use aes::{cipher::generic_array::GenericArray, Aes128, NewBlockCipher, BlockEncrypt, BlockDecrypt};
use rand::RngCore;

pub type Key = [u8; 16];
pub type Identifier = [u8; 4];
pub type Nonce = [u8; 16];

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
    let secret = base64::decode(secret).expect("Failed to decode secret from base64");

    // pad secret to 16 bytes
    let secret = {
        let mut secret = secret;
        secret.resize(16, 0);
        secret
    };

    let key: Key = secret[..16].try_into().expect(&format!("Failed to convert {:?} to Key", secret));

    (addr, key)
}

pub fn aes_enc(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    
    let data_length = data.len();
    
    // insert data_length as first 8 bytes of data
    let mut data2 = Vec::new();
    data2.extend(data_length.to_be_bytes());
    data2.extend(data);

    let encrypter = Aes128::new(key.into());

    let blocks = data2.chunks(16);
    
    for block in blocks {
        let mut block = block.to_vec();
        block.resize(16, 0);
        encrypter.encrypt_block(GenericArray::from_mut_slice(&mut block));
        result.extend(block);
    }

    result
}

pub fn aes_dec(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let decrypter = Aes128::new(key.into());

    let blocks = data.chunks(16);
    
    for block in blocks {
        let mut block = block.to_vec();
        block.resize(16, 0);
        decrypter.decrypt_block(GenericArray::from_mut_slice(&mut block));
        result.extend(block);
    }

    // first decode the length of the data
    let data_length = usize::from_be_bytes(result[..8].try_into().unwrap());
    result[8..8+data_length as usize].to_vec()
}

pub fn read_stream_by_len(stream: &mut std::net::TcpStream, length: i32) -> std::io::Result<Vec<u8>> {
    let mut buffer = [0; 65536];
    let mut result = Vec::new();

    let mut bytes_read = 0;

    while bytes_read < length {
        let bytes = stream.read(&mut buffer).expect(
            &fmt::format(format_args!("Failed to read {} bytes from stream", length))
        );
        if bytes == 0 {
            // sleep for 0.1 seconds
            println!("Sleeping for 0.1 seconds, current bytes read: {}", bytes_read);
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        result.extend(&buffer[..bytes]);
        bytes_read += bytes as i32;
    }

    Ok(result[..length as usize].to_vec())
}

