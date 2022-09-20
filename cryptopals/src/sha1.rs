use crate::aes::util::generate_rnd_key;

use self::lib::{Digest, Sha1};

pub mod lib;
pub mod simd;

#[derive(Debug, PartialEq, Eq)]
pub enum AuthenticationResult {
    Successful,
    Failed,
}

pub struct Message {
    pub message: Vec<u8>,
    pub mac: Digest,
}

pub struct Messenger {
    pub key: [u8; 16],
}

impl Default for Messenger {
    fn default() -> Self {
        Self {
            key: generate_rnd_key(),
        }
    }
}

impl Messenger {
    pub fn new(key: [u8; 16]) -> Self {
        Messenger { key: key }
    }

    fn key_encrypt(&self, message: &[u8]) -> Digest {
        let mut hash_cipher = Sha1::new();
        hash_cipher.update(&[&self.key, message].concat());
        hash_cipher.digest()
    }

    pub fn send(&self, message: &[u8]) -> Message {
        Message {
            message: message.to_vec(),
            mac: self.key_encrypt(message),
        }
    }

    pub fn authenticate_with_prefix_mac(&self, message: &Message) -> AuthenticationResult {
        let mut hash_cipher = Sha1::new();
        hash_cipher.update(&[self.key.to_vec(), message.message.clone()].concat());

        match hash_cipher.digest() == message.mac {
            true => AuthenticationResult::Successful,
            false => AuthenticationResult::Failed,
        }
    }
}
