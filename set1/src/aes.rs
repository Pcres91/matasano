use bitstream_io::{BigEndian, BitReader, BitWriter};
use std::io::{Cursor, Error, ErrorKind};

pub fn encrypt(plain_text: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, Error> {
    if plain_text.len() % 16 != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Data must be in blocks of 128",
        ));
    }

    let mut blocks: Vec<u8> = plain_text.to_vec();

    for i in 0..(blocks.len() / 16) {
        let idx = i * 16;
        run_encrypt_round(&mut blocks[idx..idx + 16], key);
    }

    Ok(blocks)
}

pub fn decrypt(cipher: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, Error> {
    if cipher.len() % 16 != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Data must be in blocks of 128",
        ));
    }

    let mut blocks: Vec<u8> = cipher.to_vec();

    for i in 0..(blocks.len() / 16) {
        let idx = i * 16;
        run_decrypt_round(&mut blocks[idx..idx + 16], key);
    }

    Ok(blocks)
}

fn run_encrypt_round(mut block: &mut [u8], key: &[u8; 16]) {
    apply_key(&mut block, key);
    substitute_bytes(&mut block);
    mix_rows(&mut block);
    mix_columns(&mut block);
}

fn run_decrypt_round(mut block: &mut [u8], key: &[u8; 16]) {
    inverse_mix_columns(&mut block);
    inverse_mix_rows(&mut block);
    inverse_substitute_bytes(&mut block);
    apply_key(&mut block, key);
}

fn apply_key(data: &mut [u8], key: &[u8; 16]) {}

fn substitute_bytes(data: &mut [u8]) {}

fn inverse_substitute_bytes(data: &mut [u8]) {}

fn mix_rows(data: &mut [u8]) {}

fn inverse_mix_rows(data: &mut [u8]) {}

fn mix_columns(data: &mut [u8]) {}

fn inverse_mix_columns(data: &mut [u8]) {}
