use std::io::{Error, ErrorKind};

pub const KNOWN_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

pub fn encrypt_ecb_128(plain_text: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != 16 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("encrypt_ecb_128(): Key must be 16 bytes. Got {}", key.len()),
        ));
    }

    let expanded_key = expand_key(key)?;

    let mut blocks: Vec<u8> = plain_text.to_vec();
    pkcs7_pad(&mut blocks, 16)?;
    for i in 0..(blocks.len() / 16) {
        let idx = i * 16;
        encrypt_block_128(&mut blocks[idx..idx + 16], &expanded_key)?;
    }

    Ok(blocks)
}

pub fn decrypt_ecb_128(cipher_text: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, Error> {
    if cipher_text.len() % 16 != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "decrypt_ecb_128(): Data must be in blocks of 16 bytes, got {}",
                cipher_text.len()
            ),
        ));
    }
    if key.len() != 16 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("decrypt_ecb_128(): Key must be 16 bytes. Got {}", key.len()),
        ));
    }

    let expanded_key = expand_key(key)?;

    let mut blocks: Vec<u8> = cipher_text.to_vec();
    for i in 0..(blocks.len() / 16) {
        let idx = i * 16;
        decrypt_block_128(&mut blocks[idx..idx + 16], &expanded_key)?;
    }

    let mut pkcs7_padded = true;

    let last_val = blocks[blocks.len() - 1];
    for i in 0..last_val as usize {
        let idx = blocks.len() - 1 - i;
        if blocks[idx] != last_val {
            pkcs7_padded = false;
            break;
        }
    }

    if pkcs7_padded {
        blocks = blocks[..blocks.len() - last_val as usize].to_vec();
    }

    Ok(blocks)
}

pub fn detect_cipher_in_ecb_128_mode(cipher_text: &[u8]) -> bool {
    let num_blocks = cipher_text.len() / 16;

    use std::collections::hash_set::HashSet;
    let mut set: HashSet<Vec<u8>> = HashSet::new();
    for i in 0..num_blocks {
        let idx = i * 16;
        set.insert(cipher_text[idx..idx + 16].to_vec());
    }
    let num_unique_blocks = set.len();

    num_blocks - num_unique_blocks > 1
}

pub fn encrypt_cbc_128(plain_text: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let iv = vec![0u8; 16];
    Ok(encrypt_cbc_128_with_iv(plain_text, key, &iv)?)
}

pub fn encrypt_cbc_128_with_iv(
    cipher_text: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, Error> {
    let expanded_key = expand_key(key)?;

    let mut blocks: Vec<u8> = cipher_text.to_vec();
    let mut prev_block = iv.to_vec();

    for i in 0..blocks.len() / 16 {
        let idx = i * 16;

        for j in 0..16 {
            blocks[idx + j] ^= prev_block[j];
        }

        encrypt_block_128(&mut blocks[idx..idx + 16], &expanded_key)?;

        prev_block = blocks[idx..idx + 16].to_vec();
    }

    Ok(blocks)
}

pub fn decrypt_cbc_128(cipher_text: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    let iv = vec![0u8; 16];
    Ok(decrypt_cbc_128_with_iv(cipher_text, key, &iv)?)
}

pub fn decrypt_cbc_128_with_iv(
    cipher_text: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, Error> {
    let expanded_key = expand_key(key)?;

    let mut blocks: Vec<u8> = cipher_text.to_vec();
    let mut prev_block = iv.to_vec();

    for i in 0..blocks.len() / 16 {
        let idx = i * 16;
        let block = blocks[idx..idx + 16].to_vec();

        decrypt_block_128(&mut blocks[idx..idx + 16], &expanded_key)?;

        for j in 0..16 {
            blocks[idx + j] ^= prev_block[j];
        }

        prev_block = block.to_vec();
    }
    Ok(blocks)
}

pub fn break_ecb_128_ciphertext(
    cipher_text: &[u8],
    encryptor: &dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    let block_size = find_block_length(&cipher_text, encryptor)?;
    if block_size != 16 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Breaking aes-ecb-128: Block size not found to be size 16.",
        ));
    }

    let in_ecb_mode = detect_cipher_in_ecb_128_mode(&ecb_encryption_oracle(
        &vec![b'a'; block_size * 5],
        &cipher_text,
        &encryptor,
    )?);
    if !in_ecb_mode {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Could not assert that the data is aes-ecb-128 encrypted",
        ));
    }

    let mut result: Vec<u8> = Vec::new();

    for block_num in 0..cipher_text.len() / 16 + 1 {
        let idx = block_num * 16;
        let end_idx = if idx + 16 < cipher_text.len() {
            idx + 16
        } else {
            cipher_text.len()
        };

        result.extend_from_slice(&break_ecb_128_cipherblock(
            &cipher_text[idx..end_idx],
            &encryptor,
        )?);
    }

    Ok(result)
}

/// block can be < 16
pub fn break_ecb_128_cipherblock(
    block: &[u8],
    encryptor: &dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    let block_size = 16;

    let mut result: Vec<u8> = vec![0u8; block.len()];

    let mut new_input_block = vec![b'A'; 16];
    let mut decrypted_char = b'\0';

    #[allow(clippy::needless_range_loop)]
    for char_idx in 0..block.len() {
        let input_block = vec![b'A'; block_size - char_idx - 1];
        let ecb_input_block_with_unkown = ecb_encryption_oracle(&input_block, block, encryptor)?;
        let expected_block = &ecb_input_block_with_unkown[..16];

        for i in SMART_ASCII.iter() {
            new_input_block[15] = *i;
            let new_output = ecb_encryption_oracle(&[], &new_input_block, encryptor)?;
            if &new_output[..16] == expected_block {
                decrypted_char = *i;
                break;
            }
        }
        if decrypted_char == b'\0' {
            println!("Char couldnt be found, returning result up to point",);
            break;
        } else {
            new_input_block.remove(0);
            new_input_block.push(decrypted_char);
            result[char_idx] = decrypted_char;
        }
    }

    Ok(result)
}

pub fn generate_key() -> Vec<u8> {
    extern crate rand;
    use rand::prelude::*;

    let mut rng = rand::thread_rng();

    let mut key = vec![0u8; 16];
    rng.fill_bytes(&mut key);

    key
}

pub fn rnd_encryption_oracle(plain_text: &[u8]) -> Result<(Vec<u8>, bool), Error> {
    let key = generate_key();

    extern crate rand;
    use rand::prelude::*;
    let mut rng = rand::thread_rng();

    // extend plain text with 5-10 bytes at the start and end
    let num_prefix_bytes: usize = rng.gen_range(5, 11);
    let mut prefix = vec![0u8; num_prefix_bytes];
    rng.fill_bytes(&mut prefix);

    let num_suffix_bytes: usize = rng.gen_range(5, 11);
    let mut suffix = vec![0u8; num_suffix_bytes];
    rng.fill_bytes(&mut suffix);

    let mut new_plain_text: Vec<u8> = Vec::new();
    new_plain_text.extend_from_slice(&prefix);
    new_plain_text.extend_from_slice(plain_text);
    new_plain_text.extend_from_slice(&suffix);

    pkcs7_pad(&mut new_plain_text, 16)?;

    // select to either encrypt ecb/cbc
    let ecb_encrypt: bool = rng.gen();

    // println!("ecb encryption: {}", ecb_encrypt);

    if ecb_encrypt {
        Ok((encrypt_ecb_128(&new_plain_text, &key)?, true))
    } else {
        let iv: [u8; 16] = rng.gen();
        Ok((encrypt_cbc_128_with_iv(&new_plain_text, &key, &iv)?, false))
    }
}

pub fn decryption_oracle(
    encryptor: &dyn Fn(&[u8]) -> Result<(Vec<u8>, bool), Error>,
) -> Result<bool, Error> {
    let plain_text = [b'a'; 16 * 5];
    let (cipher_text, in_ecb_mode) = encryptor(&plain_text)?;
    let detected_ecb = detect_cipher_in_ecb_128_mode(&cipher_text);

    Ok(detected_ecb == in_ecb_mode)
}

pub fn ecb_encryption_oracle(
    known_text: &[u8],
    cipher_text: &[u8],
    encryptor: &dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    let mut concatted = known_text.to_vec();
    concatted.extend_from_slice(cipher_text);
    pkcs7_pad(&mut concatted, 16)?;

    Ok(encryptor(&concatted, &KNOWN_KEY)?)
}

pub fn find_block_length(
    cipher_text: &[u8],
    encryptor: &dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, Error>,
) -> Result<usize, Error> {
    let mut prev_length = 0;
    for i in 0..0xff {
        let known_text = vec![b'a'; i];
        let new_cipher = ecb_encryption_oracle(&known_text, cipher_text, encryptor)?;

        if prev_length == 0 {
            prev_length = new_cipher.len();
        } else {
            let block_size = new_cipher.len() - prev_length;
            if block_size != 0 {
                return Ok(block_size);
            }

            prev_length = new_cipher.len();
        }
    }

    Err(Error::new(
        ErrorKind::NotFound,
        "Couldn't find the block length",
    ))
}

fn encrypt_block_128(block: &mut [u8], expanded_key: &[u8]) -> Result<(), Error> {
    if expanded_key.len() != 176 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "encrypt_block(): Expanded key must be 176 bytes. Got length {}",
                expanded_key.len()
            ),
        ));
    }

    apply_key(block, &expanded_key[..16])?;

    for round in 1..10 {
        mix_and_sub_rows(block)?;
        mix_columns(block)?;
        apply_key(block, &expanded_key[round * 16..round * 16 + 16])?;
    }

    //last round, no mix columns
    mix_and_sub_rows(block)?;
    apply_key(block, &expanded_key[10 * 16..10 * 16 + 16])?;

    Ok(())
}

fn decrypt_block_128(block: &mut [u8], expanded_key: &[u8]) -> Result<(), Error> {
    if expanded_key.len() != 176 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "decrypt_block(): Expanded key must be 176 bytes. Got length {}",
                expanded_key.len()
            ),
        ));
    }

    // must be last four words of the expanded key
    apply_key(block, &expanded_key[160..176])?;

    let mut key_idx: usize = 144;
    for _round in 1..10 {
        inverse_mix_and_sub_rows(block)?;
        apply_key(block, &expanded_key[key_idx..key_idx + 16])?;
        inverse_mix_columns(block)?;
        key_idx -= 16;
    }

    //final round
    inverse_mix_and_sub_rows(block)?;
    apply_key(block, &expanded_key[..16])?;

    Ok(())
}

fn expand_key(key: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != 16 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("expand_key(): Key must be 16 bytes. Got {}", key.len()),
        ));
    }

    // get 11-rounds-worth of keys
    let mut expanded_key = vec![0u8; 176];

    // first round key is the key
    expanded_key[..16].clone_from_slice(&key[..16]);

    // for rounds 1 -> 10
    for round_num in 1..11 {
        // get g(last word from prev key)
        let g_word = g(&expanded_key[round_num * 16 - 4..round_num * 16], round_num)?;

        // set first word: XOR previous word with g(first word of previous key)
        for idx in 0..4 {
            expanded_key[round_num * 16 + idx] =
                expanded_key[(round_num - 1) * 16 + idx] ^ g_word[idx];
        }

        // set second, third and fourth word: XOR previous word with word of previous key
        for idx in 4..4 * 4 {
            expanded_key[round_num * 16 + idx] =
                expanded_key[round_num * 16 - 4 + idx] ^ expanded_key[(round_num - 1) * 16 + idx];
        }
    }

    Ok(expanded_key)
}

fn g(word_in: &[u8], rcon_idx: usize) -> Result<Vec<u8>, Error> {
    if word_in.len() != 4 {
        return Err(Error::new(ErrorKind::InvalidData, "Word must be 4 bytes"));
    }

    // rotate bytes left once and substitute from S-box
    let tmp = [
        SUB_TABLE[word_in[1] as usize],
        SUB_TABLE[word_in[2] as usize],
        SUB_TABLE[word_in[3] as usize],
        SUB_TABLE[word_in[0] as usize],
    ];

    // xor with round constant rcon
    let arr2 = [RCON[rcon_idx], 0, 0, 0];
    Ok(xor_words(&tmp, &arr2)?)
}

fn xor_words(l: &[u8], r: &[u8]) -> Result<Vec<u8>, Error> {
    if l.len() != 4 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("xor_words(): l must be 4 bytes, got {}", l.len()),
        ));
    }
    if r.len() != 4 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("xor_words(): r must be 4 bytes, got {}", r.len()),
        ));
    }

    Ok(vec![l[0] ^ r[0], l[1] ^ r[1], l[2] ^ r[2], l[3] ^ r[3]])
}

fn apply_key(state: &mut [u8], key: &[u8]) -> Result<(), Error> {
    if key.len() != 16 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("apply_key(): Key must be 16 bytes. Got {}", key.len()),
        ));
    }
    if state.len() != 16 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("apply_key(): State must be 16 bytes. Got {}", state.len()),
        ));
    }

    for i in 0..state.len() {
        state[i] ^= key[i];
    }

    Ok(())
}

fn mix_and_sub_rows(state: &mut [u8]) -> Result<(), Error> {
    // row 0 doesn't change
    // row 1 rotated left once
    // row 2 rotated left twice
    // row 3 rotated left 3 times
    // could be done with shifting u32s but didn't want
    // to deal with the memory casting
    if state.len() != 16 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "mix_and_sub_rows(): state must be 16 bytes in length, got {}",
                state.len()
            ),
        ));
    }
    let tmp = state.to_vec();

    state[0] = SUB_TABLE[tmp[0] as usize];
    state[4] = SUB_TABLE[tmp[4] as usize];
    state[8] = SUB_TABLE[tmp[8] as usize];
    state[12] = SUB_TABLE[tmp[12] as usize];

    state[1] = SUB_TABLE[tmp[5] as usize];
    state[5] = SUB_TABLE[tmp[9] as usize];
    state[9] = SUB_TABLE[tmp[13] as usize];
    state[13] = SUB_TABLE[tmp[1] as usize];

    state[2] = SUB_TABLE[tmp[10] as usize];
    state[6] = SUB_TABLE[tmp[14] as usize];
    state[10] = SUB_TABLE[tmp[2] as usize];
    state[14] = SUB_TABLE[tmp[6] as usize];

    state[3] = SUB_TABLE[tmp[15] as usize];
    state[7] = SUB_TABLE[tmp[3] as usize];
    state[11] = SUB_TABLE[tmp[7] as usize];
    state[15] = SUB_TABLE[tmp[11] as usize];

    Ok(())
}

fn inverse_mix_and_sub_rows(state: &mut [u8]) -> Result<(), Error> {
    // row 0 doesn't change
    // row 1 rotated right once
    // row 2 rotated right twice
    // row 3 rotated right 3 times
    if state.len() != 16 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "state must be 16 bytes in length",
        ));
    }
    let tmp = state.to_vec();

    state[0] = INV_SUB_TABLE[tmp[0] as usize];
    state[4] = INV_SUB_TABLE[tmp[4] as usize];
    state[8] = INV_SUB_TABLE[tmp[8] as usize];
    state[12] = INV_SUB_TABLE[tmp[12] as usize];

    state[1] = INV_SUB_TABLE[tmp[13] as usize];
    state[5] = INV_SUB_TABLE[tmp[1] as usize];
    state[9] = INV_SUB_TABLE[tmp[5] as usize];
    state[13] = INV_SUB_TABLE[tmp[9] as usize];

    state[2] = INV_SUB_TABLE[tmp[10] as usize];
    state[6] = INV_SUB_TABLE[tmp[14] as usize];
    state[10] = INV_SUB_TABLE[tmp[2] as usize];
    state[14] = INV_SUB_TABLE[tmp[6] as usize];

    state[3] = INV_SUB_TABLE[tmp[7] as usize];
    state[7] = INV_SUB_TABLE[tmp[11] as usize];
    state[11] = INV_SUB_TABLE[tmp[15] as usize];
    state[15] = INV_SUB_TABLE[tmp[3] as usize];

    Ok(())
}

fn mix_columns(state: &mut [u8]) -> Result<(), Error> {
    if state.len() != 16 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "state must be 16 bytes in length",
        ));
    }
    let tmp = state.to_vec();

    for i in 0..(state.len() / 4) {
        state[(4 * i)] = MUL_2[tmp[(4 * i)] as usize]
            ^ MUL_3[tmp[(4 * i) + 1] as usize]
            ^ tmp[(4 * i) + 2]
            ^ tmp[(4 * i) + 3];
        state[(4 * i) + 1] = tmp[(4 * i)]
            ^ MUL_2[tmp[(4 * i) + 1] as usize]
            ^ MUL_3[tmp[(4 * i) + 2] as usize]
            ^ tmp[(4 * i) + 3];
        state[(4 * i) + 2] = tmp[(4 * i)]
            ^ tmp[(4 * i) + 1]
            ^ MUL_2[tmp[(4 * i) + 2] as usize]
            ^ MUL_3[tmp[(4 * i) + 3] as usize];
        state[(4 * i) + 3] = MUL_3[tmp[(4 * i)] as usize]
            ^ tmp[(4 * i) + 1]
            ^ tmp[(4 * i) + 2]
            ^ MUL_2[tmp[(4 * i) + 3] as usize];
    }

    Ok(())
}

fn inverse_mix_columns(state: &mut [u8]) -> Result<(), Error> {
    if state.len() != 16 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "state must be 16 bytes in length",
        ));
    }
    let tmp = state.to_vec();

    for i in 0..(state.len() / 4) {
        state[(4 * i)] = MUL_14[tmp[(4 * i)] as usize]
            ^ MUL_11[tmp[(4 * i) + 1] as usize]
            ^ MUL_13[tmp[(4 * i) + 2] as usize]
            ^ MUL_9[tmp[(4 * i) + 3] as usize];
        state[(4 * i) + 1] = MUL_9[tmp[(4 * i)] as usize]
            ^ MUL_14[tmp[(4 * i) + 1] as usize]
            ^ MUL_11[tmp[(4 * i) + 2] as usize]
            ^ MUL_13[tmp[(4 * i) + 3] as usize];
        state[(4 * i) + 2] = MUL_13[tmp[(4 * i)] as usize]
            ^ MUL_9[tmp[(4 * i) + 1] as usize]
            ^ MUL_14[tmp[(4 * i) + 2] as usize]
            ^ MUL_11[tmp[(4 * i) + 3] as usize];
        state[(4 * i) + 3] = MUL_11[tmp[(4 * i)] as usize]
            ^ MUL_13[tmp[(4 * i) + 1] as usize]
            ^ MUL_9[tmp[(4 * i) + 2] as usize]
            ^ MUL_14[tmp[(4 * i) + 3] as usize];
    }

    Ok(())
}

const SUB_TABLE: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

const INV_SUB_TABLE: [u8; 256] = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
];

const MUL_2: [u8; 256] = [
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
    0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
    0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
    0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
    0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
    0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
    0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
    0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
    0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
    0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
    0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
    0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
    0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
    0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
    0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
    0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5,
];

const MUL_3: [u8; 256] = [
    0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11,
    0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21,
    0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
    0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41,
    0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1,
    0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
    0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1,
    0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99, 0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81,
    0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
    0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba,
    0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea,
    0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
    0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c, 0x49, 0x4a,
    0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a,
    0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
    0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a,
];

const MUL_9: [u8; 256] = [
    0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53, 0x6c, 0x65, 0x7e, 0x77,
    0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf, 0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7,
    0x3b, 0x32, 0x29, 0x20, 0x1f, 0x16, 0x0d, 0x04, 0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c,
    0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94, 0xe3, 0xea, 0xf1, 0xf8, 0xc7, 0xce, 0xd5, 0xdc,
    0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49, 0x3e, 0x37, 0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01,
    0xe6, 0xef, 0xf4, 0xfd, 0xc2, 0xcb, 0xd0, 0xd9, 0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91,
    0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72, 0x05, 0x0c, 0x17, 0x1e, 0x21, 0x28, 0x33, 0x3a,
    0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2, 0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa,
    0xec, 0xe5, 0xfe, 0xf7, 0xc8, 0xc1, 0xda, 0xd3, 0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b,
    0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43, 0x34, 0x3d, 0x26, 0x2f, 0x10, 0x19, 0x02, 0x0b,
    0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8, 0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0,
    0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a, 0x71, 0x78, 0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30,
    0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5, 0xd2, 0xdb, 0xc0, 0xc9, 0xf6, 0xff, 0xe4, 0xed,
    0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35, 0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d,
    0xa1, 0xa8, 0xb3, 0xba, 0x85, 0x8c, 0x97, 0x9e, 0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6,
    0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e, 0x79, 0x70, 0x6b, 0x62, 0x5d, 0x54, 0x4f, 0x46,
];

const MUL_11: [u8; 256] = [
    0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31, 0x58, 0x53, 0x4e, 0x45, 0x74, 0x7f, 0x62, 0x69,
    0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81, 0xe8, 0xe3, 0xfe, 0xf5, 0xc4, 0xcf, 0xd2, 0xd9,
    0x7b, 0x70, 0x6d, 0x66, 0x57, 0x5c, 0x41, 0x4a, 0x23, 0x28, 0x35, 0x3e, 0x0f, 0x04, 0x19, 0x12,
    0xcb, 0xc0, 0xdd, 0xd6, 0xe7, 0xec, 0xf1, 0xfa, 0x93, 0x98, 0x85, 0x8e, 0xbf, 0xb4, 0xa9, 0xa2,
    0xf6, 0xfd, 0xe0, 0xeb, 0xda, 0xd1, 0xcc, 0xc7, 0xae, 0xa5, 0xb8, 0xb3, 0x82, 0x89, 0x94, 0x9f,
    0x46, 0x4d, 0x50, 0x5b, 0x6a, 0x61, 0x7c, 0x77, 0x1e, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2f,
    0x8d, 0x86, 0x9b, 0x90, 0xa1, 0xaa, 0xb7, 0xbc, 0xd5, 0xde, 0xc3, 0xc8, 0xf9, 0xf2, 0xef, 0xe4,
    0x3d, 0x36, 0x2b, 0x20, 0x11, 0x1a, 0x07, 0x0c, 0x65, 0x6e, 0x73, 0x78, 0x49, 0x42, 0x5f, 0x54,
    0xf7, 0xfc, 0xe1, 0xea, 0xdb, 0xd0, 0xcd, 0xc6, 0xaf, 0xa4, 0xb9, 0xb2, 0x83, 0x88, 0x95, 0x9e,
    0x47, 0x4c, 0x51, 0x5a, 0x6b, 0x60, 0x7d, 0x76, 0x1f, 0x14, 0x09, 0x02, 0x33, 0x38, 0x25, 0x2e,
    0x8c, 0x87, 0x9a, 0x91, 0xa0, 0xab, 0xb6, 0xbd, 0xd4, 0xdf, 0xc2, 0xc9, 0xf8, 0xf3, 0xee, 0xe5,
    0x3c, 0x37, 0x2a, 0x21, 0x10, 0x1b, 0x06, 0x0d, 0x64, 0x6f, 0x72, 0x79, 0x48, 0x43, 0x5e, 0x55,
    0x01, 0x0a, 0x17, 0x1c, 0x2d, 0x26, 0x3b, 0x30, 0x59, 0x52, 0x4f, 0x44, 0x75, 0x7e, 0x63, 0x68,
    0xb1, 0xba, 0xa7, 0xac, 0x9d, 0x96, 0x8b, 0x80, 0xe9, 0xe2, 0xff, 0xf4, 0xc5, 0xce, 0xd3, 0xd8,
    0x7a, 0x71, 0x6c, 0x67, 0x56, 0x5d, 0x40, 0x4b, 0x22, 0x29, 0x34, 0x3f, 0x0e, 0x05, 0x18, 0x13,
    0xca, 0xc1, 0xdc, 0xd7, 0xe6, 0xed, 0xf0, 0xfb, 0x92, 0x99, 0x84, 0x8f, 0xbe, 0xb5, 0xa8, 0xa3,
];

const MUL_13: [u8; 256] = [
    0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23, 0x68, 0x65, 0x72, 0x7f, 0x5c, 0x51, 0x46, 0x4b,
    0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3, 0xb8, 0xb5, 0xa2, 0xaf, 0x8c, 0x81, 0x96, 0x9b,
    0xbb, 0xb6, 0xa1, 0xac, 0x8f, 0x82, 0x95, 0x98, 0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0,
    0x6b, 0x66, 0x71, 0x7c, 0x5f, 0x52, 0x45, 0x48, 0x03, 0x0e, 0x19, 0x14, 0x37, 0x3a, 0x2d, 0x20,
    0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e, 0x05, 0x08, 0x1f, 0x12, 0x31, 0x3c, 0x2b, 0x26,
    0xbd, 0xb0, 0xa7, 0xaa, 0x89, 0x84, 0x93, 0x9e, 0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb, 0xf6,
    0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5, 0xbe, 0xb3, 0xa4, 0xa9, 0x8a, 0x87, 0x90, 0x9d,
    0x06, 0x0b, 0x1c, 0x11, 0x32, 0x3f, 0x28, 0x25, 0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d,
    0xda, 0xd7, 0xc0, 0xcd, 0xee, 0xe3, 0xf4, 0xf9, 0xb2, 0xbf, 0xa8, 0xa5, 0x86, 0x8b, 0x9c, 0x91,
    0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33, 0x24, 0x29, 0x62, 0x6f, 0x78, 0x75, 0x56, 0x5b, 0x4c, 0x41,
    0x61, 0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42, 0x09, 0x04, 0x13, 0x1e, 0x3d, 0x30, 0x27, 0x2a,
    0xb1, 0xbc, 0xab, 0xa6, 0x85, 0x88, 0x9f, 0x92, 0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 0xf7, 0xfa,
    0xb7, 0xba, 0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94, 0xdf, 0xd2, 0xc5, 0xc8, 0xeb, 0xe6, 0xf1, 0xfc,
    0x67, 0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44, 0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c,
    0x0c, 0x01, 0x16, 0x1b, 0x38, 0x35, 0x22, 0x2f, 0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d, 0x4a, 0x47,
    0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 0xff, 0xb4, 0xb9, 0xae, 0xa3, 0x80, 0x8d, 0x9a, 0x97,
];

const MUL_14: [u8; 256] = [
    0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a, 0x70, 0x7e, 0x6c, 0x62, 0x48, 0x46, 0x54, 0x5a,
    0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca, 0x90, 0x9e, 0x8c, 0x82, 0xa8, 0xa6, 0xb4, 0xba,
    0xdb, 0xd5, 0xc7, 0xc9, 0xe3, 0xed, 0xff, 0xf1, 0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81,
    0x3b, 0x35, 0x27, 0x29, 0x03, 0x0d, 0x1f, 0x11, 0x4b, 0x45, 0x57, 0x59, 0x73, 0x7d, 0x6f, 0x61,
    0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87, 0xdd, 0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7,
    0x4d, 0x43, 0x51, 0x5f, 0x75, 0x7b, 0x69, 0x67, 0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19, 0x17,
    0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c, 0x06, 0x08, 0x1a, 0x14, 0x3e, 0x30, 0x22, 0x2c,
    0x96, 0x98, 0x8a, 0x84, 0xae, 0xa0, 0xb2, 0xbc, 0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc,
    0x41, 0x4f, 0x5d, 0x53, 0x79, 0x77, 0x65, 0x6b, 0x31, 0x3f, 0x2d, 0x23, 0x09, 0x07, 0x15, 0x1b,
    0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97, 0x85, 0x8b, 0xd1, 0xdf, 0xcd, 0xc3, 0xe9, 0xe7, 0xf5, 0xfb,
    0x9a, 0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0, 0xea, 0xe4, 0xf6, 0xf8, 0xd2, 0xdc, 0xce, 0xc0,
    0x7a, 0x74, 0x66, 0x68, 0x42, 0x4c, 0x5e, 0x50, 0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20,
    0xec, 0xe2, 0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6, 0x9c, 0x92, 0x80, 0x8e, 0xa4, 0xaa, 0xb8, 0xb6,
    0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26, 0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56,
    0x37, 0x39, 0x2b, 0x25, 0x0f, 0x01, 0x13, 0x1d, 0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71, 0x63, 0x6d,
    0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd, 0xa7, 0xa9, 0xbb, 0xb5, 0x9f, 0x91, 0x83, 0x8d,
];

// 2, 4, 8, 16, 32, etc for the round number idx - 1
const RCON: [u8; 11] = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

/// looks for space, lowercase, uppercase, newline/tab/etc, numbers, then rest
/// could be sped up more using common::common_letter_freqs, but this already
/// reduces number of checks by ~5-6x compared to 0u8..0xff
const SMART_ASCII: [u8; 255] = [
    32, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
    116, 117, 118, 119, 120, 121, 122, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 39, 9, 10, 11, 12, 13, 40, 41, 42, 43, 44, 45, 46,
    47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 33, 34, 35, 36, 37, 38,
    91, 92, 93, 94, 95, 96, 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136,
    137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
    156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174,
    175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193,
    194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212,
    213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231,
    232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250,
    251, 252, 253, 254, 255,
];

pub fn pkcs7_pad(message: &mut Vec<u8>, block_byte_length: usize) -> Result<(), Error> {
    let final_block_len = message.len() % block_byte_length;

    let mut num_padded_bytes = block_byte_length - final_block_len;
    if num_padded_bytes == 0 {
        num_padded_bytes = block_byte_length;
    }
    if num_padded_bytes > 0xff {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "pad_message_pkcs7(): Cannot pad with {} bytes",
                num_padded_bytes
            ),
        ));
    }

    // pad with bytes of the length of padding
    let padding = vec![num_padded_bytes as u8; num_padded_bytes];

    message.extend_from_slice(&padding);

    Ok(())
}

#[allow(dead_code)]
fn print_state(state: &[u8]) {
    println!();
    for i in 0..4 {
        println!(
            "|{:2x} {:2x} {:2x} {:2x}|",
            state[i],
            state[i + 4],
            state[i + 8],
            state[i + 12]
        );
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7_pads_entirely_new_block() {
        let block_size = 16;
        let mut block = vec![0u8; block_size];
        let copy = block.clone();
        pkcs7_pad(&mut block, block_size).unwrap();

        assert_eq!(copy.len() + block_size, block.len());
    }
}
