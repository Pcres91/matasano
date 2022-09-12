use itertools::Itertools;

use crate::{aes::util::Result, common::errors::AesError, common::expectations::expect_eq};

/// returns just the padding bytes for the plaintext
pub fn get_padding_for(plaintext: &[u8], block_byte_length: usize) -> Result<Vec<u8>> {
    let final_block_len = plaintext.len() % block_byte_length;

    let padding_len = if block_byte_length - final_block_len == 0 {
        block_byte_length
    } else {
        block_byte_length - final_block_len
    };

    if padding_len > 0xff {
        return Err(AesError::PKCS7PaddingTooLongError);
    }

    Ok(vec![padding_len as u8; padding_len])
}

/// returns the plaintext + pkcs7padding
pub fn pad(plaintext: &[u8], block_byte_length: usize) -> Result<Vec<u8>> {
    let final_block_len = plaintext.len() % block_byte_length;

    let mut blocks = plaintext.to_vec();

    let mut bytes_to_pad_length = block_byte_length - final_block_len;
    if bytes_to_pad_length == 0 {
        bytes_to_pad_length = block_byte_length;
    }
    if bytes_to_pad_length > 0xff {
        return Err(AesError::PKCS7PaddingTooLongError);
    }

    // pad with bytes of the length of padding
    let padding = vec![bytes_to_pad_length as u8; bytes_to_pad_length];

    blocks.extend_from_slice(&padding);
    Ok(blocks)
}

/// adds the pkcs7padding to the message
pub fn pad_inplace(message: &mut Vec<u8>, block_byte_length: usize) -> Result<()> {
    let final_block_len = message.len() % block_byte_length;

    let mut num_padded_bytes = block_byte_length - final_block_len;
    if num_padded_bytes == 0 {
        num_padded_bytes = block_byte_length;
    }
    if num_padded_bytes > 0xff {
        return Err(AesError::PKCS7PaddingTooLongError);
    }

    // pad with bytes of the length of padding
    let padding = vec![num_padded_bytes as u8; num_padded_bytes];

    message.extend_from_slice(&padding);

    Ok(())
}

pub fn is_padding_valid_for(data: &[u8], block_length: usize) -> Result<bool> {
    expect_eq(
        0,
        data.len() % block_length,
        "validate_pkcs7_padding: data must be divisible by block length",
    )?;

    // check valid padding
    let last_val = data[data.len() - 1];

    if last_val as usize > data.len() || last_val == 0 {
        return Ok(false);
    };

    Ok(data[data.len() - last_val as usize..]
        .into_iter()
        .all_equal())
}

pub fn validate_and_remove_padding(data: &[u8]) -> Result<Vec<u8>> {
    println!("validate {:?}", data);
    match is_padding_valid_for(&data, 16)? {
        true => (),
        false => {
            return Err(AesError::InvalidPkcs7Padding(
                data[data.len() - 16..].to_vec(),
            ))
        }
    }

    Ok(data[..data.len() - data[data.len() - 1] as usize].to_vec())
}

#[cfg(test)]
mod pkcs7_tests {
    use super::*;

    use crate::common::expectations::{expect_false, expect_true};

    #[test]
    fn test_pkcs7_pads_entirely_new_block() {
        let block_size = 16;
        let mut block = vec![0u8; block_size];
        let copy = block.clone();
        pad_inplace(&mut block, block_size).unwrap();

        assert_eq!(copy.len() + block_size, block.len());
    }

    #[test]
    fn test_pkcs_remove_padding() {
        let mut message = vec![0u8; 12];
        message.extend_from_slice(&[4u8; 4]);

        let res = validate_and_remove_padding(&message);

        match res {
            Ok(r) => assert_eq!(message.len() - 4, r.len()),
            Err(_) => assert_eq!(true, false),
        }
    }

    #[test]
    fn test_pkcs_remove_padding_failure() {
        let mut message = vec![0u8; 12];
        message.extend_from_slice(&[4u8; 2]);

        let original_length = message.len();

        match validate_and_remove_padding(&message) {
            Ok(_) => assert!(false),
            Err(_) => assert_eq!(original_length, message.len()),
        };
    }
    #[test]
    fn test_padding_validity_returned_when_encrypting_block() {
        let mut data = [vec![0u8; 14], vec![0x2u8; 2]].concat();
        expect_true(
            is_padding_valid_for(&data, 16).unwrap(),
            "Testing valid padding is validated",
        )
        .unwrap();

        data = [vec![1u8; 16], vec![0xfu8; 16]].concat();
        expect_true(
            is_padding_valid_for(&data, 16).unwrap(),
            "Testing valid full padding block",
        )
        .unwrap();

        data = [vec![1u8; 15], vec![0xffu8; 1]].concat();
        expect_false(
            is_padding_valid_for(&data, 16).unwrap(),
            "Testing 0xff final block on bad padding",
        )
        .unwrap();

        data = [vec![1u8; 14], vec![0x3u8; 2]].concat();
        expect_false(
            is_padding_valid_for(&data, 16).unwrap(),
            "Testing one too few values is invalid",
        )
        .unwrap();

        data = [vec![1u8; 12], vec![0x3u8; 4]].concat();
        expect_true(
            is_padding_valid_for(&data, 16).unwrap(),
            "Testing one too many values is valid",
        )
        .unwrap();

        data = [vec![1u8; 15], vec![0x0u8; 1]].concat();
        expect_false(
            is_padding_valid_for(&data, 16).unwrap(),
            "Testing last value is 0 returns invalid",
        )
        .unwrap();
    }
}
