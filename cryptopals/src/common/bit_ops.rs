use crate::common::{errors::Result, expectations::*};
use bitstream_io::{BigEndian, BitRead, BitReader, BitWrite, BitWriter};
use rayon::prelude::*;
use std::io::Cursor;

///xor exactly 16 bytes on the stack
pub fn xor_16_bytes(left: &[u8], right: &[u8]) -> [u8; 16] {
    let mut res = [0u8; 16];
    left.into_iter()
        .zip(right.into_iter())
        .enumerate()
        .for_each(|(idx, (l, r))| res[idx] = l ^ r);
    res
}

/// use xor_bytes in a map fn with zipped slices of the same size
pub fn xor_bytes_tuple_no_fail(val: (&[u8], &[u8])) -> Vec<u8> {
    xor_bytes(val.0, val.1).unwrap()
}

pub fn xor_bytes(left: &[u8], right: &[u8]) -> Result<Vec<u8>> {
    expect_eq(left.len(), right.len(), "Lengths of the two slices to xor")?;

    Ok(left
        .into_par_iter()
        .zip(right)
        .map(|(l, r)| l ^ r)
        .collect())
}

// performs a per-bit operation using bitstreams.Bit of overkill
#[allow(dead_code)]
pub fn xor_bits(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut l_cur = Cursor::new(&left);
    let mut l_reader = BitReader::endian(&mut l_cur, BigEndian);

    let mut r_cur = Cursor::new(&right);
    let mut r_reader = BitReader::endian(&mut r_cur, BigEndian);

    let mut writer = BitWriter::endian(Vec::new(), BigEndian);

    let num_bits = left.len() * 8;

    for _i in 0..num_bits {
        let res: bool = l_reader.read_bit().unwrap() ^ r_reader.read_bit().unwrap();
        writer.write_bit(res).unwrap();
    }

    writer.into_writer()
}

/// XOR each character in a buffer with a single character key.
pub fn xor_with_single_byte(cipher: &[u8], key: u8) -> Vec<u8> {
    cipher.par_iter().map(|byte| byte ^ key).collect()
}
