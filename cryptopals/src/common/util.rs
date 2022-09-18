use crate::common::{
    expectations::*,
    {bit_ops::xor_with_single_byte, errors::Result},
};
use bitstream_io::{BigEndian, BitRead, BitReader};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;
extern crate hex;
extern crate num_traits;

pub fn until_err<T, E>(
    err: &mut &mut std::result::Result<(), E>,
    item: std::result::Result<T, E>,
) -> Option<T> {
    match item {
        Ok(item) => Some(item),
        Err(e) => {
            **err = Err(e);
            None
        }
    }
}

pub struct Wrap(pub Vec<u8>);

impl fmt::Display for Wrap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &byte in &self.0 {
            write!(f, "{}", byte as char)?;
        }
        Ok(())
    }
}

/// for data that might not be 100% convertable to utf8,
/// display a hash where the data failed to convert
pub fn try_display(text: &[u8]) -> String {
    text.iter()
        .map(|c| match String::from_utf8([*c].to_vec()) {
            Ok(c) => c,
            Err(_) => String::from('#'),
        })
        .collect()
}

/// converts a string of hex into bytes
/// ie, "0123afbe" -> vec![0x01, 0x23, 0xaf, 0xbe]
pub fn hex_string_to_vec_u8(bytes: &[u8]) -> Result<Vec<u8>> {
    match hex::decode(bytes) {
        Ok(res) => Ok(res),
        Err(hex_error) => Err(hex_error.into()),
    }
}

#[allow(dead_code)]
fn ascii_to_uppercase(chr: u8) -> u8 {
    if chr >= 97 && chr <= 122 {
        return chr - (97 - 65);
    };

    chr
}

/// list of the most frequent ASCII characters
/// without characters or punctuation. For long texts
/// this should be sufficient.
/// Shamelessly stolen from
/// http://www.fitaly.com/board/domper3/posts/136.html
pub fn score_text(msg: &[u8]) -> i32 {
    let mut freq_count = 0;
    for &byte in msg {
        if [101, 32, 116, 111, 97, 110, 105, 115, 114, 108].contains(&byte) {
            freq_count += 8;
        } else if [104, 100, 99, 117, 109, 103, 112, 46, 45, 102].contains(&byte) {
            freq_count += 4;
        } else if [119, 121, 98, 118, 44, 107, 149, 48, 49, 58].contains(&byte) {
            freq_count += 2;
        } else if [83, 67, 77, 84, 73, 68, 65, 69, 80, 87].contains(&byte) {
            freq_count += 1;
        } else if [43, 35, 37, 93, 91, 90, 64, 33, 9, 125].contains(&byte) {
            freq_count -= 4;
        } else if [92, 183, 96, 124, 126, 237].contains(&byte) {
            freq_count -= 8;
        } else if byte <= 12 {
            freq_count -= 20;
        }
    }

    freq_count
}

/// return the character with the highest character "score" when XOR'd with the buffer
pub fn find_best_character_key(cipher: &[u8]) -> u8 {
    find_best_character_key_and_score(cipher).key
}

pub struct ScoredText {
    pub key: u8,
    pub score: i32,
    pub plaintext: Vec<u8>,
}

impl From<(u8, i32, Vec<u8>)> for ScoredText {
    fn from(f: (u8, i32, Vec<u8>)) -> Self {
        ScoredText {
            key: f.0,
            score: f.1,
            plaintext: f.2,
        }
    }
}

/// same as find_best_character_key, but also return the score.
/// Returned as (key, score)
/// TODO use enumerate to store key value
pub fn find_best_character_key_and_score(cipher: &[u8]) -> ScoredText {
    (0..0xffu8)
        .into_par_iter()
        .map(|key| (key, xor_with_single_byte(&cipher, key)))
        .map(|(key, decoded_message)| (key, score_text(&decoded_message), decoded_message))
        .max_by(|left, right| left.1.cmp(&right.1))
        .unwrap()
        .into()
}

/// cycle through the key, XOR'ing the text with each subsequent character of the key
pub fn repeated_xor(text: &[u8], key: &[u8]) -> Vec<u8> {
    fn xor_with_key(chunk: &[u8], key: &[u8]) -> Vec<u8> {
        chunk
            .par_iter()
            .zip(key.par_iter())
            .map(|(c, key_char)| c ^ key_char)
            .collect()
    }

    text.par_chunks(key.len())
        .map(|chunk| xor_with_key(chunk, key))
        .flatten()
        .collect()
}

/// Computes the distance between two strings on a per-bit (not byte) basis
pub fn hamming_distance(string1: &[u8], string2: &[u8]) -> Result<usize> {
    expect_eq(
        string1.len(),
        string2.len(),
        "Hamming Distance can only be calculated between two strings of equal length",
    )?;

    let mut cur1 = Cursor::new(&string1);
    let mut read1 = BitReader::endian(&mut cur1, BigEndian);
    let mut cur2 = Cursor::new(&string2);
    let mut read2 = BitReader::endian(&mut cur2, BigEndian);

    let mut distance = 0;
    for _ in 0..(string1.len() * 8/* per bit, not byte */) {
        let res = read1.read_bit()? ^ read2.read_bit()?;
        if res {
            distance += 1
        };
    }
    Ok(distance)
}

/// get the average hamming distance between blocks of key_length size, for num_blocks
pub fn get_average_distance(data: &[u8], key_size: usize, num_blocks: usize) -> Result<f32> {
    expect_true(num_blocks * key_size <= data.len(), format!("Not enough data for the num blocks requested. Data length: {}, num_blocks: {}, key_length: {}",
        data.len(), num_blocks, key_size).as_str())?;

    let sum_distances = (0..(num_blocks - 1) * key_size)
        .step_by(key_size)
        .par_bridge()
        .fold(
            || 0usize,
            |acc, idx| {
                acc + hamming_distance(
                    &data[idx..(idx + key_size)],
                    &data[(idx + key_size)..(idx + 2 * key_size)],
                )
                .unwrap()
            },
        )
        .sum::<usize>();

    let normalised_distance_sum = sum_distances as f32 / key_size as f32;
    let average_distance = normalised_distance_sum / num_blocks as f32;
    Ok(average_distance)
}

/// Find the key size with the lowest average hamming distance between each block. Averaged over num_blocks blocks
pub fn find_key_size(
    data: &[u8],
    key_size_range: (usize, usize),
    num_blocks: usize,
) -> Result<usize> {
    Ok((key_size_range.0..key_size_range.1)
        .into_par_iter()
        .map(|key_size| {
            (
                key_size,
                get_average_distance(&data, key_size, num_blocks).unwrap(),
            )
        })
        .min_by(|left, right| left.1.partial_cmp(&right.1).unwrap())
        .unwrap()
        .0)
}

/// Think numpy - getting a single byte from a given dimension
///
/// Examples:
///
/// ```
/// let v = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];\n
/// let r = get_slice(&v, 0, 2);
/// expect_eq(vec![0, 2, 4, 6, 8, 10, 12], r, "sliced correctly").unwrap();
/// let r = get_slice(&v, 1, 3);
/// expect_eq(vec![1, 4, 7, 10], r, "sliced correctly").unwrap();
/// let r = get_slice(&v, 2, 4);
/// expect_eq(vec![2, 6, 10], r, "sliced correctly").unwrap();
/// ```
pub fn get_slice(data: &[u8], start_idx: usize, step_by: usize) -> Vec<u8> {
    data[start_idx..]
        .par_iter()
        .step_by(step_by)
        .map(|i| *i)
        .collect()
}

/// using get_slice, return per-idx the bytes that have all been encrypted with that
/// key's byte
pub fn get_data_per_byte_of_key(data: &[u8], key_size: usize) -> Vec<Vec<u8>> {
    (0..key_size)
        .into_par_iter()
        .map(|key| get_slice(data, key, key_size))
        .collect()
}

#[allow(dead_code)]
pub fn slice_by_byte_with_idx(data: &[u8], key_size: usize) -> BTreeMap<usize, Vec<u8>> {
    let mut sliced_data = BTreeMap::new();

    for key_idx in 0..key_size {
        sliced_data.insert(key_idx, get_slice(data, key_idx, key_size));
    }

    sliced_data
}

pub fn prefix_with_rnd_bytes(range: (usize, usize), text: &[u8]) -> Vec<u8> {
    extern crate rand;
    use rand::prelude::*;

    let mut rng = rand::thread_rng();

    let num_random_bytes = rng.gen_range(range.0..range.1);

    // println!("rnd bytes: {}", num_random_bytes);

    let mut res = vec![0u8; num_random_bytes];
    rng.fill_bytes(&mut res);

    res.extend_from_slice(text);

    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hamming_distance() {
        let string1 = "this is a test";
        let string2 = "wokka wokka!!!";

        let res = hamming_distance(&string1.as_bytes(), &string2.as_bytes()).unwrap();

        assert_eq!(37, res);
    }
}

/// looks for space, lowercase, uppercase, newline/tab/etc, numbers, then rest
/// could be sped up more using common::common_letter_freqs, but this already
/// reduces number of checks by ~5-6x compared to 0u8..0xff
pub const SMART_ASCII: [u8; 255] = [
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

#[cfg(test)]
mod common_util_tests {
    use crate::common::expectations::expect_eq;

    use super::{get_slice, hex_string_to_vec_u8};

    #[test]
    fn test_hex_string_to_u8() {
        let expected = b"YELLOW SUBMARINE";

        let res = hex_string_to_vec_u8(b"59454c4c4f57205355424d4152494e45").unwrap();

        expect_eq(expected.to_vec(), res, "hex_string_to_u8").unwrap();
    }

    #[test]
    fn test_get_slice_output() {
        let v = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let r = get_slice(&v, 0, 2);
        expect_eq(vec![0, 2, 4, 6, 8, 10, 12], r, "sliced correctly").unwrap();
        let r = get_slice(&v, 1, 3);
        expect_eq(vec![1, 4, 7, 10], r, "sliced correctly").unwrap();
        let r = get_slice(&v, 2, 4);
        expect_eq(vec![2, 6, 10], r, "sliced correctly").unwrap();
    }
}
