use hex::FromHexError;
use std::{string::FromUtf8Error, time::SystemTimeError};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, CryptoError>;
pub type AesResult<T> = std::result::Result<T, AesError>;
pub type ExpectationResult<T> = std::result::Result<T, ExpectationFailure>;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AesError encountered.")]
    AesError(#[from] AesError),
    #[error("ExpectationFailure encountered.")]
    ExpectationFailure(#[from] ExpectationFailure),
    #[error("UserStorageError encountered.")]
    UserStorageError(#[from] UserStorageError),
    #[error("SystemTimeError encountered.")]
    SystemTimeError(#[from] SystemTimeError),
    #[error("HexError encountered.")]
    HexError(#[from] FromHexError),
    #[error("IoError encountered.")]
    IoError(#[from] std::io::Error),
    #[error("Utf8Error encountered.")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("Invalid Data: {0}")]
    InvalidDataError(String),
    #[error("MS RNG generator must be seeded before getting a number")]
    MersenneTwisterNotSeededError,
}

#[derive(Debug, Error, PartialEq)]
pub enum ExpectationFailure {
    #[error("Expected\n{expected}\nactual\n{actual}\n{message}")]
    ExpectEqualFailure {
        expected: String,
        actual: String,
        message: String,
    },
    #[error("Expected true statement, was false. {message}")]
    ExpectTrueFailure { message: String },
    #[error("Expected false statement, was true. {message}")]
    ExpectFalseFailure { message: String },
}

#[derive(Debug, Error, PartialEq)]
pub enum AesError {
    #[error("the key for ECB 128 encryption must be aes::BLOCK_SIZE bytes in length")]
    KeyLengthError,
    #[error("Cipher Text length must be divisible by aes::BLOCK_SIZE, got {0}")]
    CipherTextLengthError(String),
    #[error("The data is not PKCS7-padded")]
    NotPKCS7PaddedError,
    #[error("Maximum block length for PKCS7 padding exceeded. Maximum is 0xff bytes")]
    PKCS7PaddingTooLongError,
    #[error("The Key length once expanded must be 176 bytes")]
    ExpandedKeyLengthError,
    #[error("ECB 128 Error: {0}")]
    Ecb128Error(String),
    #[error("CBC 128 Error: {0}")]
    Cbc128Error(String),
    #[error("Not Found: {0}")]
    NotFound(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("{0}")]
    InvalidLength(String),
    #[error("Invalid PKCS7 padding. Last block: {0:?}")]
    InvalidPkcs7Padding(Vec<u8>),
    #[error("FromUtf8Error encountered.")]
    FromUtf8Error(#[from] FromUtf8Error),
    #[error("ExpectationFailure encountered.")]
    ExpectationFailure(#[from] ExpectationFailure),
}

#[derive(Debug, Error, PartialEq)]
pub enum UserStorageError {
    #[error("Invalid email format")]
    InvalidEmailFormat,
}
