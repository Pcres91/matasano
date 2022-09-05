use hex::FromHexError;
use thiserror::Error;
use std::string::FromUtf8Error;

pub type Result<T> = std::result::Result<T, CryptoError>;
pub type AesResult<T> = std::result::Result<T, AesError>;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AesError encountered.")]
    AesError(#[from] AesError),
    #[error("UserStorageError encountered.")]
    UserStorageError(#[from] UserStorageError),
    #[error("HexError encountered.")]
    HexError(#[from] FromHexError),
    #[error("IoError encountered.")]
    IoError(#[from] std::io::Error),
    #[error("Utf8Error encountered.")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("Invalid Data: {0}")]
    InvalidDataError(String),
    #[error("Expected {expected}, got {actual}. {message}")]
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

#[derive(Debug, Error)]
pub enum AesError {
    #[error("the key for ECB 128 encryption must be 16 bytes in length")]
    KeyLengthError,
    #[error("Cipher Text length must be divisible by 16")]
    CipherTextLengthError,
    #[error("The data is not PKCS7-padded")]
    NotPKCS7PaddedError,
    #[error("Maximum block length for PKCS7 padding exceeded. Maximum is 0xff bytes")]
    PKCS7PaddingTooLongError,
    #[error("The Key length once expanded must be of correct size")]
    ExpandedKeyLengthError,
    #[error("ECB 128 Error: {0}")]
    Ecb128Error(String),
    #[error("Not Found: {0}")]
    NotFound(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Invalid length: {0}")]
    InvalidLength(String),
    #[error("FromUtf8Error encountered.")]
    FromUtf8Error(#[from] FromUtf8Error),
}

#[derive(Debug, Error)]
pub enum UserStorageError {
    #[error("Invalid email format")]
    InvalidEmailFormat,
}
