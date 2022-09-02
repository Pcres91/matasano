use crate::errors::{CryptoError, Result};

// TODO: change these to anyhow::context!() calls?
pub fn expect_eq<T>(expected: T, actual: T, message: &str) -> Result<()>
where
    T: std::cmp::Eq,
    T: std::fmt::Debug,
{
    match expected == actual {
        true => Ok(()),
        false => Err(CryptoError::ExpectEqualFailure {
            expected: format!("{expected:?}"),
            actual: format!("{actual:?}"),
            message: message.to_string(),
        }),
    }
}

pub fn expect_true(expected: bool, message: &str) -> Result<()> {
    match expected {
        true => Ok(()),
        false => Err(CryptoError::ExpectTrueFailure {
            message: message.to_string(),
        }),
    }
}

pub fn expect_false(expected: bool, message: &str) -> Result<()> {
    match expected {
        false => Ok(()),
        true => Err(CryptoError::ExpectFalseFailure {
            message: message.to_string(),
        }),
    }
}
