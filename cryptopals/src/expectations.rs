use std::error;
use std::fmt;

pub type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

#[derive(Debug, Clone)]
pub struct ExpectationFailure;

impl fmt::Display for ExpectationFailure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Expectation was not met")
    }
}

impl error::Error for ExpectationFailure {}

pub fn expect_eq<T>(expected: T, actual: T) -> Result<()>
where
    T: std::cmp::Eq,
{
    match expected == actual {
        true => Ok(()),
        false => Err(ExpectationFailure.into()),
    }
}

pub fn expect_true(expected: bool) -> Result<()> {
    match expected {
        true => Ok(()),
        false => Err(ExpectationFailure.into()),
    }
}

pub fn expect_false(expected: bool) -> Result<()> {
    expect_true(!expected)
}