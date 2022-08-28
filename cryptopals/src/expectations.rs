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

#[macro_export]
macro_rules! expect_eq {
    ($expected:expr, $actual:expr, $message:literal) => {
        expect_eq_impl($expected, $actual, Some($message))
    };
    ($expected:expr, $actual:expr) => {
        expect_eq_impl($expected, $actual, None)
    };
}

#[macro_export]
macro_rules! expect_false {
    ($expected:expr, $message:literal) => {
        expect_false_impl($expected, Some($message))
    };
    ($expected:expr) => {
        expect_false_impl($expected, None)
    };
}

#[macro_export]
macro_rules! expect_true {
    ($expected:expr, $message:literal) => {
        expect_true_impl($expected, Some($message))
    };
    ($expected:expr) => {
        expect_true_impl($expected, None)
    };
    ($expected:expr, $message:expr) => {
        expect_true_impl($expected, Some($message))
    }
}

#[macro_export]
macro_rules! expect_ok {
    ($function:expr, $arg:expr) => {
        match $function($arg) {
            Ok(()) => Ok(()),
            Err(_) => Err(ExpectationFailure.into()),
        }
    };
}

pub fn expect_eq_impl<T>(expected: T, actual: T, message: Option<&str>) -> Result<()>
where
    T: std::cmp::Eq,
    T: std::fmt::Debug,
{
    match expected == actual {
        true => Ok(()),
        false => {
            match message {
                Some(m) => println!("Expected {expected:?}\nActual {actual:?}. {m}"),
                None => println!("Expected {expected:?}\nActual {actual:?}."),
            }
            Err(ExpectationFailure.into())
        }
    }
}

pub fn expect_true_impl(expected: bool, message: Option<&str>) -> Result<()> {
    match expected {
        true => Ok(()),
        false => {
            match message {
                Some(m) => println!("Invalid Expectation: {m}"),
                None => println!("Invalid Expectation"),
            }
            Err(ExpectationFailure.into())
        }
    }
}

pub fn expect_false_impl(expected: bool, message: Option<&str>) -> Result<()> {
    expect_true_impl(!expected, message)
}
