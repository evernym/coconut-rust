use failure::{Backtrace, Context, Error, Fail};
use ps_sig::errors::PSError;
use std::fmt;

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum CoconutErrorKind {
    #[fail(
        display = "Verkey valid for {} messages but given {} messages",
        expected, given
    )]
    UnsupportedNoOfMessages { expected: usize, given: usize },

    #[fail(
        display = "Same no of bases and exponents required. {} bases and {} exponents",
        bases, exponents
    )]
    UnequalNoOfBasesExponents { bases: usize, exponents: usize },

    #[fail(display = "Error from PS sig crate {:?}", msg)]
    PSError { msg: String },

    #[fail(display = "Error with message {:?}", msg)]
    GeneralError { msg: String },
}

#[derive(Debug)]
pub struct CoconutError {
    inner: Context<CoconutErrorKind>,
}

impl CoconutError {
    pub fn kind(&self) -> CoconutErrorKind {
        let c = self.inner.get_context().clone();
        c
    }

    pub fn from_kind(kind: CoconutErrorKind) -> Self {
        Self {
            inner: Context::new("").context(kind),
        }
    }
}

impl From<CoconutErrorKind> for CoconutError {
    fn from(kind: CoconutErrorKind) -> Self {
        Self {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<CoconutErrorKind>> for CoconutError {
    fn from(inner: Context<CoconutErrorKind>) -> Self {
        Self { inner }
    }
}

impl Fail for CoconutError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for CoconutError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl From<PSError> for CoconutError {
    fn from(err: PSError) -> Self {
        let message = format!(
            "PSError: {}",
            Fail::iter_causes(&err)
                .map(|e| e.to_string())
                .collect::<String>()
        );

        CoconutErrorKind::PSError { msg: message }.into()
    }
}
