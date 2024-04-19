use std::error::Error as StdError;
use std::panic::Location;

#[derive(Debug)]
pub struct Error {
    pub inner: InnerError,
    location: &'static Location<'static>,
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.inner)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}, {}", self.inner, self.location)
    }
}

/// Errors that can occur in the crate
#[derive(Debug)]
pub enum InnerError {
    BadEventId,
    BadHexInput,
    BufferTooSmall(usize),
    Crypto(secp256k1::Error),
    EndOfInput,
    General(String),
    InvalidAddr,
    JsonBad(&'static str, usize),
    JsonBadCharacter(char, usize, char),
    JsonBadEvent(&'static str, usize),
    JsonBadFilter(&'static str, usize),
    JsonBadStringChar(u32),
    JsonEscape,
    JsonEscapeSurrogate,
    ParseInt(std::num::ParseIntError),
    StdUtf8Error(std::str::Utf8Error),
    TryFromSlice(std::array::TryFromSliceError),
    Utf8Error,
}

impl std::fmt::Display for InnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InnerError::BadEventId => write!(f, "Bad event id, does not match hash"),
            InnerError::BadHexInput => write!(f, "Bad hex input"),
            InnerError::BufferTooSmall(u) => {
                write!(f, "Output buffer too small, we require >={} bytes", u)
            }
            InnerError::Crypto(e) => write!(f, "Crypto: {e}"),
            InnerError::EndOfInput => write!(f, "End of input"),
            InnerError::General(s) => write!(f, "{s}"),
            InnerError::InvalidAddr => write!(f, "Invalid naddr"),
            InnerError::JsonBad(err, pos) => write!(f, "JSON bad: {err} at position {pos}"),
            InnerError::JsonBadCharacter(c, pos, ec) => write!(
                f,
                "JSON bad character: {c} at position {pos}, {ec} was expected"
            ),
            InnerError::JsonBadEvent(err, pos) => {
                write!(f, "JSON bad event: {err} at position {pos}")
            }
            InnerError::JsonBadFilter(err, pos) => {
                write!(f, "JSON bad filter: {err} at position {pos}")
            }
            InnerError::JsonBadStringChar(ch) => {
                write!(f, "JSON string bad character: codepoint {ch}")
            }
            InnerError::JsonEscape => write!(f, "JSON string escape error"),
            InnerError::JsonEscapeSurrogate => write!(
                f,
                "JSON string escape surrogate (ancient style) is not supported"
            ),
            InnerError::ParseInt(e) => write!(f, "parse int error: {e}"),
            InnerError::StdUtf8Error(e) => write!(f, "UTF-8 error: {e}"),
            InnerError::TryFromSlice(e) => write!(f, "slice error: {e}"),
            InnerError::Utf8Error => write!(f, "UTF-8 error"),
        }
    }
}

impl StdError for InnerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            InnerError::Crypto(e) => Some(e),
            InnerError::TryFromSlice(e) => Some(e),
            _ => None,
        }
    }
}

// Note: we impl Into because our typical pattern is InnerError::Variant.into()
//       when we tried implementing From, the location was deep in rust code's
//       blanket into implementation, which wasn't the line number we wanted.
//
//       As for converting other error types, the try! macro uses From so it
//       is correct.
#[allow(clippy::from_over_into)]
impl Into<Error> for InnerError {
    #[track_caller]
    fn into(self) -> Error {
        Error {
            inner: self,
            location: std::panic::Location::caller(),
        }
    }
}

impl From<std::array::TryFromSliceError> for Error {
    #[track_caller]
    fn from(err: std::array::TryFromSliceError) -> Self {
        Error {
            inner: InnerError::TryFromSlice(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<secp256k1::Error> for Error {
    #[track_caller]
    fn from(err: secp256k1::Error) -> Self {
        Error {
            inner: InnerError::Crypto(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<std::num::ParseIntError> for Error {
    #[track_caller]
    fn from(err: std::num::ParseIntError) -> Self {
        Error {
            inner: InnerError::ParseInt(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<std::str::Utf8Error> for Error {
    #[track_caller]
    fn from(err: std::str::Utf8Error) -> Self {
        Error {
            inner: InnerError::StdUtf8Error(err),
            location: std::panic::Location::caller(),
        }
    }
}
