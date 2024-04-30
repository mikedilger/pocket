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
    Io(std::io::Error),
    PocketDb(pocket_db::Error),
    PocketTypes(pocket_types::Error),
    Secp256k1(secp256k1::Error),
}

impl std::fmt::Display for InnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InnerError::Io(e) => write!(f, "I/O: {e}"),
            InnerError::PocketDb(e) => write!(f, "db: {e}"),
            InnerError::PocketTypes(e) => write!(f, "types: {e}"),
            InnerError::Secp256k1(e) => write!(f, "secp256k1: {e}"),
        }
    }
}

impl StdError for InnerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            InnerError::Io(e) => Some(e),
            InnerError::PocketDb(e) => Some(e),
            InnerError::PocketTypes(e) => Some(e),
            InnerError::Secp256k1(e) => Some(e),
            // _ => None,
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

impl From<pocket_types::Error> for Error {
    #[track_caller]
    fn from(err: pocket_types::Error) -> Self {
        Error {
            inner: InnerError::PocketTypes(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<pocket_db::Error> for Error {
    #[track_caller]
    fn from(err: pocket_db::Error) -> Self {
        Error {
            inner: InnerError::PocketDb(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<std::io::Error> for Error {
    #[track_caller]
    fn from(err: std::io::Error) -> Self {
        Error {
            inner: InnerError::Io(err),
            location: std::panic::Location::caller(),
        }
    }
}

impl From<secp256k1::Error> for Error {
    #[track_caller]
    fn from(err: secp256k1::Error) -> Self {
        Error {
            inner: InnerError::Secp256k1(err),
            location: std::panic::Location::caller(),
        }
    }
}
