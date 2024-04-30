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
    BadHexInput,
    BufferTooSmall(usize),
    EndOfInput,
    General(String),
    TryFromSlice(std::array::TryFromSliceError),
}

impl std::fmt::Display for InnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InnerError::BadHexInput => write!(f, "Bad hex input"),
            InnerError::BufferTooSmall(u) => {
                write!(f, "Output buffer too small, we require >={} bytes", u)
            }
            InnerError::EndOfInput => write!(f, "End of input"),
            InnerError::General(s) => write!(f, "{s}"),
            InnerError::TryFromSlice(e) => write!(f, "slice error: {e}"),
        }
    }
}

impl StdError for InnerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
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
