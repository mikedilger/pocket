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
    Deleted,
    Duplicate,
    EndOfInput,
    General(String),
    Lmdb(crate::heed::Error),
    InvalidDelete,
    Io(std::io::Error),
    PocketTypes(pocket_types::Error),
    Replaced,
    Scraper,
    WrongEventKind,
}

impl std::fmt::Display for InnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InnerError::Deleted => write!(f, "Event was previously deleted"),
            InnerError::Duplicate => write!(f, "Duplicate event"),
            InnerError::EndOfInput => write!(f, "End of input"),
            InnerError::General(s) => write!(f, "{s}"),
            InnerError::Io(e) => write!(f, "I/O: {e}"),
            InnerError::Lmdb(e) => write!(f, "LMDB: {e}"),
            InnerError::InvalidDelete => write!(f, "Invalid delete event"),
            InnerError::PocketTypes(e) => write!(f, "types: {e}"),
            InnerError::Replaced => write!(f, "Event was previously replaced"),
            InnerError::Scraper => write!(f, "scraper"),
            InnerError::WrongEventKind => write!(f, "Wrong event kind"),
        }
    }
}

impl StdError for InnerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            InnerError::Io(e) => Some(e),
            InnerError::Lmdb(e) => Some(e),
            InnerError::PocketTypes(e) => Some(e),
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

impl From<pocket_types::Error> for Error {
    #[track_caller]
    fn from(err: pocket_types::Error) -> Self {
        Error {
            inner: InnerError::PocketTypes(err),
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

impl From<crate::heed::Error> for Error {
    #[track_caller]
    fn from(err: crate::heed::Error) -> Self {
        Error {
            inner: InnerError::Lmdb(err),
            location: std::panic::Location::caller(),
        }
    }
}
