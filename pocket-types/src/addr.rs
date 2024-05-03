use crate::{Error, InnerError, Kind, Pubkey};

/// A nostr addr, e.g. used in an 'a' tag with 'kind:author:d' format
#[derive(Debug, Clone)]
pub struct Addr {
    /// The kind of the replaceable event
    pub kind: Kind,

    /// The author of the replaceable event
    pub author: Pubkey,

    /// The indentifier
    pub d: Vec<u8>,
}

impl Addr {
    /// Try to create an Addr from bytes (that represent a string)
    pub fn try_from_bytes(input: &[u8]) -> Result<Addr, Error> {
        let mut iter = input.splitn(3, |b| *b == b':');
        if let Some(kind_bytes) = iter.next() {
            let kind_str = std::str::from_utf8(kind_bytes)?;
            let kind = Kind::try_from_string_bytes(kind_str)?;
            if let Some(author_bytes) = iter.next() {
                let author = Pubkey::read_hex(author_bytes)?;
                if let Some(d_bytes) = iter.next() {
                    return Ok(Addr {
                        kind,
                        author,
                        d: d_bytes.to_owned(),
                    });
                }
            }
        }
        Err(InnerError::InvalidAddr.into())
    }
}
