use crate::{Error, InnerError, Kind, Pubkey};

#[derive(Debug, Clone)]
pub struct Addr {
    pub kind: Kind,
    pub author: Pubkey,
    pub d: Vec<u8>,
}

impl Addr {
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
