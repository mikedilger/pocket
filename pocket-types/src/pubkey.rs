use crate::error::Error;
use derive_more::{AsRef, Deref, From, Into};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, AsRef, Deref, From, Into)]
pub struct Pubkey([u8; 32]);

impl Pubkey {
    pub fn from_bytes(bytes: [u8; 32]) -> Pubkey {
        Pubkey(bytes)
    }

    /// Write to output buffer in lowercase hex format
    pub fn write_hex(&self, output: &mut [u8]) -> Result<(), Error> {
        write_hex!(self.0, output, 32)
    }

    /// Read from input buffer in lowercase hex format
    pub fn read_hex(input: &[u8]) -> Result<Pubkey, Error> {
        let mut out: [u8; 32] = [0; 32];
        read_hex!(input, &mut out, 32)?;
        Ok(Pubkey(out))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes: [u8; 64] = [0; 64];
        self.write_hex(&mut bytes).unwrap();
        let hex = unsafe { std::str::from_utf8_unchecked(&bytes) };
        write!(f, "{hex}")
    }
}

impl TryInto<Pubkey> for &[u8] {
    type Error = Error;

    fn try_into(self) -> Result<Pubkey, Self::Error> {
        let array: [u8; 32] = self.try_into()?;
        Ok(Pubkey(array))
    }
}

#[cfg(test)]
mod test {
    use super::Pubkey;

    #[test]
    fn test_pubkey_hex_functions() {
        let hex = b"1110ee4ff957fa9c55832eaccb4dc1c45bfc6304e1e4e9fa478f53df4b20062d";
        let pubkey = Pubkey::read_hex(hex).unwrap();
        eprintln!("{:?}", pubkey);
        let mut hex2: [u8; 64] = [0; 64];
        pubkey.write_hex(&mut hex2).unwrap();
        assert_eq!(hex, &hex2);
        assert_eq!(format!("{}", pubkey).as_bytes(), hex);
    }
}
