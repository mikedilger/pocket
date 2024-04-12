use derive_more::{AsRef, Deref, From, Into};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, AsRef, Deref, From, Into)]
pub struct Kind(u16);

impl Kind {
    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn is_replaceable(&self) -> bool {
        (10000..20000).contains(&self.0) || self.0 == 0 || self.0 == 3
    }

    pub fn is_ephemeral(&self) -> bool {
        (20000..30000).contains(&self.0)
    }

    pub fn is_parameterized_replaceable(&self) -> bool {
        (30000..40000).contains(&self.0)
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
