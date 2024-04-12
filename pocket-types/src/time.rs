use derive_more::{AsRef, Deref, From, Into};
use std::fmt;
use std::ops::{Add, Sub};
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, AsRef, Deref, From, Into)]
pub struct Time(u64);

impl Time {
    pub fn from_u64(secs: u64) -> Time {
        Time(secs)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn min() -> Time {
        Time(0)
    }

    pub fn max() -> Time {
        Time(u64::MAX)
    }

    pub fn now() -> Time {
        // Safety: unwrap() can only panic if the system time is before UNIX_EPOCH
        Time(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs())
    }
}

impl Default for Time {
    fn default() -> Time {
        Time::now()
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add<Time> for Time {
    type Output = Time;

    fn add(self, rhs: Time) -> Self::Output {
        Time(self.0 + rhs.0)
    }
}

impl Sub<Time> for Time {
    type Output = Time;

    fn sub(self, rhs: Time) -> Self::Output {
        Time(self.0 - rhs.0)
    }
}
