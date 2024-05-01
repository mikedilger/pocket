mod json_escape;
pub(crate) mod json_parse;
mod utf8;

pub use json_escape::{json_escape, json_unescape};
pub use json_parse::{eat_whitespace, verify_char};

#[inline]
pub(crate) fn put(
    output: &mut [u8],
    offset: usize,
    data: &[u8],
) -> Result<(), crate::error::Error> {
    if output.len() < offset + data.len() {
        Err(crate::error::InnerError::BufferTooSmall(offset + data.len()).into())
    } else {
        output[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }
}
