use crate::error::{Error, InnerError};
use crate::json::json_parse::read_tags_array;
use std::fmt;
use std::ops::{Deref, DerefMut};

/*
 * 0 .. 2    u16      Length of the tags section
 * 2 .. 4    u16      num_tags
 * 4 .. 6    u16      offset of zeroeth tag
 * 6 .. 8    u16      offset of first tag
 * ...
 *
 * 4+num_tags*2 ..    beginning of actual tag data
 *
 *    Tag data looks like this for each tag:
 *    count, (len, data), (len, data), ...
 */

/// This stores an array of tags, each tag being an array of byte-strings.
/// It is stored in a single packed linear byte array.
/// This is an unsized type; internally it borrows a slice of bytes
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Tags([u8]);

impl Tags {
    fn from_inner<S: AsRef<[u8]> + ?Sized>(s: &S) -> &Tags {
        // SAFETY: Tags is just a wrapper around [u8],
        // therefore converting &mut [u8] to &mut Tags is safe.
        unsafe { &*(s.as_ref() as *const [u8] as *const Tags) }
    }

    fn from_inner_mut(inner: &mut [u8]) -> &mut Tags {
        // SAFETY: Tags is just a wrapper around [u8],
        // therefore converting &mut [u8] to &mut Tags is safe.
        unsafe { &mut *(inner as *mut [u8] as *mut Tags) }
    }

    /// Presuming the input is the start of a Tags slice, this determines the end
    /// and returns the wrapped `Tags` type. It does not validate that it is
    /// accurate.
    ///
    /// # Safety
    /// Be sure the input is a valid Tags structure.
    pub unsafe fn delineate(input: &[u8]) -> Result<&Tags, Error> {
        if input.len() < 2 {
            return Err(InnerError::EndOfInput.into());
        }
        let len = parse_u16!(input, 0) as usize;
        if input.len() < len {
            return Err(InnerError::EndOfInput.into());
        }
        Ok(Self::from_inner(&input[0..len]))
    }

    /// Parse JSON input into a Tags.
    ///
    /// Returns the count of consumed input bytes and the Tags
    pub fn from_json<'a>(
        json: &[u8],
        output_buffer: &'a mut [u8],
    ) -> Result<(usize, &'a Tags), Error> {
        let mut inpos: usize = 0;
        let tags_size = read_tags_array(json, &mut inpos, output_buffer)?;
        Ok((inpos, Self::from_inner(&output_buffer[..tags_size])))
    }

    pub fn from_parts<'a, T: AsRef<[U]>, U: AsRef<str>>(
        parts: &[T],
        output: &'a mut [u8],
    ) -> Result<&'a Tags, Error> {
        let numtags = parts.len();
        let length = Self::output_size_needed(parts);
        if output.len() < length {
            return Err(InnerError::BufferTooSmall(length).into());
        }

        // write length
        output[0..2].copy_from_slice((length as u16).to_ne_bytes().as_slice());

        // write num_tags
        output[2..4].copy_from_slice((parts.len() as u16).to_ne_bytes().as_slice());

        // movable write pointer, start after the header
        // (the header offsets still need filling in)
        let mut p: usize = 4 + 2 * numtags;

        for (n, tagref) in parts.iter().enumerate() {
            let tag = tagref.as_ref();
            // write header offset pos
            output[4 + 2 * n..4 + 2 * n + 2].copy_from_slice((p as u16).to_ne_bytes().as_slice());

            // write count
            output[p..p + 2].copy_from_slice((tag.len() as u16).to_ne_bytes().as_slice());
            p += 2;

            for sref in tag.iter() {
                let s = sref.as_ref();

                let slen = s.as_bytes().len();

                // write string len
                output[p..p + 2].copy_from_slice((slen as u16).to_ne_bytes().as_slice());
                p += 2;

                // write string
                output[p..p + slen].copy_from_slice(s.as_bytes());
                p += slen;
            }
        }

        Ok(Self::from_inner(&output[..length]))
    }

    pub fn output_size_needed<T: AsRef<[U]>, U: AsRef<str>>(parts: &[T]) -> usize {
        let numtags = parts.len();
        let mut length = 4 + 2 * numtags; // for the header
        for tagref in parts.iter() {
            let tag = tagref.as_ref();
            length += 2; // for the count
            for sref in tag.iter() {
                let s = sref.as_ref();
                length += 2; // for the len
                length += s.as_bytes().len(); // for the data itself
            }
        }
        length
    }

    pub fn copy(&self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() < self.0.len() {
            return Err(InnerError::BufferTooSmall(self.0.len()).into());
        }
        output[..self.0.len()].copy_from_slice(&self.0);
        Ok(())
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[inline]
    pub fn len(&self) -> usize {
        parse_u16!(self.0, 2) as usize
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> TagsIter<'_> {
        TagsIter {
            tags: self,
            next: 0,
        }
    }

    pub fn get_string(&self, tag: usize, string: usize) -> Option<&[u8]> {
        if tag >= self.len() {
            return None;
        }

        let mut offset = parse_u16!(self.0, 4 + tag * 2) as usize;
        let count = parse_u16!(self.0, offset) as usize;
        offset += 2;
        if string >= count {
            return None;
        }

        let end = parse_u16!(self.0, 0) as usize;

        // pass the fields we aren't reading
        for _ in 0..string {
            let len = parse_u16!(self.0, offset) as usize;
            offset += 2 + len;
            if offset > end {
                // safety check
                return None;
            }
        }
        let len = parse_u16!(self.0, offset) as usize;
        offset += 2;
        if offset + len > end {
            // safety check
            return None;
        }

        Some(&self.0[offset..offset + len])
    }

    pub fn get_value<'a>(&'a self, key: &[u8]) -> Option<&'a [u8]> {
        for tag in 0..self.len() {
            if let Some(thing) = self.get_string(tag, 0) {
                if thing == key {
                    return self.get_string(tag, 1);
                }
            }
        }
        None
    }

    pub fn matches(&self, letter: &[u8], value: &[u8]) -> bool {
        for mut tag in self.iter() {
            if tag.next() == Some(letter) && tag.next() == Some(value) {
                return true;
            }
        }
        false
    }

    pub fn as_json(&self) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::with_capacity(256);
        let mut first = true;
        output.push(b'[');
        for tag in self.iter() {
            if !first {
                output.push(b',');
            }
            output.push(b'[');
            let mut firststring = true;
            for bytes in tag {
                if !firststring {
                    output.push(b',');
                }
                output.push(b'"');
                output.extend(bytes);
                output.push(b'"');
                firststring = false;
            }
            output.push(b']');
            first = false;
        }
        output.push(b']');
        output
    }
}

impl fmt::Display for Tags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.as_json();
        let s = unsafe { std::str::from_utf8_unchecked(&bytes) };
        write!(f, "{s}")
    }
}

#[derive(Debug)]
pub struct TagsIter<'a> {
    tags: &'a Tags,
    next: usize,
}

impl<'a> Iterator for TagsIter<'a> {
    type Item = TagsStringIter<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.tags.len() {
            None
        } else {
            let offset_slot = 4 + self.next * 2;
            let offset = parse_u16!(self.tags.0, offset_slot) as usize;
            let count = parse_u16!(self.tags.0, offset) as usize;
            self.next += 1;
            Some(TagsStringIter {
                tags: self.tags,
                count,
                cur_offset: offset + 2,
                next: 0,
            })
        }
    }
}

#[derive(Debug)]
pub struct TagsStringIter<'a> {
    tags: &'a Tags,
    count: usize,
    cur_offset: usize,
    next: usize,
}

impl<'a> Iterator for TagsStringIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.count {
            None
        } else {
            // Read len
            let len = parse_u16!(self.tags.0, self.cur_offset) as usize;
            let s = &self.tags.0[self.cur_offset + 2..self.cur_offset + 2 + len];
            self.cur_offset += 2 + len;
            self.next += 1;
            Some(s)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OwnedTags(Vec<u8>);

impl OwnedTags {
    pub fn new<T: AsRef<[U]>, U: AsRef<str>>(parts: &[T]) -> Result<OwnedTags, Error> {
        let size = Tags::output_size_needed(parts);
        let mut buffer = vec![0; size];
        let _tags = Tags::from_parts(parts, &mut buffer)?;
        Ok(OwnedTags(buffer))
    }

    #[inline]
    pub fn empty() -> OwnedTags {
        let mut buffer: Vec<u8> = vec![0; 4];
        buffer[0..2].copy_from_slice(4_u16.to_ne_bytes().as_slice());
        buffer[2] = 0;
        buffer[3] = 0;
        OwnedTags(buffer)
    }
}

impl Deref for OwnedTags {
    type Target = Tags;

    fn deref(&self) -> &Self::Target {
        Tags::from_inner(&self.0)
    }
}

impl DerefMut for OwnedTags {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Tags::from_inner_mut(&mut self.0)
    }
}

#[cfg(test)]
mod test {
    use super::Tags;

    #[test]
    fn test_tags() {
        let mut output: Vec<u8> = Vec::with_capacity(110);
        output.resize(110, 0);
        let tags_from_parts = Tags::from_parts(
            &[
                vec!["Hello world!", "Hello", "world!"],
                vec![
                    "p",
                    "ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49",
                ],
            ],
            &mut output,
        )
        .unwrap();

        let data: Vec<u8> = vec![
            110, 0, // tags_len
            2, 0, // num_tags
            8, 0, // first tag at offset 8
            39, 0, // second tag at offset 39
            // 8:
            3, 0, // three fields long
            12, 0, // first field 12 bytes long
            72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33, // "Hello world!"
            5, 0, // second field 5 bytes long
            72, 101, 108, 108, 111, // "Hello"
            6, 0, // third field 6 bytes long
            119, 111, 114, 108, 100, 33, // world!
            // 39:
            2, 0, // two fields long
            1, 0,   // first field 1 bytes long
            112, // "p"
            64, 0, // second field 64 bytes long
            101, 101, 49, 49, 97, 53, 100, 102, 102, 52, 48, 99, 49, 57, 97, 53, 53, 53, 102, 52,
            49, 102, 101, 52, 50, 98, 52, 56, 102, 48, 48, 101, 54, 49, 56, 99, 57, 49, 50, 50, 53,
            54, 50, 50, 97, 101, 51, 55, 98, 54, 99, 50, 98, 98, 54, 55, 98, 55, 54, 99, 52, 101,
            52, 57,
            // "ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49"
        ];
        let tags = unsafe { Tags::delineate(&data).unwrap() };

        // Test that Tags::from_parts() gives the same data
        assert_eq!(tags_from_parts, tags);

        // Test tag access with get_string()

        assert_eq!(tags.get_string(0, 0), Some(b"Hello world!".as_slice()));
        assert_eq!(tags.get_string(0, 1), Some(b"Hello".as_slice()));
        assert_eq!(tags.get_string(0, 2), Some(b"world!".as_slice()));
        assert_eq!(tags.get_string(0, 3), None);
        assert_eq!(tags.get_string(1, 0), Some(b"p".as_slice()));
        assert_eq!(
            tags.get_string(1, 1),
            Some(b"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49".as_slice())
        );
        assert_eq!(tags.get_string(1, 2), None);
        assert_eq!(tags.get_string(2, 0), None);

        // Test tag access with iterators

        let mut iter = tags.iter();

        let mut tag1 = iter.next().unwrap();
        println!("TagsStringIter 1 {:?}", tag1);
        assert_eq!(tag1.next(), Some(b"Hello world!".as_slice()));
        assert_eq!(tag1.next(), Some(b"Hello".as_slice()));
        assert_eq!(tag1.next(), Some(b"world!".as_slice()));
        assert!(tag1.next().is_none());

        let mut tag2 = iter.next().unwrap();
        assert_eq!(tag2.next(), Some(b"p".as_slice()));
        assert_eq!(
            tag2.next(),
            Some(b"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49".as_slice())
        );
        assert!(tag2.next().is_none());

        let tag3 = iter.next();
        assert!(tag3.is_none());

        assert_eq!(
            format!("{tags}"),
            r#"[["Hello world!","Hello","world!"],["p","ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49"]]"#
        );
    }

    #[test]
    fn test_tags_from_json() {
        let mut output: Vec<u8> = Vec::with_capacity(4096);
        output.resize(4096, 0);

        let json = r#"[["Hello world!","Hello","world!"],["p","ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49"]]"#;

        let (_, tags) = Tags::from_json(json.as_bytes(), &mut output).unwrap();

        assert_eq!(tags.get_string(0, 0), Some(b"Hello world!".as_slice()));
        assert_eq!(tags.get_string(0, 1), Some(b"Hello".as_slice()));
        assert_eq!(tags.get_string(0, 2), Some(b"world!".as_slice()));
        assert_eq!(tags.get_string(0, 3), None);
        assert_eq!(tags.get_string(1, 0), Some(b"p".as_slice()));
        assert_eq!(
            tags.get_string(1, 1),
            Some(b"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49".as_slice())
        );
        assert_eq!(tags.get_string(1, 2), None);
        assert_eq!(tags.get_string(2, 0), None);
    }

    #[test]
    fn test_empty_tag() {
        let mut output: Vec<u8> = Vec::with_capacity(256);
        output.resize(256, 0);

        let json = r#"[[]]"#;
        let (_, _tags) = Tags::from_json(json.as_bytes(), &mut output).unwrap();

        let json = r#"[["-"],[]]"#;
        let (_, tags) = Tags::from_json(json.as_bytes(), &mut output).unwrap();
        assert_eq!(tags.get_string(0, 0), Some(b"-".as_slice()));
    }
}
