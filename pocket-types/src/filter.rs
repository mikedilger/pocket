use super::{Event, Id, Kind, Pubkey, Tags, Time};
use crate::error::{Error, InnerError};
use crate::json::json_parse::*;
use crate::json::json_unescape;
use crate::json::put;
use std::fmt;
use std::ops::{Deref, DerefMut};

/*
 *  0 [4 bytes] length of entire structure
 *  4 [2 bytes] num_ids
 *  6 [2 bytes] num_authors
 *  8 [2 bytes] num_kinds
 *  10 [2 bytes] PADDING
 *  12 [4 bytes] limit				u32.   Set to u32::max if limit was not set.
 *  16 [8 bytes] since				u64.   Set to 0 if since was not set.
 *  24 [8 bytes] until				u64.   Set to u64::max if until was not set.
 *  32 [ID] array
 *  [Pubkey] array                  starts at 32 + num_ids*32
 *  [Kind] array                    starts at 32 + num_ids*32 + num_authors*32
 *  [Tags] object                   starts at 32 + num_ids*32 + num_authors*32 * num_kinds*2
 */

const NUM_IDS_OFFSET: usize = 4;
const NUM_AUTHORS_OFFSET: usize = 6;
const NUM_KINDS_OFFSET: usize = 8;
const LIMIT_OFFSET: usize = 12;
const SINCE_OFFSET: usize = 16;
const UNTIL_OFFSET: usize = 24;
const ARRAYS_OFFSET: usize = 32;
const ID_SIZE: usize = 32;
const PUBKEY_SIZE: usize = 32;
const KIND_SIZE: usize = 2;

/// A nostr filter
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Filter([u8]);

impl Filter {
    fn from_inner<S: AsRef<[u8]> + ?Sized>(s: &S) -> &Filter {
        // SAFETY: Filter is just a wrapper around [u8],
        // therefore converting &mut [u8] to &mut Filter is safe.
        unsafe { &*(s.as_ref() as *const [u8] as *const Filter) }
    }

    fn from_inner_mut(inner: &mut [u8]) -> &mut Filter {
        // SAFETY: Filter is just a wrapper around [u8],
        // therefore converting &mut [u8] to &mut Filter is safe.
        unsafe { &mut *(inner as *mut [u8] as *mut Filter) }
    }

    /// Presuming the input is the start of a Filter slice, this determines the end
    /// and returns the wrapped `Filter` type. It does not validate that it is
    /// accurate.
    ///
    /// # Safety
    /// Be sure the input is a valid Filter slice.
    pub unsafe fn delineate(input: &[u8]) -> Result<&Filter, Error> {
        if input.len() < ARRAYS_OFFSET {
            return Err(InnerError::EndOfInput.into());
        }
        let len = parse_u32!(input, 0) as usize;
        if input.len() < len {
            return Err(InnerError::EndOfInput.into());
        }
        Ok(Self::from_inner(&input[0..len]))
    }

    /// Copy to an allocated owned data type
    pub fn to_owned(&self) -> OwnedFilter {
        OwnedFilter(self.0.to_owned())
    }

    /// Build a filter from parts
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts<'a>(
        ids: &[Id],
        authors: &[Pubkey],
        kinds: &[Kind],
        tags: &Tags,
        since: Option<Time>,
        until: Option<Time>,
        limit: Option<u32>,
        output: &'a mut [u8],
    ) -> Result<&'a Filter, Error> {
        let length = Self::output_size_needed(ids, authors, kinds, tags);
        if output.len() < length {
            return Err(InnerError::BufferTooSmall(length).into());
        }

        // length
        output[0..4].copy_from_slice((length as u32).to_ne_bytes().as_slice());

        // num_ids
        output[4..6].copy_from_slice((ids.len() as u16).to_ne_bytes().as_slice());

        // num_authors
        output[6..8].copy_from_slice((authors.len() as u16).to_ne_bytes().as_slice());

        // num_kinds
        output[8..10].copy_from_slice((kinds.len() as u16).to_ne_bytes().as_slice());

        // zero-padding
        output[10] = 0;
        output[11] = 0;

        // limit
        match limit {
            Some(l) => output[12..16].copy_from_slice(l.to_ne_bytes().as_slice()),
            None => output[12..16].copy_from_slice(u32::MAX.to_ne_bytes().as_slice()),
        }

        // since
        match since {
            Some(s) => output[16..24].copy_from_slice(s.as_u64().to_ne_bytes().as_slice()),
            None => output[16..24].copy_from_slice(0_u64.to_ne_bytes().as_slice()),
        }

        // until
        match until {
            Some(u) => output[24..32].copy_from_slice(u.as_u64().to_ne_bytes().as_slice()),
            None => output[24..32].copy_from_slice(u64::MAX.to_ne_bytes().as_slice()),
        }

        let mut p = 32;

        // ids
        for id in ids.iter() {
            output[p..p + 32].copy_from_slice(id.as_slice());
            p += 32;
        }

        // authors
        for pubkey in authors.iter() {
            output[p..p + 32].copy_from_slice(pubkey.as_slice());
            p += 32;
        }

        // kinds
        for kind in kinds.iter() {
            output[p..p + 2].copy_from_slice(kind.as_ref().to_ne_bytes().as_slice());
            p += 2;
        }

        // tags
        output[p..p + tags.as_bytes().len()].copy_from_slice(tags.as_bytes());

        assert_eq!(p + tags.as_bytes().len(), length);

        Ok(Self::from_inner(&output[..length]))
    }

    /// The number of bytes needed to represent a filter with the data supplied
    pub fn output_size_needed(
        ids: &[Id],
        authors: &[Pubkey],
        kinds: &[Kind],
        tags: &Tags,
    ) -> usize {
        32 + ids.len() * 32 + authors.len() * 32 + kinds.len() * 2 + tags.as_bytes().len()
    }

    /// Parse JSON input into a Filter
    ///
    /// Returns the count of consumed input bytes, output bytes, and the Filter
    pub fn from_json<'a>(
        json: &[u8],
        output_buffer: &'a mut [u8],
    ) -> Result<(usize, usize, &'a Filter), Error> {
        let (incount, outcount) = parse_json_filter(json, output_buffer)?;
        Ok((
            incount,
            outcount,
            Self::from_inner(&output_buffer[..outcount]),
        ))
    }

    /// Copy the internal reprentation bytes
    pub fn copy(&self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() < self.0.len() {
            return Err(InnerError::EndOfInput.into());
        }
        output[..self.0.len()].copy_from_slice(&self.0);
        Ok(())
    }

    /// As internal representation bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The length of the internal representation bytes
    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The number of ids that this filter has
    #[inline]
    pub fn num_ids(&self) -> usize {
        parse_u16!(self.0, NUM_IDS_OFFSET) as usize
    }

    /// the event ids that this filter matches
    #[inline]
    pub fn ids(&self) -> FilterIdIter<'_> {
        FilterIdIter {
            filter: self,
            next: 0,
        }
    }

    /// the number of authors that this filter has
    #[inline]
    pub fn num_authors(&self) -> usize {
        parse_u16!(self.0, NUM_AUTHORS_OFFSET) as usize
    }

    #[inline]
    fn start_of_authors(&self) -> usize {
        ARRAYS_OFFSET + self.num_ids() * ID_SIZE
    }

    /// The authors that this filter matches
    #[inline]
    pub fn authors(&self) -> FilterAuthorIter<'_> {
        FilterAuthorIter {
            filter: self,
            start_of_authors: self.start_of_authors(),
            next: 0,
        }
    }

    /// The number of event kinds this filter has
    #[inline]
    pub fn num_kinds(&self) -> usize {
        parse_u16!(self.0, NUM_KINDS_OFFSET) as usize
    }

    #[inline]
    fn start_of_kinds(&self) -> usize {
        ARRAYS_OFFSET + self.num_ids() * ID_SIZE + self.num_authors() * PUBKEY_SIZE
    }

    /// The event kinds that this filter matches
    #[inline]
    pub fn kinds(&self) -> FilterKindIter<'_> {
        FilterKindIter {
            filter: self,
            start_of_kinds: self.start_of_kinds(),
            next: 0,
        }
    }

    #[inline]
    fn start_of_tags(&self) -> usize {
        ARRAYS_OFFSET
            + self.num_ids() * ID_SIZE
            + self.num_authors() * PUBKEY_SIZE
            + self.num_kinds() * KIND_SIZE
    }

    /// The Tags that this filter matches.
    ///
    /// Note that only single-letter tags are currently supported.
    #[inline]
    pub fn tags(&self) -> Result<&Tags, Error> {
        unsafe { Tags::delineate(&self.0[self.start_of_tags()..]) }
    }

    /// The maximum number of events this filter will output
    #[inline]
    pub fn limit(&self) -> u32 {
        parse_u32!(self.0, LIMIT_OFFSET)
    }

    /// The time before which events will not match
    #[inline]
    pub fn since(&self) -> Time {
        parse_u64!(self.0, SINCE_OFFSET).into()
    }

    /// The time beyond which events will not match
    #[inline]
    pub fn until(&self) -> Time {
        parse_u64!(self.0, UNTIL_OFFSET).into()
    }

    /// Does the given event match this filter?
    pub fn event_matches(&self, event: &Event) -> Result<bool, Error> {
        // ids
        if self.num_ids() != 0 && !self.ids().any(|id| id == event.id()) {
            return Ok(false);
        }

        // authors
        if self.num_authors() != 0 && !self.authors().any(|pk| pk == event.pubkey()) {
            return Ok(false);
        }

        // kinds
        if self.num_kinds() != 0 && !self.kinds().any(|kind| kind == event.kind()) {
            return Ok(false);
        }

        // since
        if event.created_at() < self.since() {
            return Ok(false);
        }

        // until
        if event.created_at() > self.until() {
            return Ok(false);
        }

        // tags
        let filter_tags = self.tags()?;
        if !filter_tags.is_empty() {
            let event_tags = event.tags()?;
            if event_tags.is_empty() {
                return Ok(false);
            }

            let mut i = 0;
            while let Some(letter) = filter_tags.get_string(i, 0) {
                let mut j = 1;
                let mut found = false;
                while let Some(value) = filter_tags.get_string(i, j) {
                    if event_tags.matches(letter, value) {
                        found = true;
                        break;
                    }
                    j += 1;
                }
                if !found {
                    return Ok(false);
                }
                i += 1;
            }
        }

        Ok(true)
    }

    /// Output JSON bytes for this nostr filter
    pub fn as_json(&self) -> Result<Vec<u8>, Error> {
        let mut output: Vec<u8> = Vec::with_capacity(256);
        output.push(b'{');
        let mut first = true;

        if self.num_ids() > 0 {
            output.extend(br#""ids":["#);
            for (i, id) in self.ids().enumerate() {
                if i > 0 {
                    output.push(b',');
                }
                output.push(b'"');
                let pos = output.len();
                output.resize(pos + 64, 0);
                id.write_hex(&mut output[pos..])?;
                output.push(b'"');
            }
            output.push(b']');
            first = false;
        }

        if self.num_authors() > 0 {
            if !first {
                output.push(b',');
            }
            output.extend(br#""authors":["#);
            for (i, pk) in self.authors().enumerate() {
                if i > 0 {
                    output.push(b',');
                }
                output.push(b'"');
                let pos = output.len();
                output.resize(pos + 64, 0);
                pk.write_hex(&mut output[pos..])?;
                output.push(b'"');
            }
            output.push(b']');
            first = false;
        }

        if self.num_kinds() > 0 {
            if !first {
                output.push(b',');
            }
            output.extend(br#""kinds":["#);
            for (i, k) in self.kinds().enumerate() {
                if i > 0 {
                    output.push(b',');
                }
                output.extend(format!("{}", *k.as_ref()).as_bytes());
            }
            output.push(b']');
            first = false;
        }

        let tags = self.tags()?;
        if !tags.is_empty() {
            // Filter 'tags' are not an array of arrays, they are just a convenient
            // way to store similar data. They also elide the '#'. So we have to
            // iterate here, we cannot use tags.as_json()
            for tag in tags.iter() {
                if !first {
                    output.push(b',');
                }
                for (i, bytes) in tag.enumerate() {
                    if i == 0 {
                        output.extend(b"\"#");
                        output.extend(bytes);
                        output.extend(b"\":[");
                    } else {
                        if i > 1 {
                            output.push(b',');
                        }
                        output.push(b'"');
                        output.extend(bytes);
                        output.push(b'"');
                    }
                }
                output.push(b']');
                first = false;
            }
        }

        if self.limit() != u32::MAX {
            if !first {
                output.push(b',');
            }
            output.extend(format!(r#""limit":{}"#, self.limit()).as_bytes());
            first = false;
        }

        if self.since() != Time::min() {
            if !first {
                output.push(b',');
            }
            output.extend(format!(r#""since":{}"#, *self.since().as_ref()).as_bytes());
            first = false;
        }

        if self.until() != Time::max() {
            if !first {
                output.push(b',');
            }
            output.extend(format!(r#""until":{}"#, *self.until().as_ref()).as_bytes());
        }

        output.push(b'}');

        Ok(output)
    }

    /// The offset used for NIP-45 (pr #1561)
    pub fn hyperloglog_offset(&self) -> Result<Option<usize>, Error> {
        let tags = self.tags()?;

        // Restrictions on what kinds of filters get Hll counts
        if self.num_ids() != 0
            || self.num_authors() != 0
            || self.num_kinds() != 1
            || self.limit() != u32::MAX
            || self.since() != Time::min()
            || self.until() != Time::max()
            || tags.count() != 1
        {
            return Ok(None);
        }

        if self.kinds().next() == Some(Kind::from_u16(3)) {
            // {"#p": ["<pubkey>"], "kinds": [3]}
            if tags.get_string(0, 0) != Some(b"p") {
                return Ok(None);
            }
        } else if self.kinds().next() == Some(Kind::from_u16(7)) {
            // {"#e": ["<id>"], "kinds": [7]}
            if tags.get_string(0, 0) != Some(b"e") {
                return Ok(None);
            }
        } else {
            return Ok(None);
        };

        let hex = match tags.get_string(0, 1) {
            Some(h) => h,
            None => {
                return Ok(None); // actually an error
            }
        };

        if hex.len() != 64 {
            return Ok(None); // actually an error
        }

        let base_offset = crate::HEX_INVERSE[hex[32] as usize];
        if base_offset == 255 {
            return Ok(None); // actually an error
        }

        Ok(Some(base_offset as usize + 8))
    }
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(bytes) = self.as_json() {
            let s = unsafe { std::str::from_utf8_unchecked(&bytes) };
            write!(f, "{s}")
        } else {
            write!(f, "{{Corrupted Event}}")
        }
    }
}

#[derive(Debug)]
pub struct FilterIdIter<'a> {
    filter: &'a Filter,
    next: usize,
}

impl Iterator for FilterIdIter<'_> {
    type Item = Id;

    fn next(&mut self) -> Option<Self::Item> {
        let num_ids = parse_u16!(self.filter.0, NUM_IDS_OFFSET) as usize;
        if self.next >= num_ids {
            None
        } else {
            let offset = ARRAYS_OFFSET + self.next * ID_SIZE;
            self.next += 1;
            if self.filter.0.len() < offset + ID_SIZE {
                None
            } else {
                Some(self.filter.0[offset..offset + ID_SIZE].try_into().unwrap())
            }
        }
    }
}

#[derive(Debug)]
pub struct FilterAuthorIter<'a> {
    filter: &'a Filter,
    start_of_authors: usize,
    next: usize,
}

impl Iterator for FilterAuthorIter<'_> {
    type Item = Pubkey;

    fn next(&mut self) -> Option<Self::Item> {
        let num_authors = parse_u16!(self.filter.0, NUM_AUTHORS_OFFSET) as usize;
        if self.next >= num_authors {
            None
        } else {
            let offset = self.start_of_authors + self.next * PUBKEY_SIZE;
            self.next += 1;
            if self.filter.0.len() < offset + PUBKEY_SIZE {
                None
            } else {
                Some(
                    self.filter.0[offset..offset + PUBKEY_SIZE]
                        .try_into()
                        .unwrap(),
                )
            }
        }
    }
}

#[derive(Debug)]
pub struct FilterKindIter<'a> {
    filter: &'a Filter,
    start_of_kinds: usize,
    next: usize,
}

impl Iterator for FilterKindIter<'_> {
    type Item = Kind;

    fn next(&mut self) -> Option<Self::Item> {
        let num_kinds = parse_u16!(self.filter.0, NUM_KINDS_OFFSET) as usize;
        if self.next >= num_kinds {
            None
        } else {
            let offset = self.start_of_kinds + self.next * KIND_SIZE;
            self.next += 1;
            if self.filter.0.len() < offset + KIND_SIZE {
                None
            } else {
                Some(parse_u16!(self.filter.0, offset).into())
            }
        }
    }
}

/// An owned memory-allocated filter
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OwnedFilter(Vec<u8>);

impl OwnedFilter {
    /// Create a new memory-allocated owned filter
    pub fn new(
        ids: &[Id],
        authors: &[Pubkey],
        kinds: &[Kind],
        tags: &Tags,
        since: Option<Time>,
        until: Option<Time>,
        limit: Option<u32>,
    ) -> Result<OwnedFilter, Error> {
        let size = Filter::output_size_needed(ids, authors, kinds, tags);
        let mut buffer = vec![0; size];
        let _filter =
            Filter::from_parts(ids, authors, kinds, tags, since, until, limit, &mut buffer)?;
        Ok(OwnedFilter(buffer))
    }
}

impl Deref for OwnedFilter {
    type Target = Filter;

    fn deref(&self) -> &Self::Target {
        Filter::from_inner(&self.0)
    }
}

impl DerefMut for OwnedFilter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Filter::from_inner_mut(&mut self.0)
    }
}

/// Parses a JSON filter from the `input` buffer. Places the parsed filter into the `output` buffer.
/// Returns the count of consumed bytes and output bytes
fn parse_json_filter(input: &[u8], output: &mut [u8]) -> Result<(usize, usize), Error> {
    if input.len() < 2 {
        return Err(InnerError::JsonBadFilter("Too short", 0).into());
    }

    // This tracks where we are currently looking in the input as we scan forward.
    // It is short for INput POSition.
    let mut inpos = 0;

    // Remember which fields we have read using bit flags.
    // We should only get at maximum one of each
    const HAVE_IDS: u8 = 0x1 << 0;
    const HAVE_AUTHORS: u8 = 0x1 << 1;
    const HAVE_KINDS: u8 = 0x1 << 2;
    const HAVE_LIMIT: u8 = 0x1 << 3;
    const HAVE_SINCE: u8 = 0x1 << 4;
    const HAVE_UNTIL: u8 = 0x1 << 5;
    let mut found: u8 = 0;

    // Remember which tags we have seen
    // We track A-Z in the lower 26 bits, and a-z in the next 26 bits
    let mut found_tags: u64 = 0;
    let letter_to_tag_bit = |letter: u8| -> Option<u64> {
        match letter {
            65..=90 => Some(letter as u64 - 65),
            97..=122 => Some(letter as u64 - 97 + 26),
            _ => None,
        }
    };

    // Start structure with that of an empty filter
    put(
        output,
        0,
        &[
            0, 0, 0, 0, // length (we will fill it in later)
            0, 0, // 0 ids
            0, 0, // 0 authors
            0, 0, // 0 kinds
            0, 0, // padding
            255, 255, 255, 255, // max limit
            0, 0, 0, 0, 0, 0, 0, 0, // since 1970
            255, 255, 255, 255, 255, 255, 255, 255, // until max unixtime
        ],
    )?;

    let mut end: usize = ARRAYS_OFFSET;

    // We just store the position of ids, authors, kinds, and tags
    // and come back to parse them properly again at the end,
    // since we need to write them in a particular order.
    let mut start_ids: Option<usize> = None;
    let mut start_authors: Option<usize> = None;
    let mut start_kinds: Option<usize> = None;
    // Allowing up to 32 tag filter fields (plenty!)
    // (we are not differentiating letters yet, just collecting offsets)
    // (we make the array to avoid allocation)
    let mut num_tag_fields = 0;
    let mut start_tags: [usize; 32] = [usize::MAX; 32];

    eat_whitespace(input, &mut inpos);
    verify_char(input, b'{', &mut inpos)?;
    loop {
        eat_whitespace_and_commas(input, &mut inpos);

        // Check for end
        if input[inpos] == b'}' {
            inpos += 1;
            break;
        }

        verify_char(input, b'"', &mut inpos)?;

        if inpos + 4 <= input.len() && &input[inpos..inpos + 4] == b"ids\"" {
            // Check for duplicate
            if found & HAVE_IDS == HAVE_IDS {
                return Err(InnerError::JsonBadFilter("Duplicate id field", inpos).into());
            }
            inpos += 4;

            eat_colon_with_whitespace(input, &mut inpos)?;
            verify_char(input, b'[', &mut inpos)?;

            // Record for later
            start_ids = Some(inpos);

            // Burn the field
            while inpos < input.len() && input[inpos] != b']' {
                inpos += 1;
            }
            verify_char(input, b']', &mut inpos)?;

            // Mark as found 'ids'  FIXME this dups `start_ids`
            found |= HAVE_IDS;
        } else if inpos + 8 <= input.len() && &input[inpos..inpos + 8] == b"authors\"" {
            // Check for duplicate
            if found & HAVE_AUTHORS == HAVE_AUTHORS {
                return Err(InnerError::JsonBadFilter("Duplicate authors field", inpos).into());
            }
            inpos += 8;

            eat_colon_with_whitespace(input, &mut inpos)?;
            verify_char(input, b'[', &mut inpos)?;

            // Save the input offset for post-processing
            start_authors = Some(inpos);

            // Burn the field
            while inpos < input.len() && input[inpos] != b']' {
                inpos += 1;
            }
            verify_char(input, b']', &mut inpos)?;

            found |= HAVE_AUTHORS;
        } else if inpos + 6 <= input.len() && &input[inpos..inpos + 6] == b"kinds\"" {
            // Check for duplicate
            if found & HAVE_KINDS == HAVE_KINDS {
                return Err(InnerError::JsonBadFilter("Duplicate kinds field", inpos).into());
            }
            inpos += 6;

            eat_colon_with_whitespace(input, &mut inpos)?;
            verify_char(input, b'[', &mut inpos)?;

            // Mark this position and bypass this field
            start_kinds = Some(inpos);

            // Burn the field
            while inpos < input.len() && input[inpos] != b']' {
                inpos += 1;
            }
            verify_char(input, b']', &mut inpos)?;

            found |= HAVE_KINDS;
        } else if inpos + 6 <= input.len() && &input[inpos..inpos + 6] == b"since\"" {
            // Check for duplicate
            if found & HAVE_SINCE == HAVE_SINCE {
                return Err(InnerError::JsonBadFilter("Duplicate since field", inpos).into());
            }
            inpos += 6;

            eat_colon_with_whitespace(input, &mut inpos)?;
            let since = read_u64(input, &mut inpos)?;
            put(output, SINCE_OFFSET, since.to_ne_bytes().as_slice())?;

            found |= HAVE_SINCE;
        } else if inpos + 6 <= input.len() && &input[inpos..inpos + 6] == b"until\"" {
            // Check for duplicate
            if found & HAVE_UNTIL == HAVE_UNTIL {
                return Err(InnerError::JsonBadFilter("Duplicate until field", inpos).into());
            }
            inpos += 6;

            eat_colon_with_whitespace(input, &mut inpos)?;
            let until = read_u64(input, &mut inpos)?;
            put(output, UNTIL_OFFSET, until.to_ne_bytes().as_slice())?;

            found |= HAVE_UNTIL;
        } else if inpos + 6 <= input.len() && &input[inpos..inpos + 6] == b"limit\"" {
            // Check for duplicate
            if found & HAVE_LIMIT == HAVE_LIMIT {
                return Err(InnerError::JsonBadFilter("Duplicate limit field", inpos).into());
            }
            inpos += 6;

            eat_colon_with_whitespace(input, &mut inpos)?;
            let limit = read_u64(input, &mut inpos)?;
            let limit: u32 = limit as u32;
            put(output, LIMIT_OFFSET, limit.to_ne_bytes().as_slice())?;

            found |= HAVE_LIMIT;
        } else if inpos + 3 <= input.len()
            && input[inpos] == b'#'
            && ((input[inpos + 1] >= 65 && input[inpos + 1] <= 90)
                || (input[inpos + 1] >= 97 && input[inpos + 1] <= 122))
            && input[inpos + 2] == b'"'
        {
            inpos += 1; // pass the hash

            // Mark this position (on the letter itself)
            start_tags[num_tag_fields] = inpos;
            num_tag_fields += 1;

            let letter = input[inpos];
            inpos += 2; // pass the letter and quote

            // Remember we found this tag in the `found_tags` bitfield
            if let Some(bit) = letter_to_tag_bit(letter) {
                if found_tags & bit == bit {
                    return Err(InnerError::JsonBadFilter("Duplicate tag", inpos).into());
                }
                found_tags |= bit;
            }

            // Burn the rest
            eat_colon_with_whitespace(input, &mut inpos)?;
            verify_char(input, b'[', &mut inpos)?;
            burn_array(input, &mut inpos)?;
        } else {
            burn_key_and_value(input, &mut inpos)?;
        }
    }

    // Copy ids
    if let Some(mut inpos) = start_ids {
        let mut num_ids: u16 = 0;
        // `inpos` is right after the open bracket of the array
        loop {
            eat_whitespace_and_commas(input, &mut inpos);
            if input[inpos] == b']' {
                break;
            }
            read_id(input, &mut inpos, &mut output[end..])?;
            num_ids += 1;
            end += ID_SIZE;
        }

        // Write num_ids
        put(output, NUM_IDS_OFFSET, num_ids.to_ne_bytes().as_slice())?;
    }

    // Copy authors
    if let Some(mut inpos) = start_authors {
        let mut num_authors: u16 = 0;
        // `inpos` is right after the open bracket of the array
        loop {
            eat_whitespace_and_commas(input, &mut inpos);
            if input[inpos] == b']' {
                break;
            }
            read_pubkey(input, &mut inpos, &mut output[end..])?;
            num_authors += 1;
            end += PUBKEY_SIZE;
        }

        // write num_authors
        put(
            output,
            NUM_AUTHORS_OFFSET,
            num_authors.to_ne_bytes().as_slice(),
        )?;
    }

    // Copy kinds
    if let Some(mut inpos) = start_kinds {
        let mut num_kinds: u16 = 0;
        // `inpos` is right after the open bracket of the array
        loop {
            eat_whitespace_and_commas(input, &mut inpos);
            if input[inpos] == b']' {
                break;
            }
            let u = read_u64(input, &mut inpos)?;
            if u > 65535 {
                return Err(
                    InnerError::JsonBadFilter("Filter has kind number too large", inpos).into(),
                );
            }
            put(output, end, (u as u16).to_ne_bytes().as_slice())?;
            num_kinds += 1;
            end += KIND_SIZE;
        }

        // write num_kinds
        put(output, NUM_KINDS_OFFSET, num_kinds.to_ne_bytes().as_slice())?;
    }

    // Copy tags
    {
        let write_tags_start = end;
        // write number of tags
        put(
            output,
            write_tags_start + 2,
            (num_tag_fields as u16).to_ne_bytes().as_slice(),
        )?;
        // bump end past offset fields
        end += 4 + 2 * num_tag_fields;
        // Now pull in each tag
        #[allow(clippy::needless_range_loop)]
        for w in 0..num_tag_fields {
            // Write it's offset
            put(
                output,
                write_tags_start + 4 + (2 * w),
                ((end - write_tags_start) as u16).to_ne_bytes().as_slice(),
            )?;

            let mut inpos = start_tags[w];
            let letter = input[inpos];

            // bump past count output and write letter
            let countindex = end;
            end += 2;
            put(output, end, 1_u16.to_ne_bytes().as_slice())?;
            if output.len() < end + 2 {
                return Err(InnerError::BufferTooSmall(end + 2).into());
            }
            output[end + 2] = letter;

            // bump past what we just wrote
            end += 3;

            // scan further in input
            inpos += 1; // move off letter
            verify_char(input, b'"', &mut inpos)?;
            eat_colon_with_whitespace(input, &mut inpos)?;
            verify_char(input, b'[', &mut inpos)?;

            let mut count: u16 = 1; // the tag letter itself counts
            loop {
                eat_whitespace_and_commas(input, &mut inpos);
                if input[inpos] == b']' {
                    break;
                }
                verify_char(input, b'"', &mut inpos)?;
                // copy  data
                let (inlen, outlen) = json_unescape(&input[inpos..], &mut output[end + 2..])?;
                // write len
                put(output, end, (outlen as u16).to_ne_bytes().as_slice())?;
                end += 2 + outlen;
                inpos += inlen + 1;
                count += 1;
            }

            // write count
            put(output, countindex, count.to_ne_bytes().as_slice())?;
        }
        // write length of tags section
        put(
            output,
            write_tags_start,
            ((end - write_tags_start) as u16).to_ne_bytes().as_slice(),
        )?;
    }

    if end > u32::MAX as usize {
        return Err(InnerError::JsonBadFilter("Filter is too long", end).into());
    }

    // Write length of filter
    put(output, 0, (end as u32).to_ne_bytes().as_slice())?;

    Ok((inpos, end))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Pubkey, Tags, TagsIter, TagsStringIter, Time};

    #[test]
    fn test_filter() {
        /*
         * {
         *   "ids": [ "6b43bc2e373b6d9330ff571f3f4e6d897b32d01d65227df3fa41cdf731c63c3a",
         *            "1f47034c9d6d0539382a86ba31766f00f2b8312ab167c036729422ec9e7085e8"],
         *   "authors": [ "52b4a076bcbbbdc3a1aefa3735816cf74993b1b8db202b01c883c58be7fad8bd",
         *                "ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49" ],
         *   "kinds": [ 1, 5, 30023 ],
         *   "since": 1702161345,
         *   "#p": [ "fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52" ],
         * }
         */

        // For comparison
        let id1 = Id::read_hex(b"6b43bc2e373b6d9330ff571f3f4e6d897b32d01d65227df3fa41cdf731c63c3a")
            .unwrap();

        let id2 = Id::read_hex(b"1f47034c9d6d0539382a86ba31766f00f2b8312ab167c036729422ec9e7085e8")
            .unwrap();
        let pk1 =
            Pubkey::read_hex(b"52b4a076bcbbbdc3a1aefa3735816cf74993b1b8db202b01c883c58be7fad8bd")
                .unwrap();
        let pk2 =
            Pubkey::read_hex(b"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49")
                .unwrap();
        let tagged =
            Pubkey::read_hex(b"fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52")
                .unwrap();

        let data: Vec<u8> = vec![
            211, 0, 0, 0, // length of structure
            2, 0, // number of IDs
            2, 0, // number of authors
            3, 0, // number of kinds
            0, 0, // padding
            255, 255, 255, 255, // limit
            0xC1, 0xEB, 0x74, 0x65, 0, 0, 0, 0, // since
            255, 255, 255, 255, 255, 255, 255, 255, // until
            0x6b, 0x43, 0xbc, 0x2e, 0x37, 0x3b, 0x6d, 0x93, 0x30, 0xff, 0x57, 0x1f, 0x3f, 0x4e,
            0x6d, 0x89, 0x7b, 0x32, 0xd0, 0x1d, 0x65, 0x22, 0x7d, 0xf3, 0xfa, 0x41, 0xcd, 0xf7,
            0x31, 0xc6, 0x3c, 0x3a, // ID 1
            0x1f, 0x47, 0x03, 0x4c, 0x9d, 0x6d, 0x05, 0x39, 0x38, 0x2a, 0x86, 0xba, 0x31, 0x76,
            0x6f, 0x00, 0xf2, 0xb8, 0x31, 0x2a, 0xb1, 0x67, 0xc0, 0x36, 0x72, 0x94, 0x22, 0xec,
            0x9e, 0x70, 0x85, 0xe8, // ID 2
            0x52, 0xb4, 0xa0, 0x76, 0xbc, 0xbb, 0xbd, 0xc3, 0xa1, 0xae, 0xfa, 0x37, 0x35, 0x81,
            0x6c, 0xf7, 0x49, 0x93, 0xb1, 0xb8, 0xdb, 0x20, 0x2b, 0x01, 0xc8, 0x83, 0xc5, 0x8b,
            0xe7, 0xfa, 0xd8, 0xbd, // Pubkey 1
            0xee, 0x11, 0xa5, 0xdf, 0xf4, 0x0c, 0x19, 0xa5, 0x55, 0xf4, 0x1f, 0xe4, 0x2b, 0x48,
            0xf0, 0x0e, 0x61, 0x8c, 0x91, 0x22, 0x56, 0x22, 0xae, 0x37, 0xb6, 0xc2, 0xbb, 0x67,
            0xb7, 0x6c, 0x4e, 0x49, // Pubkey 2
            1, 0, 5, 0, 71, 117, // 3 kinds
            // Tags
            45, 0, // tags_len
            1, 0, // num_tags
            6, 0, // first tag offset at 6
            2, 0, // 2 fields long
            1, 0,   // 1st field is 1 byte
            112, // "p"
            32, 0, // 2nd field is 32 bytes
            // 2nd field
            0xfa, 0x98, 0x4b, 0xd7, 0xdb, 0xb2, 0x82, 0xf0, 0x7e, 0x16, 0xe7, 0xae, 0x87, 0xb2,
            0x6a, 0x2a, 0x7b, 0x9b, 0x90, 0xb7, 0x24, 0x6a, 0x44, 0x77, 0x1f, 0x0c, 0xf5, 0xae,
            0x58, 0x01, 0x8f, 0x52,
        ];

        let filter = unsafe { Filter::delineate(&data).unwrap() };

        assert_eq!(filter.num_ids(), 2);
        let mut ids = filter.ids();
        assert_eq!(ids.next().unwrap(), id1);
        assert_eq!(ids.next().unwrap(), id2);
        assert!(ids.next().is_none());

        assert_eq!(filter.num_authors(), 2);
        let mut authors = filter.authors();
        assert_eq!(authors.next().unwrap(), pk1);
        assert_eq!(authors.next().unwrap(), pk2);
        assert!(authors.next().is_none());

        assert_eq!(filter.num_kinds(), 3);
        let mut kinds = filter.kinds();
        assert_eq!(kinds.next().unwrap(), 1.into());
        assert_eq!(kinds.next().unwrap(), 5.into());
        assert_eq!(kinds.next().unwrap(), 30023.into());
        assert!(kinds.next().is_none());

        assert_eq!(filter.limit(), u32::MAX);
        assert_eq!(filter.since(), 1702161345.into());
        assert_eq!(filter.until(), Time::max());

        let tags = filter.tags().unwrap();
        assert_eq!(tags.count(), 1);
        let mut iter = tags.iter();
        let mut tag = iter.next().unwrap();
        assert!(iter.next().is_none());
        assert_eq!(tag.next().unwrap(), b"p");
        let p_bytes = tag.next().unwrap();
        assert!(tag.next().is_none());
        let pk: Pubkey = p_bytes.try_into().unwrap();
        assert_eq!(pk, tagged);
    }

    #[test]
    fn test_parse_json_empty_filter() {
        let json = br##"{}"##;
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);
        let (consumed, size) = parse_json_filter(&json[..], &mut buffer).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(size, 36);
        assert_eq!(
            &buffer[0..size],
            &[
                36, 0, 0, 0, // length
                0, 0, // 0 ids
                0, 0, // 0 authors
                0, 0, // 0 kinds
                0, 0, // padding
                255, 255, 255, 255, // max limit
                0, 0, 0, 0, 0, 0, 0, 0, // since 1970
                255, 255, 255, 255, 255, 255, 255, 255, // until max unixtime
                4, 0, 0, 0, // empty tags section
            ]
        );
    }

    #[test]
    fn test_parse_json_filter1() {
        let json = br##"{"kinds":[1,30023],"since":1681778790,"authors":["e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"],"until":1704238196,"ids" : [ "7089afc2e77f366bc0fd1662e4048f59f18391c04a35957f21bbd1f3e6a492c4"],"limit":10}"##;
        // ,"#e":"a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7"}"##;
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);
        let (consumed, size) = parse_json_filter(&json[..], &mut buffer).unwrap();
        assert_eq!(consumed, json.len());
        assert_eq!(size, 136);
        assert_eq!(
            &buffer[0..size],
            &[
                136, 0, 0, 0, // length
                1, 0, // 0 ids
                2, 0, // 0 authors
                2, 0, // 0 kinds
                0, 0, // padding
                10, 0, 0, 0, // max limit 10
                102, 232, 61, 100, 0, 0, 0, 0, // since 1681778790
                116, 156, 148, 101, 0, 0, 0, 0, // until 1704238196
                // First ID:
                112, 137, 175, 194, 231, 127, 54, 107, 192, 253, 22, 98, 228, 4, 143, 89, 241, 131,
                145, 192, 74, 53, 149, 127, 33, 187, 209, 243, 230, 164, 146, 196,
                // First author:
                226, 204, 247, 207, 32, 64, 63, 63, 42, 74, 85, 179, 40, 240, 222, 59, 227, 133, 88,
                167, 213, 243, 54, 50, 253, 170, 239, 199, 38, 193, 200, 235,
                // Second author:
                44, 134, 171, 204, 152, 247, 253, 138, 103, 80, 170, 184, 223, 108, 24, 99, 144, 63,
                16, 114, 6, 204, 45, 114, 232, 175, 235, 108, 56, 53, 122, 237, // Kinds,
                1, 0, // 1
                71, 117, // 30023
                4, 0, 0, 0, // empty tags section
            ]
        );
    }

    #[test]
    fn test_parse_json_filter2() {
        let json = br##"{"kinds":[1,30023],"since":1681778790,"authors":["e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"],"until":1704238196,"ids" : [ "7089afc2e77f366bc0fd1662e4048f59f18391c04a35957f21bbd1f3e6a492c4"],"limit":10, "#e":["a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7"]}"##;
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);
        let (consumed, size) = parse_json_filter(&json[..], &mut buffer).unwrap();
        assert_eq!(consumed, json.len());
        assert_eq!(size, 209);
        assert_eq!(
            &buffer[0..size],
            &[
                209, 0, 0, 0, // length
                1, 0, // 0 ids
                2, 0, // 0 authors
                2, 0, // 0 kinds
                0, 0, // padding
                10, 0, 0, 0, // max limit 10
                102, 232, 61, 100, 0, 0, 0, 0, // since 1681778790
                116, 156, 148, 101, 0, 0, 0, 0, // until 1704238196
                // First ID:
                112, 137, 175, 194, 231, 127, 54, 107, 192, 253, 22, 98, 228, 4, 143, 89, 241, 131,
                145, 192, 74, 53, 149, 127, 33, 187, 209, 243, 230, 164, 146, 196,
                // First author:
                226, 204, 247, 207, 32, 64, 63, 63, 42, 74, 85, 179, 40, 240, 222, 59, 227, 133, 88,
                167, 213, 243, 54, 50, 253, 170, 239, 199, 38, 193, 200, 235,
                // Second author:
                44, 134, 171, 204, 152, 247, 253, 138, 103, 80, 170, 184, 223, 108, 24, 99, 144, 63,
                16, 114, 6, 204, 45, 114, 232, 175, 235, 108, 56, 53, 122, 237, // Kinds,
                1, 0, // 1
                71, 117, // 30023
                // Tag section:
                77, 0, // tags section length is 77
                1, 0, // just one tag
                6, 0, // offset of 0th tag is 6
                // First tag:
                2, 0, // 2 fields
                // Field 1:
                1, 0,   // 1 byte long
                101, // 'e'
                // Field 2:
                64, 0, // 64 bytes long
                97, 57, 54, 54, 51, 48, 53, 53, 49, 54, 52, 97, 98, 56, 98, 51, 48, 100, 57, 53,
                50, 52, 54, 53, 54, 51, 55, 48, 99, 52, 98, 102, 57, 51, 51, 57, 51, 98, 98, 48,
                53, 49, 98, 55, 101, 100, 102, 52, 53, 53, 54, 102, 52, 48, 99, 53, 50, 57, 56,
                100, 99, 48, 99, 55
            ]
        );
    }

    #[test]
    fn test_filter_parse_and_check() {
        let json = br##"{"kinds":[1,5,9,30023],"since":1681778790,"authors":["e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"], "#e":["a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"],"#p":["2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"]}"##;
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);
        let (consumed, size) = parse_json_filter(&json[..], &mut buffer).unwrap();
        assert_eq!(consumed, json.len());
        assert_eq!(size, 452);
        let filter = unsafe { Filter::delineate(&buffer).unwrap() };
        assert_eq!(filter.len(), 452);
        assert_eq!(filter.num_ids(), 0);

        assert_eq!(filter.num_authors(), 2);
        let mut author_iter = filter.authors();
        assert_eq!(
            author_iter.next(),
            Some(
                Pubkey::read_hex(
                    b"e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"
                )
                .unwrap()
            )
        );
        assert_eq!(
            author_iter.next(),
            Some(
                Pubkey::read_hex(
                    b"2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"
                )
                .unwrap()
            )
        );
        assert_eq!(author_iter.next(), None);

        assert_eq!(filter.num_kinds(), 4);
        let mut kind_iter = filter.kinds();
        assert_eq!(kind_iter.next(), Some(1.into()));
        assert_eq!(kind_iter.next(), Some(5.into()));
        assert_eq!(kind_iter.next(), Some(9.into()));
        assert_eq!(kind_iter.next(), Some(30023.into()));
        assert_eq!(kind_iter.next(), None);

        assert_eq!(filter.limit(), u32::MAX);
        assert_eq!(filter.since(), 1681778790.into());
        assert_eq!(filter.until(), Time::max());

        let tags: &Tags = filter.tags().unwrap();
        let mut tag_iter: TagsIter = tags.iter();
        let mut tag1_iter: TagsStringIter = tag_iter.next().unwrap();
        assert_eq!(tag1_iter.next(), Some(b"e".as_slice()));
        assert_eq!(
            tag1_iter.next(),
            Some(b"a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7".as_slice())
        );
        assert_eq!(
            tag1_iter.next(),
            Some(b"2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed".as_slice())
        );
        assert_eq!(tag1_iter.next(), None);
        let mut tag2_iter = tag_iter.next().unwrap();
        assert_eq!(tag2_iter.next(), Some(b"p".as_slice()));
        assert_eq!(
            tag2_iter.next(),
            Some(b"2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed".as_slice())
        );
        assert_eq!(
            tag2_iter.next(),
            Some(b"2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed".as_slice())
        );
        assert_eq!(
            tag2_iter.next(),
            Some(b"2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed".as_slice())
        );
        assert_eq!(tag2_iter.next(), None);
        assert!(tag_iter.next().is_none());
    }

    #[test]
    fn test_filter_hyperloglog_offset() {
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);

        /*
        // Not a filter we can HLL count
        let json = br##"{"kinds": [3], "#a": ["30023:a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7:sandwiches","30023:a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7:drinks"]}]"##;
        let _ = parse_json_filter(&json[..], &mut buffer).unwrap();
        let filter = unsafe { Filter::delineate(&buffer).unwrap() };
        assert_eq!(filter.hyperloglog_offset().unwrap(), None);
         */

        // Test count followers
        let json = br##"{"kinds": [3], "#p": ["a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7"]}]"##;
        //                                     012345678901234567890123456789012 (gives us 9 + 8 = 17)
        let _ = parse_json_filter(&json[..], &mut buffer).unwrap();
        let filter = unsafe { Filter::delineate(&buffer).unwrap() };
        assert_eq!(filter.hyperloglog_offset().unwrap(), Some(17));

        // Test count reactions
        let json = br##"{"kinds": [7], "#e": ["a9663055164ab8b30d9524656371c4bf63393bb051b7edf4556f40c5298dc0c7"]}]"##;
        //                                     012345678901234567890123456789012 (gives us 6 + 8 = 14)
        let _ = parse_json_filter(&json[..], &mut buffer).unwrap();
        let filter = unsafe { Filter::delineate(&buffer).unwrap() };
        assert_eq!(filter.hyperloglog_offset().unwrap(), Some(14));
    }
}
