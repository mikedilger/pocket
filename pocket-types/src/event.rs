use super::{Id, Kind, Pubkey, Sig, Tags, Time};
use crate::error::{Error, InnerError};
use crate::json::json_escape;
use crate::json::json_parse::*;
use std::cmp::Ordering;
use std::fmt;
use std::ops::{Deref, DerefMut};

/*
 * 0 [4 bytes] length of the event structure
 * 4 [2 bytes] kind
 * 6 [2 bytes] PADDING
 * 8 [8 bytes] created_at
 * 16 [32 bytes] id
 * 48 [32 bytes] pubkey
 * 80 [64 bytes] sig
 * 144 [T bytes] Tags
 * 144+T [4 bytes] content length
 * 144+T+4 [C bytes] content
 * 144+T+4+C <--- beginning of region beyond the event
 */

/// A nostr Event
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Event([u8]);

#[allow(clippy::len_without_is_empty)]
impl Event {
    fn from_inner<S: AsRef<[u8]> + ?Sized>(s: &S) -> &Event {
        // SAFETY: Event is just a wrapper around [u8],
        // therefore converting &mut [u8] to &mut Event is safe.
        unsafe { &*(s.as_ref() as *const [u8] as *const Event) }
    }

    fn from_inner_mut(inner: &mut [u8]) -> &mut Event {
        // SAFETY: Event is just a wrapper around [u8],
        // therefore converting &mut [u8] to &mut Event is safe.
        unsafe { &mut *(inner as *mut [u8] as *mut Event) }
    }

    /// Presuming the input is the start of an Event slice, this determines the end
    /// and returns the wrapped `Event` type. It does not validate that it is
    /// accurate.
    ///
    /// # Safety
    /// Be sure the input is a valid Event slice
    pub unsafe fn delineate(input: &[u8]) -> Result<&Event, Error> {
        if input.len() < 144 + 4 + 4 {
            return Err(InnerError::EndOfInput.into());
        }
        let len = parse_u32!(input, 0) as usize;
        if input.len() < len {
            return Err(InnerError::EndOfInput.into());
        }
        Ok(Self::from_inner(&input[0..len]))
    }

    /// Copy to an allocated owned data type
    pub fn to_owned(&self) -> OwnedEvent {
        OwnedEvent(self.0.to_owned())
    }

    /// Parse JSON input into an Event.
    ///
    /// Returns the count of consumed input bytes and the Event
    pub fn from_json<'a>(
        json: &[u8],
        output_buffer: &'a mut [u8],
    ) -> Result<(usize, &'a Event), Error> {
        let (incount, outcount) = parse_json_event(json, output_buffer)?;
        Ok((incount, Self::from_inner(&output_buffer[..outcount])))
    }

    /// Build an event from parts
    ///
    /// This is not for creating a new event (hence there is no private key or signature
    /// generation), this is for translating from other event structures
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts<'a>(
        id: Id,
        kind: Kind,
        pubkey: Pubkey,
        sig: Sig,
        tags: &Tags,
        created_at: Time,
        content: &[u8],
        output: &'a mut [u8],
    ) -> Result<&'a Event, Error> {
        let taglen = tags.as_bytes().len();
        let contentlen = content.len();
        let length = Self::output_size_needed(taglen, contentlen);
        if output.len() < length {
            return Err(InnerError::BufferTooSmall(length).into());
        }

        // length
        output[0..4].copy_from_slice((length as u32).to_ne_bytes().as_slice());

        // kind
        output[4..6].copy_from_slice(kind.as_ref().to_ne_bytes().as_slice());

        // zero-padding
        output[6] = 0;
        output[7] = 0;

        // created_at
        output[8..16].copy_from_slice(created_at.as_ref().to_ne_bytes().as_slice());

        // id
        output[16..48].copy_from_slice(id.as_slice());

        // pubkey
        output[48..80].copy_from_slice(pubkey.as_slice());

        // sig
        output[80..144].copy_from_slice(sig.as_slice());

        // tags
        output[144..144 + taglen].copy_from_slice(tags.as_bytes());

        // content len
        output[144 + taglen..144 + taglen + 4]
            .copy_from_slice((contentlen as u32).to_ne_bytes().as_slice());

        // content
        output[144 + taglen + 4..144 + taglen + 4 + contentlen].copy_from_slice(content);

        Ok(Self::from_inner(&output[..length]))
    }

    /// The number of bytes needed to represent an event with such parameters
    pub fn output_size_needed(tagslen: usize, contentlen: usize) -> usize {
        144 + tagslen + 4 + contentlen
    }

    /// This copies the internal bytes of this event
    pub fn copy(&self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < self.0.len() {
            return Err(InnerError::BufferTooSmall(self.0.len()).into());
        }
        output[..self.0.len()].copy_from_slice(&self.0);
        Ok(self.0.len())
    }

    /// The internal bytes representation of this Event
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// How many bytes this serialized event consumes
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The Kind of this event
    pub fn kind(&self) -> Kind {
        parse_u16!(self.0, 4).into()
    }

    /// The created_at Time of this event
    pub fn created_at(&self) -> Time {
        parse_u64!(self.0, 8).into()
    }

    /// The Id of this event
    pub fn id(&self) -> Id {
        let inner: [u8; 32] = self.0[16..16 + 32].try_into().unwrap();
        inner.into()
    }

    /// The Pubkey (author) of this event
    pub fn pubkey(&self) -> Pubkey {
        let inner: [u8; 32] = self.0[48..48 + 32].try_into().unwrap();
        inner.into()
    }

    /// The Sig of this event
    pub fn sig(&self) -> Sig {
        let inner: [u8; 64] = self.0[80..80 + 64].try_into().unwrap();
        inner.into()
    }

    /// The Tags of this event
    pub fn tags(&self) -> Result<&Tags, Error> {
        unsafe { Tags::delineate(&self.0[144..]) }
    }

    /// The content of this event
    pub fn content(&self) -> &[u8] {
        let t = parse_u16!(self.0, 144) as usize;
        let c = parse_u32!(self.0, 144 + t) as usize;
        &self.0[144 + t + 4..144 + t + 4 + c]
    }

    /// Output json bytes for this nostr event
    pub fn as_json(&self) -> Result<Vec<u8>, Error> {
        let mut output: Vec<u8> = Vec::with_capacity(256);
        output.extend(br#"{"id":""#);
        let pos = output.len();
        output.resize(pos + 64, 0);
        self.id().write_hex(&mut output[pos..]).unwrap();
        output.extend(br#"","pubkey":""#);
        let pos = output.len();
        output.resize(pos + 64, 0);
        self.pubkey().write_hex(&mut output[pos..]).unwrap();
        output.extend(br#"","kind":"#);
        output.extend(format!("{}", self.kind().deref()).as_bytes());
        output.extend(br#","created_at":"#);
        output.extend(format!("{}", self.created_at().deref()).as_bytes());
        output.extend(br#","tags":"#);
        output.extend(self.tags()?.as_json());
        output.extend(br#","content":""#);
        // This is okay if it is not accurate. It generally avoids
        // lots of little mallocs when the capacity is already allocated
        output.reserve(self.content().len() * 7 / 6);
        let mut output = json_escape(self.content(), output)?;
        output.extend(br#"","sig":""#);
        let pos = output.len();
        output.resize(pos + 128, 0);
        self.sig().write_hex(&mut output[pos..]).unwrap();
        output.extend(br#""}"#);
        Ok(output)
    }

    /// Verify the validity of this event
    pub fn verify(&self) -> Result<(), Error> {
        use secp256k1::hashes::{sha256, Hash};
        use secp256k1::schnorr::Signature;
        use secp256k1::{Message, XOnlyPublicKey};

        // This is okay if it is not accurate. It generally avoids
        // lots of little mallocs when the capacity is already allocated
        let escaped_content = Vec::with_capacity(self.content().len() * 7 / 6);
        let escaped_content = json_escape(self.content(), escaped_content)?;

        let signable = format!(
            r#"[0,"{}",{},{},{},"{}"]"#,
            self.pubkey(),
            self.created_at(),
            self.kind(),
            self.tags()?,
            unsafe { std::str::from_utf8_unchecked(&escaped_content[..]) },
        );

        drop(escaped_content);

        let hash = sha256::Hash::hash(signable.as_bytes());

        let hashref = <sha256::Hash as AsRef<[u8]>>::as_ref(&hash);
        if hashref != self.id().as_slice() {
            return Err(InnerError::BadEventId.into());
        }

        let pubkey = XOnlyPublicKey::from_slice(self.pubkey().as_slice())?;
        let sig = Signature::from_slice(self.sig().as_slice())?;
        let message = Message::from_digest_slice(hashref)?;
        sig.verify(&message, &pubkey)?;

        Ok(())
    }

    /// Whether the event is expired (NIP-40)
    pub fn is_expired(&self) -> Result<bool, Error> {
        for mut tag in self.tags()?.iter() {
            if tag.next() == Some(b"expiration") {
                if let Some(expires) = tag.next() {
                    // Interpret string as a u64
                    let mut p = 0;
                    let time = read_u64(expires, &mut p)?;
                    if time <= *Time::now().deref() {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(bytes) = self.as_json() {
            let s = unsafe { std::str::from_utf8_unchecked(&bytes) };
            write!(f, "{s}")
        } else {
            write!(f, "{{Corrupted Event}}")
        }
    }
}

impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Event {
    fn cmp(&self, other: &Self) -> Ordering {
        self.created_at()
            .cmp(&other.created_at())
            .then(self.id().cmp(&other.id()))
    }
}

/// A memory-allocated owned event
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OwnedEvent(pub Vec<u8>);

impl OwnedEvent {
    /// Create a new memory-allocated owned event
    pub fn new(
        id: Id,
        kind: Kind,
        pubkey: Pubkey,
        sig: Sig,
        tags: &Tags,
        created_at: Time,
        content: &[u8],
    ) -> Result<OwnedEvent, Error> {
        let size = Event::output_size_needed(tags.as_bytes().len(), content.len());
        let mut buffer = vec![0; size];
        let _event = Event::from_parts(
            id,
            kind,
            pubkey,
            sig,
            tags,
            created_at,
            content,
            &mut buffer,
        )?;
        Ok(OwnedEvent(buffer))
    }

    /// Create a new memory-allocated owned event with a private key
    pub fn sign_new(
        keypair: &secp256k1::Keypair,
        kind: Kind,
        tags: &Tags,
        created_at: Time,
        content: &[u8],
    ) -> Result<OwnedEvent, Error> {
        use secp256k1::hashes::{sha256, Hash};
        use secp256k1::Message;

        let (xonlypubkey, _parity) = keypair.x_only_public_key();
        let pubkey = Pubkey::from_bytes(xonlypubkey.serialize());

        let escaped_content = Vec::with_capacity(content.len() * 7 / 6);
        let escaped_content = json_escape(content, escaped_content)?;
        let signable = format!(
            r#"[0,"{}",{},{},{},"{}"]"#,
            pubkey,
            created_at,
            kind,
            tags,
            unsafe { std::str::from_utf8_unchecked(&escaped_content[..]) },
        );
        drop(escaped_content);

        let hash = sha256::Hash::hash(signable.as_bytes());
        let hashref = <sha256::Hash as AsRef<[u8; 32]>>::as_ref(&hash);
        let id = Id::from_bytes(*hashref);
        let message = Message::from_digest_slice(hashref)?;
        let signature = keypair.sign_schnorr(message);
        let sig = Sig::from_bytes(signature.serialize());
        Self::new(id, kind, pubkey, sig, tags, created_at, content)
    }
}

impl Deref for OwnedEvent {
    type Target = Event;

    fn deref(&self) -> &Self::Target {
        Event::from_inner(&self.0)
    }
}

impl DerefMut for OwnedEvent {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Event::from_inner_mut(&mut self.0)
    }
}

// Parses a JSON event from the `input` buffer.
// Places the parsed event into the `output` buffer.
// Returns the count of consumed bytes and output bytes
fn parse_json_event(input: &[u8], output: &mut [u8]) -> Result<(usize, usize), Error> {
    // Minimum-sized JSON event is 204 characters long
    if input.len() < 204 {
        return Err(InnerError::JsonBadEvent("Too Short", 0).into());
    }

    // NOTE: 152 is the minimum binary event
    if output.len() < 152 {
        return Err(InnerError::BufferTooSmall(152).into());
    }

    // This tracks where we are currently looking in the input as we scan forward.
    // It is short for INput POSition.
    let mut inpos = 0;

    // If tags comes before content, content can use this to know where to put itself.
    // This is the length of the tags output section. 0 means it hasn't been written yet.
    let mut tags_size: usize = 0;

    // If content comes before tags, we cannot write it because we don't know how much
    // space Tags will take.  So we instead just remember where the content string
    // begins so we can write it later.
    let mut content_input_start: usize = 0;

    // Remember which fields we have read using bit flags.
    // We must get all seven of these fields for an event to be valid.
    const HAVE_ID: u8 = 0x1 << 0;
    const HAVE_PUBKEY: u8 = 0x1 << 1;
    const HAVE_SIG: u8 = 0x1 << 2;
    const HAVE_CREATED_AT: u8 = 0x1 << 3;
    const HAVE_KIND: u8 = 0x1 << 4;
    const HAVE_CONTENT: u8 = 0x1 << 5;
    const HAVE_TAGS: u8 = 0x1 << 6;
    let mut complete: u8 = 0;

    eat_whitespace(input, &mut inpos);
    verify_char(input, b'{', &mut inpos)?;
    loop {
        eat_whitespace(input, &mut inpos);

        // Presuming that we must have at least one field, we don't have to look
        // for the end of the object yet.

        // Move to the start of the field name
        verify_char(input, b'"', &mut inpos)?;

        // No matter which field is next, we need at least 7 bytes for the smallest
        // field and value: kind":1
        // This allows us to skip length tests below that are shorter than inpos+7
        if inpos + 7 > input.len() {
            return Err(InnerError::JsonBadEvent("Too Short or Missing Fields", inpos).into());
        }

        if &input[inpos..inpos + 3] == b"id\"" {
            if complete & HAVE_ID == HAVE_ID {
                return Err(InnerError::JsonBadEvent("Duplicate id field", inpos).into());
            }
            inpos += 3;
            eat_colon_with_whitespace(input, &mut inpos)?;
            read_id(input, &mut inpos, &mut output[16..48])?;
            complete |= HAVE_ID;
        } else if &input[inpos..inpos + 4] == b"sig\"" {
            if complete & HAVE_SIG == HAVE_SIG {
                return Err(InnerError::JsonBadEvent("Duplicate sig field", inpos).into());
            }
            inpos += 4;
            eat_colon_with_whitespace(input, &mut inpos)?;
            read_sig(input, &mut inpos, output)?;
            complete |= HAVE_SIG;
        } else if &input[inpos..inpos + 5] == b"kind\"" {
            if complete & HAVE_KIND == HAVE_KIND {
                return Err(InnerError::JsonBadEvent("Duplicate kind field", inpos).into());
            }
            inpos += 5;
            eat_colon_with_whitespace(input, &mut inpos)?;
            let kind = read_kind(input, &mut inpos)?;
            output[4..6].copy_from_slice(kind.to_ne_bytes().as_slice());
            complete |= HAVE_KIND;
        } else if &input[inpos..inpos + 5] == b"tags\"" {
            if complete & HAVE_TAGS == HAVE_TAGS {
                return Err(InnerError::JsonBadEvent("Duplicate tags field", inpos).into());
            }
            inpos += 5;
            eat_colon_with_whitespace(input, &mut inpos)?;
            tags_size = read_tags_array(input, &mut inpos, &mut output[144..])?;
            complete |= HAVE_TAGS;
            if content_input_start != 0 {
                // Content was found earlier than tags.
                // Now that tags have been read, we should read the content
                read_content(input, &mut content_input_start, output, 144 + tags_size)?;
                complete |= HAVE_CONTENT;
            }
        } else if &input[inpos..inpos + 7] == b"pubkey\"" {
            if complete & HAVE_PUBKEY == HAVE_PUBKEY {
                return Err(InnerError::JsonBadEvent("Duplicate pubkey field", inpos).into());
            }
            inpos += 7;
            eat_colon_with_whitespace(input, &mut inpos)?;
            read_pubkey(input, &mut inpos, &mut output[48..80])?;
            complete |= HAVE_PUBKEY;
        } else if inpos + 8 <= input.len() && &input[inpos..inpos + 8] == b"content\"" {
            if complete & HAVE_CONTENT == HAVE_CONTENT {
                return Err(InnerError::JsonBadEvent("Duplicate pubkey field", inpos).into());
            }
            inpos += 8;
            eat_colon_with_whitespace(input, &mut inpos)?;
            if tags_size == 0 {
                // Oops, we haven't read the tags yet. That means we don't yet know where
                // to place the content.  In this case we just remember the offset where
                // this needs to be done, so we can do this later.
                content_input_start = inpos;
                // skip past it so we can read the subsequent fields
                verify_char(input, b'"', &mut inpos)?;
                burn_string(input, &mut inpos)?;
            } else {
                read_content(input, &mut inpos, output, 144 + tags_size)?;
                complete |= HAVE_CONTENT;
            }
        } else if inpos + 11 <= input.len() && &input[inpos..inpos + 11] == b"created_at\"" {
            if complete & HAVE_CREATED_AT == HAVE_CREATED_AT {
                return Err(InnerError::JsonBadEvent("Duplicate created_at field", inpos).into());
            }
            inpos += 11;
            eat_colon_with_whitespace(input, &mut inpos)?;
            let u = read_u64(input, &mut inpos)?;
            output[8..16].copy_from_slice(u.to_ne_bytes().as_slice());
            complete |= HAVE_CREATED_AT;
        } else {
            burn_key_and_value(input, &mut inpos)?;
        }

        // get past the comma, or detect the close brace and exit
        if next_object_field(input, &mut inpos)? {
            break;
        }
    }

    if complete == 0b0111_1111 {
        Ok((
            inpos,
            u32::from_ne_bytes(output[0..4].try_into().unwrap()) as usize,
        ))
    } else {
        Err(InnerError::JsonBadEvent("Missing Fields", inpos).into())
    }
}

#[cfg(test)]
mod test {
    use super::Event;

    #[test]
    fn test_event_expired() {
        let json = br#"{"id":"8b8b1d98f279b43f571ce55dce7cc51ced0c24e9558bfdaa0be0467f82f64708","pubkey":"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49","created_at":1712693549,"kind":1,"sig":"870497b1a254f2394a692decd46b5cffa044302179a42e985697b488fc408118c9ff7c5578d85393474c1a025f28c869148968ee3229aa24425800ae54f54e51","content":"He got snowed in","tags":[["expiration","1712693529"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["e","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","wss://nostr-pub.wellorder.net/","root"]]}"#;
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);
        let (_size, event) = Event::from_json(json.as_slice(), &mut buffer).unwrap();
        assert_eq!(event.is_expired().unwrap(), true); // In the past

        let json = br#"{"id":"120b3d99f889c6147972b0256413e84b0b7b7862a705964b7302f5392677e52a","pubkey":"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49","created_at":1712693868,"kind":1,"sig":"ed0463b822f76f63c392b00d4a66c297f5e13371c800b139f2d40174bf77146201f29ae6e3a9da71a9346416d8b2ba4d2f5a2be693a9e75a91a33abfdc43ec71","content":"He got snowed in","tags":[["expiration","99712693529"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["e","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","wss://nostr-pub.wellorder.net/","root"]]}"#;
        let (_size, event) = Event::from_json(json.as_slice(), &mut buffer).unwrap();
        assert_eq!(event.is_expired().unwrap(), false); // Too far in the future

        let json = br#"{"kind":1,"pubkey":"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49","created_at":1681778790,"sig":"4dfea1a6f73141d5691e43afc3234dbe73016db0fb207cf247e0127cc2591ee6b4be5b462272030a9bde75882aae810f359682b1b6ce6cbb97201141c576db42","tags":[["client","gossip"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["e","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","wss://nostr-pub.wellorder.net/","root"]],"id":"a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7","content":"He got snowed in"}"#;
        let (_size, event) = Event::from_json(json.as_slice(), &mut buffer).unwrap();
        assert_eq!(event.is_expired().unwrap(), false); // Doesn't have the expiration tag
    }

    #[test]
    fn test_event_from_parts() {
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);

        let json = br#"{"kind":1,"pubkey":"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49","created_at":1681778790,"sig":"4dfea1a6f73141d5691e43afc3234dbe73016db0fb207cf247e0127cc2591ee6b4be5b462272030a9bde75882aae810f359682b1b6ce6cbb97201141c576db42","tags":[["client","gossip"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["e","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","wss://nostr-pub.wellorder.net/","root"]],"id":"a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7","content":"He got snowed in"}"#;
        let (size, event) = Event::from_json(json.as_slice(), &mut buffer).unwrap();

        let mut output: Vec<u8> = Vec::with_capacity(size);
        output.resize(size, 0);
        let event2 = Event::from_parts(
            event.id(),
            event.kind(),
            event.pubkey(),
            event.sig(),
            event.tags().unwrap(),
            event.created_at(),
            event.content(),
            &mut output,
        )
        .unwrap();

        assert_eq!(event, event2);
    }

    #[test]
    fn test_parse_json_event() {
        if 256_u16.to_ne_bytes() == [1, 0] {
            test_parse_json_event_big_endian();
        } else {
            test_parse_json_event_little_endian();
        }
    }

    fn test_parse_json_event_little_endian() {
        let json = br#"{"id":"a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7","pubkey":"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49","created_at":1681778790,"kind":1,"sig":"4dfea1a6f73141d5691e43afc3234dbe73016db0fb207cf247e0127cc2591ee6b4be5b462272030a9bde75882aae810f359682b1b6ce6cbb97201141c576db42","content":"He got snowed in","tags":[["client","gossip"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["e","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","wss://nostr-pub.wellorder.net/","root"]]}"#;
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);
        let (_insize, event) = Event::from_json(&json[..], &mut buffer).unwrap();
        assert_eq!(event.len(), 372);
        assert_eq!(
            event.as_bytes(),
            &[
                116, 1, 0, 0, // 372 bytes long
                1, 0, // kind 1
                0, 0, // padding
                102, 232, 61, 100, 0, 0, 0, 0, // created at 1681778790
                169, 102, 48, 85, 22, 74, 184, 179, 13, 149, 36, 101, 99, 112, 196, 191, 147, 57,
                59, 176, 81, 183, 237, 244, 85, 111, 64, 197, 41, 141, 192, 199, // id
                238, 17, 165, 223, 244, 12, 25, 165, 85, 244, 31, 228, 43, 72, 240, 14, 97, 140,
                145, 34, 86, 34, 174, 55, 182, 194, 187, 103, 183, 108, 78, 73, // pubkey
                77, 254, 161, 166, 247, 49, 65, 213, 105, 30, 67, 175, 195, 35, 77, 190, 115, 1,
                109, 176, 251, 32, 124, 242, 71, 224, 18, 124, 194, 89, 30, 230, 180, 190, 91, 70,
                34, 114, 3, 10, 155, 222, 117, 136, 42, 174, 129, 15, 53, 150, 130, 177, 182, 206,
                108, 187, 151, 32, 17, 65, 197, 118, 219, 66, // sig
                // 144:
                208, 0, // tags section is 208 bytes long
                3, 0, // there are three tags
                10, 0, // first tag is at offset 10
                28, 0, // second tag is at offset 28
                99, 0, // third tag is at offset 99
                // 154: (144+10)
                2, 0, // the first tag has 2 strings
                6, 0, // the first string is 6 bytes long
                99, 108, 105, 101, 110, 116, // "client"
                6, 0, // the second string is 6 bytes long
                103, 111, 115, 115, 105, 112, // "gossip"
                // 172: (144+28)
                2, 0, // the second tag has two strings
                1, 0,   // the first string is 1 char long
                112, // "p"
                64, 0, // the second string is 64 bytes long
                101, 50, 99, 99, 102, 55, 99, 102, 50, 48, 52, 48, 51, 102, 51, 102, 50, 97, 52,
                97, 53, 53, 98, 51, 50, 56, 102, 48, 100, 101, 51, 98, 101, 51, 56, 53, 53, 56, 97,
                55, 100, 53, 102, 51, 51, 54, 51, 50, 102, 100, 97, 97, 101, 102, 99, 55, 50, 54,
                99, 49, 99, 56, 101,
                98, // "e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"
                // 243: (144+99)
                4, 0, // the third tag has 4 strings
                1, 0,   // the first string is 1 char long
                101, // "e"
                64, 0, // the second string is 64 bytes long
                50, 99, 56, 54, 97, 98, 99, 99, 57, 56, 102, 55, 102, 100, 56, 97, 54, 55, 53, 48,
                97, 97, 98, 56, 100, 102, 54, 99, 49, 56, 54, 51, 57, 48, 51, 102, 49, 48, 55, 50,
                48, 54, 99, 99, 50, 100, 55, 50, 101, 56, 97, 102, 101, 98, 54, 99, 51, 56, 51, 53,
                55, 97, 101,
                100, // "2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"
                30, 0, // the third string is 30 bytes long
                119, 115, 115, 58, 47, 47, 110, 111, 115, 116, 114, 45, 112, 117, 98, 46, 119, 101,
                108, 108, 111, 114, 100, 101, 114, 46, 110, 101, 116,
                47, //  "wss://nostr-pub.wellorder.net/"
                4, 0, // the fourth string is 4 bytes long
                114, 111, 111, 116, // "root"
                // 352: (144+208)
                16, 0, 0, 0, // the content is 16 bytes long
                72, 101, 32, 103, 111, 116, 32, 115, 110, 111, 119, 101, 100, 32, 105,
                110, // "He got snowed in"

                     // 372:
            ]
        );

        // Same event in a different order
        let json2 = br#"{"kind":1,"pubkey":"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49","created_at":1681778790,"sig":"4dfea1a6f73141d5691e43afc3234dbe73016db0fb207cf247e0127cc2591ee6b4be5b462272030a9bde75882aae810f359682b1b6ce6cbb97201141c576db42","tags":[["client","gossip"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["e","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","wss://nostr-pub.wellorder.net/","root"]],"id":"a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7","content":"He got snowed in"}"#;
        let mut buffer2: Vec<u8> = Vec::with_capacity(4096);
        buffer2.resize(4096, 0);
        let (_insize, event) = Event::from_json(&json2[..], &mut buffer2).unwrap();
        assert_eq!(event.len(), 372);
        assert_eq!(&buffer[..372], &buffer2[..372]);
    }

    fn test_parse_json_event_big_endian() {
        let json = br#"{"id":"a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7","pubkey":"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49","created_at":1681778790,"kind":1,"sig":"4dfea1a6f73141d5691e43afc3234dbe73016db0fb207cf247e0127cc2591ee6b4be5b462272030a9bde75882aae810f359682b1b6ce6cbb97201141c576db42","content":"He got snowed in","tags":[["client","gossip"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["e","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","wss://nostr-pub.wellorder.net/","root"]]}"#;
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);
        let (_insize, event) = Event::from_json(&json[..], &mut buffer).unwrap();
        assert_eq!(event.len(), 372);
        assert_eq!(
            event.as_bytes(),
            &[
                0, 0, 1, 116, // 372 bytes long
                0, 1, // kind 1
                0, 0, // padding
                0, 0, 0, 0, 100, 61, 232, 102, // created at 1681778790
                169, 102, 48, 85, 22, 74, 184, 179, 13, 149, 36, 101, 99, 112, 196, 191, 147, 57,
                59, 176, 81, 183, 237, 244, 85, 111, 64, 197, 41, 141, 192, 199, // id
                238, 17, 165, 223, 244, 12, 25, 165, 85, 244, 31, 228, 43, 72, 240, 14, 97, 140,
                145, 34, 86, 34, 174, 55, 182, 194, 187, 103, 183, 108, 78, 73, // pubkey
                77, 254, 161, 166, 247, 49, 65, 213, 105, 30, 67, 175, 195, 35, 77, 190, 115, 1,
                109, 176, 251, 32, 124, 242, 71, 224, 18, 124, 194, 89, 30, 230, 180, 190, 91, 70,
                34, 114, 3, 10, 155, 222, 117, 136, 42, 174, 129, 15, 53, 150, 130, 177, 182, 206,
                108, 187, 151, 32, 17, 65, 197, 118, 219, 66, // sig
                // 144:
                0, 208, // tags section is 208 bytes long
                3, 0, // there are three tags
                0, 10, // first tag is at offset 10
                0, 28, // second tag is at offset 28
                0, 99, // third tag is at offset 99
                // 154: (144+10)
                0, 2, // the first tag has 2 strings
                0, 6, // the first string is 6 bytes long
                99, 108, 105, 101, 110, 116, // "client"
                0, 6, // the second string is 6 bytes long
                103, 111, 115, 115, 105, 112, // "gossip"
                // 172: (144+28)
                0, 2, // the second tag has two strings
                0, 1,   // the first string is 1 char long
                112, // "p"
                0, 64, // the second string is 64 bytes long
                101, 50, 99, 99, 102, 55, 99, 102, 50, 48, 52, 48, 51, 102, 51, 102, 50, 97, 52,
                97, 53, 53, 98, 51, 50, 56, 102, 48, 100, 101, 51, 98, 101, 51, 56, 53, 53, 56, 97,
                55, 100, 53, 102, 51, 51, 54, 51, 50, 102, 100, 97, 97, 101, 102, 99, 55, 50, 54,
                99, 49, 99, 56, 101,
                98, // "e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"
                // 243: (144+99)
                0, 4, // the third tag has 4 strings
                0, 1,   // the first string is 1 char long
                101, // "e"
                0, 64, // the second string is 64 bytes long
                50, 99, 56, 54, 97, 98, 99, 99, 57, 56, 102, 55, 102, 100, 56, 97, 54, 55, 53, 48,
                97, 97, 98, 56, 100, 102, 54, 99, 49, 56, 54, 51, 57, 48, 51, 102, 49, 48, 55, 50,
                48, 54, 99, 99, 50, 100, 55, 50, 101, 56, 97, 102, 101, 98, 54, 99, 51, 56, 51, 53,
                55, 97, 101,
                100, // "2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"
                0, 30, // the third string is 30 bytes long
                119, 115, 115, 58, 47, 47, 110, 111, 115, 116, 114, 45, 112, 117, 98, 46, 119, 101,
                108, 108, 111, 114, 100, 101, 114, 46, 110, 101, 116,
                47, //  "wss://nostr-pub.wellorder.net/"
                0, 4, // the fourth string is 4 bytes long
                114, 111, 111, 116, // "root"
                // 352: (144+208)
                0, 0, 0, 16, // the content is 16 bytes long
                72, 101, 32, 103, 111, 116, 32, 115, 110, 111, 119, 101, 100, 32, 105,
                110, // "He got snowed in"
                     // 372:
            ]
        );

        // Same event in a different order
        let json2 = br#"{"kind":1,"pubkey":"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49","created_at":1681778790,"sig":"4dfea1a6f73141d5691e43afc3234dbe73016db0fb207cf247e0127cc2591ee6b4be5b462272030a9bde75882aae810f359682b1b6ce6cbb97201141c576db42","tags":[["client","gossip"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["e","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","wss://nostr-pub.wellorder.net/","root"]],"id":"a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7","content":"He got snowed in"}"#;
        let mut buffer2: Vec<u8> = Vec::with_capacity(4096);
        buffer2.resize(4096, 0);
        let (_insize, event) = Event::from_json(&json2[..], &mut buffer2).unwrap();
        assert_eq!(event.len(), 372);
        assert_eq!(&buffer[..372], &buffer2[..372]);
    }

    #[test]
    fn test_sign_new() {
        use crate::{Kind, OwnedEvent, OwnedTags, Time};
        use secp256k1::Keypair;

        let keypair = Keypair::new_global(&mut rand::thread_rng());
        let event = OwnedEvent::sign_new(
            &keypair,
            Kind::from_u16(1),
            &OwnedTags::empty(),
            Time::now(),
            b"This is a test",
        )
        .unwrap();
        event.verify().unwrap();
    }

    #[test]
    fn test_event_with_quote() {
        let json = br#"{"kind":1,"id":"ff54625d37b2baf712e35ce84470fd1330420f0e6580f4d53eb7d9d0cb4f5fa0","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1720663889,"tags":[["t","\""]],"content":"hello from the nostr army knife","sig":"bf7110567b15b4c7231f4c63776bb7a5f382f2f7b1cc8b639fc0cbb7f5ff7b466a73f8ab23974d2c3597861ba70fbecf9f646c2fcfe3859d83a73e73c93db5f9"}"#;
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);
        let (_insize, event) = Event::from_json(&json[..], &mut buffer).unwrap();

        let tags = event.tags().unwrap();
        let tags_json_binary = tags.as_json();
        let s = unsafe { std::str::from_utf8_unchecked(&tags_json_binary) };
        println!("{}", s);
        event.verify().unwrap();
    }
}
