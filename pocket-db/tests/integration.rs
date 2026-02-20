mod error;
use error::Error;

use pocket_db::{InnerError, ScreenResult, Store};
use pocket_types::{Addr, Id, Kind, OwnedEvent, OwnedFilter, OwnedTags, Pubkey, Sig, Time};
use secp256k1::rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use tempfile::TempDir;

struct Author {
    seckey: SecretKey,
    pubkey: PublicKey,
}

impl Author {
    pub fn pubkey(&self) -> Pubkey {
        let (xonlypubkey, _) = self.pubkey.x_only_public_key();
        Pubkey::from_bytes(xonlypubkey.serialize())
    }

    pub fn sign(&self, id: Id) -> Result<Sig, Error> {
        use secp256k1::{Keypair, Message};

        let keypair = Keypair::from_secret_key(secp256k1::SECP256K1, &self.seckey);
        let message = Message::from_digest(id.0)?;
        Ok(Sig::from_bytes(keypair.sign_schnorr(message).serialize()))
    }
}

fn make_author() -> Author {
    let secp = Secp256k1::new();
    let (seckey, pubkey) = secp.generate_keypair(&mut OsRng);
    Author { seckey, pubkey }
}

fn make_event(
    author: &Author,
    kind: Kind,
    tags: &[&[&str]],
    content: &str,
    when: Option<Time>,
) -> Result<OwnedEvent, Error> {
    use secp256k1::hashes::sha256::Hash as Sha256;
    use secp256k1::hashes::Hash;

    let owned_tags = OwnedTags::new(tags).unwrap();
    let pubkey = author.pubkey();
    let created_at = when.unwrap_or(Time::now());
    let id = {
        let signable = format!(
            r#"[0,"{}",{},{},{},"{}"]"#,
            pubkey, created_at, kind, &*owned_tags, &content,
        );
        let hash = Sha256::hash(signable.as_bytes());
        let hashref = <Sha256 as AsRef<[u8]>>::as_ref(&hash);
        let id = Id::from_bytes(hashref.try_into().unwrap());
        id
    };

    let sig = author.sign(id)?;

    let event = OwnedEvent::new(
        id,
        kind,
        pubkey,
        sig,
        &owned_tags,
        created_at,
        content.as_bytes(),
    )?;

    Ok(event)
}

fn setup(kind: Kind, tags: &[&[&str]], content: &str) -> (Store, Author, OwnedEvent, TempDir) {
    let when = Time::now();
    let tempdir = tempfile::tempdir().unwrap();
    let store = Store::new(&tempdir, vec![]).unwrap();
    let author = make_author();
    let e = make_event(&author, kind, tags, content, Some(when)).unwrap();
    let _ = store.store_event(&e).unwrap();
    (store, author, e, tempdir)
}

const TAG_CLIENT: &[&str] = &["client", "chorus-testsuite"];
const TAG_T_NOSTR: &[&str] = &["t", "nostr"];
const TAG_E_TEST: &[&str] = &[
    "e",
    "65f07794c052916f434d2a40ad4e3c58c1c287d829b999977a7221c0ebadab0a",
];

#[test]
fn test_basic_write_and_read_back() {
    let (store, _author, e, _temp) = setup(1.into(), &[TAG_CLIENT], "GM");
    assert!(store.has_event(e.id()).unwrap());
    let maybe_ecopy = store.get_event_by_id(e.id()).unwrap();
    assert!(maybe_ecopy.is_some());
    let ecopy = maybe_ecopy.unwrap();
    assert_eq!(ecopy, &*e);
}

#[test]
fn test_find_by_id() {
    let (store, _author, e, _temp) = setup(1.into(), &[TAG_CLIENT], "GM");
    let mismatch = make_event(&make_author(), 1.into(), &[&[]], "", None).unwrap();
    store.store_event(&mismatch).unwrap();
    let filter =
        OwnedFilter::new(&[e.id()], &[], &[], &OwnedTags::empty(), None, None, None).unwrap();
    let (events, _) = store
        .find_events(&filter, true, 0, 0, |_| ScreenResult::Match)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], &*e);
}

#[test]
fn test_find_by_pubkey_and_kind() {
    let (store, _author, e, _temp) = setup(1.into(), &[TAG_CLIENT], "GM");
    let mismatch = make_event(&make_author(), 1.into(), &[&[]], "", None).unwrap();
    store.store_event(&mismatch).unwrap();
    let filter = OwnedFilter::new(
        &[],
        &[e.pubkey()],
        &[e.kind()],
        &OwnedTags::empty(),
        None,
        None,
        None,
    )
    .unwrap();
    let (events, _) = store
        .find_events(&filter, true, 0, 0, |_| ScreenResult::Match)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], &*e);
}

#[test]
fn test_find_by_pubkey_and_tags() {
    let (store, _author, e, _temp) = setup(1.into(), &[TAG_CLIENT, TAG_E_TEST], "hi!");
    let mismatch = make_event(&make_author(), 1.into(), &[&[]], "", None).unwrap();
    store.store_event(&mismatch).unwrap();
    let tags = OwnedTags::new(&[TAG_E_TEST]).unwrap();
    let filter = OwnedFilter::new(&[], &[e.pubkey()], &[], &tags, None, None, None).unwrap();
    let (events, _) = store
        .find_events(&filter, true, 0, 0, |_| ScreenResult::Match)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], &*e);
}

#[test]
fn test_find_by_kind_and_tags() {
    let (store, _author, e, _temp) = setup(1.into(), &[TAG_CLIENT, TAG_E_TEST], "hi!");
    let mismatch = make_event(&make_author(), 1.into(), &[&[]], "", None).unwrap();
    store.store_event(&mismatch).unwrap();
    let tags = OwnedTags::new(&[TAG_E_TEST]).unwrap();
    let filter = OwnedFilter::new(&[], &[], &[e.kind()], &tags, None, None, None).unwrap();
    let (events, _) = store
        .find_events(&filter, true, 0, 0, |_| ScreenResult::Match)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], &*e);
}

#[test]
fn test_find_by_tags() {
    let (store, _author, e, _temp) = setup(1.into(), &[TAG_CLIENT, TAG_E_TEST], "hi!");
    let mismatch = make_event(&make_author(), 1.into(), &[&[]], "", None).unwrap();
    store.store_event(&mismatch).unwrap();
    let tags = OwnedTags::new(&[TAG_E_TEST]).unwrap();
    let filter = OwnedFilter::new(&[], &[], &[], &tags, None, None, None).unwrap();
    let (events, _) = store
        .find_events(&filter, true, 0, 0, |_| ScreenResult::Match)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], &*e);
}

#[test]
fn test_find_by_pubkey() {
    let (store, _author, e, _temp) = setup(1.into(), &[TAG_CLIENT, TAG_E_TEST], "hi!");
    let mismatch = make_event(&make_author(), 1.into(), &[&[]], "", None).unwrap();
    store.store_event(&mismatch).unwrap();
    let filter = OwnedFilter::new(
        &[],
        &[e.pubkey()],
        &[],
        &OwnedTags::empty(),
        None,
        None,
        None,
    )
    .unwrap();
    let (events, _) = store
        .find_events(&filter, true, 0, 0, |_| ScreenResult::Match)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], &*e);
}

#[test]
fn test_find_by_scrape() {
    let (store, _author, e, _temp) = setup(1.into(), &[TAG_CLIENT, TAG_E_TEST], "hi!");
    let old = Time::from_u64(1500_000_000);
    let mismatch = make_event(&make_author(), 1.into(), &[&[]], "", Some(old)).unwrap();
    store.store_event(&mismatch).unwrap();
    let filter = OwnedFilter::new(
        &[],
        &[],
        &[],
        &OwnedTags::empty(),
        Some(old + 1),
        None,
        None,
    )
    .unwrap();
    let (events, _) = store
        .find_events(&filter, true, 0, 0, |_| ScreenResult::Match)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], &*e);

    let filter = OwnedFilter::new(
        &[],
        &[],
        &[],
        &OwnedTags::empty(),
        Some(old - 1),
        None,
        None,
    )
    .unwrap();
    let (events, _) = store
        .find_events(&filter, true, 0, 0, |_| ScreenResult::Match)
        .unwrap();
    assert_eq!(events.len(), 2);
}

#[test]
fn test_find_replaceable_event() {
    let (store, author, e, _temp) = setup(10003.into(), &[TAG_T_NOSTR], "");
    let e2 = store
        .find_replaceable_event(author.pubkey(), 10003.into())
        .unwrap()
        .unwrap();
    assert_eq!(e2, &*e);
}

#[test]
fn test_find_parameterized_replaceable_event() {
    let (store, author, e, _temp) = setup(30023.into(), &[&["d", "testing"]], "");
    let addr = Addr {
        kind: 30023.into(),
        author: author.pubkey(),
        d: b"testing".to_vec(),
    };
    let e2 = store
        .find_parameterized_replaceable_event(&addr)
        .unwrap()
        .unwrap();
    assert_eq!(e2, &*e);
}

#[test]
fn test_get_event_by_offset() {
    let tempdir = tempfile::tempdir().unwrap();
    let store = Store::new(tempdir, vec![]).unwrap();
    let author = make_author();
    let e = make_event(&author, 1.into(), &[TAG_CLIENT, TAG_E_TEST], "hi!", None).unwrap();
    let offset = store.store_event(&e).unwrap();
    let e2 = store.get_event_by_offset(offset).unwrap();
    assert_eq!(e2, &*e);
}

#[test]
fn test_deleted_by_id_event_is_deleted() {
    let (store, author, e, _temp) = setup(1.into(), &[TAG_CLIENT], "GM");
    let ehexstr = e.id().as_hex_string();

    // Store a delete event
    let del = make_event(&author, 5.into(), &[&["e", &ehexstr]], "", None).unwrap();
    let _ = store.store_event(&del).unwrap();

    // Test that the original event has been deleted
    assert!(!store.has_event(e.id()).unwrap());
    let maybe_ecopy = store.get_event_by_id(e.id()).unwrap();
    assert!(maybe_ecopy.is_none());

    // Test that the delete event remains
    assert!(store.has_event(del.id()).unwrap());
}

#[test]
fn test_cannot_delete_by_id_events_of_others() {
    let (store, _author, e, _temp) = setup(1.into(), &[TAG_CLIENT], "GM");
    let ehexstr = e.id().as_hex_string();

    // Store an invalid delete event (due to wrong author)
    let author2 = make_author();
    let del = make_event(&author2, 5.into(), &[&["e", &ehexstr]], "", None).unwrap();
    let r = store.store_event(&del);
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(matches!(err.inner, InnerError::InvalidDelete));

    // Test has_event() still has original event
    assert!(store.has_event(e.id()).unwrap());
    let maybe_ecopy = store.get_event_by_id(e.id()).unwrap();
    assert!(maybe_ecopy.is_some());

    // Test that the delete event does not remain
    assert!(!store.has_event(del.id()).unwrap());
}

#[test]
fn test_resubmission_of_deleted_by_id_event_is_rejected() {
    let (store, author, e, _temp) = setup(1.into(), &[TAG_CLIENT], "GM");
    let ehexstr = e.id().as_hex_string();

    // Store a delete event
    let del = make_event(&author, 5.into(), &[&["e", &ehexstr]], "", None).unwrap();
    let _ = store.store_event(&del).unwrap();

    // Test has_event() does not have original event
    assert!(!store.has_event(e.id()).unwrap());

    // Test resubmission fails due to Deleted
    let r = store.store_event(&e);
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(matches!(err.inner, InnerError::Deleted));
}

#[test]
fn test_deleted_by_npnaddr_event_is_deleted() {
    let (store, author, e, _temp) = setup(10003.into(), &[TAG_T_NOSTR], "");

    // Store a delete event
    let authorhex = author.pubkey().as_hex_string();
    let del = make_event(
        &author,
        5.into(),
        &[&["a", &format!("10003:{}:", authorhex)]],
        "",
        Some(e.created_at() + 1),
    )
    .unwrap();
    let _ = store.store_event(&del).unwrap();

    // Test has_event() does not have original event
    assert!(!store.has_event(e.id()).unwrap());

    // and read it back fails
    let maybe_ecopy = store.get_event_by_id(e.id()).unwrap();
    assert!(maybe_ecopy.is_none());
}

#[test]
fn test_cannot_delete_by_npnaddr_events_of_others() {
    let (store, author, e, _temp) = setup(10003.into(), &[TAG_T_NOSTR], "");

    // Try to store an invalid delete event
    let authorhex = author.pubkey().as_hex_string();
    let author2 = make_author();
    let del = make_event(
        &author2,
        5.into(),
        &[&["a", &format!("10003:{}:", authorhex)]],
        "",
        Some(e.created_at() + 1),
    )
    .unwrap();
    let r = store.store_event(&del);
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(matches!(err.inner, InnerError::InvalidDelete));

    // Test has_event() still original event
    assert!(store.has_event(e.id()).unwrap());

    // and read it back works
    let maybe_ecopy = store.get_event_by_id(e.id()).unwrap();
    assert!(maybe_ecopy.is_some());
}

#[test]
fn test_resubmission_of_deleted_by_npnaddr_event_is_rejected() {
    let (store, author, e, _temp) = setup(10003.into(), &[TAG_T_NOSTR], "");

    // Store a delete event
    let authorhex = author.pubkey().as_hex_string();
    let del = make_event(
        &author,
        5.into(),
        &[&["a", &format!("10003:{}:", authorhex)]],
        "",
        Some(e.created_at() + 1),
    )
    .unwrap();
    let _ = store.store_event(&del).unwrap();

    // Test has_event() does not have original event
    assert!(!store.has_event(e.id()).unwrap());

    // Test resubmission fails
    assert!(store.store_event(&e).is_err());
}

#[test]
fn test_submission_of_any_older_deleted_by_npnaddr_event_is_rejected() {
    let (store, author, e, _temp) = setup(10003.into(), &[TAG_T_NOSTR], "");

    // Store a delete event
    let authorhex = author.pubkey().as_hex_string();
    let del = make_event(
        &author,
        5.into(),
        &[&["a", &format!("10003:{}:", authorhex)]],
        "",
        Some(e.created_at() + 1),
    )
    .unwrap();
    let _ = store.store_event(&del).unwrap();

    // Test has_event() does not have original event
    assert!(!store.has_event(e.id()).unwrap());

    // Store a different but still older event with same naddr
    let e2 = make_event(
        &author,
        10003.into(),
        &[&["d", "testing"]],
        "Hi",
        Some(e.created_at() - 1),
    )
    .unwrap();
    assert!(store.store_event(&e2).is_err());
}

#[test]
fn test_submission_of_any_newer_deleted_by_npnaddr_event_is_accepted() {
    let (store, author, e, _temp) = setup(10003.into(), &[TAG_T_NOSTR], "");

    // Store a delete event
    let authorhex = author.pubkey().as_hex_string();
    let del = make_event(
        &author,
        5.into(),
        &[&["a", &format!("10003:{}:", authorhex)]],
        "",
        Some(e.created_at() + 1),
    )
    .unwrap();
    let _ = store.store_event(&del).unwrap();

    // Test has_event() does not have original event
    assert!(!store.has_event(e.id()).unwrap());

    // Store a different but still older event with same naddr
    let e2 = make_event(
        &author,
        10003.into(),
        &[TAG_T_NOSTR],
        "Hi",
        Some(e.created_at() + 2),
    )
    .unwrap();
    assert!(store.store_event(&e2).is_ok());

    assert!(store.has_event(e2.id()).unwrap());
}

#[test]
fn test_deleted_by_npnaddr_doesnt_affect_newer_events() {
    let (store, author, e, _temp) = setup(10003.into(), &[TAG_T_NOSTR], "");

    // Store a delete event before it
    let authorhex = author.pubkey().as_hex_string();
    let del = make_event(
        &author,
        5.into(),
        &[&["a", &format!("10003:{}:", authorhex)]],
        "",
        Some(e.created_at() - 1),
    )
    .unwrap();
    let _ = store.store_event(&del).unwrap();

    // Make sure e is not deleted
    assert!(store.has_event(e.id()).unwrap());
}

#[test]
fn test_deleted_by_pnaddr_event_is_deleted() {
    let (store, author, e, _temp) = setup(30023.into(), &[&["d", "testing"]], "");

    // Store a delete event
    let authorhex = author.pubkey().as_hex_string();
    let del = make_event(
        &author,
        5.into(),
        &[&["a", &format!("30023:{}:testing", authorhex)]],
        "",
        Some(e.created_at() + 1),
    )
    .unwrap();
    let _ = store.store_event(&del).unwrap();

    // Test has_event() does not have original event
    assert!(!store.has_event(e.id()).unwrap());

    // and read it back fails
    let maybe_ecopy = store.get_event_by_id(e.id()).unwrap();
    assert!(maybe_ecopy.is_none());
}

#[test]
fn test_cannot_delete_by_pnaddr_events_of_others() {
    let (store, author, e, _temp) = setup(30023.into(), &[&["d", "testing"]], "");

    // Attempt to store an invalid delete event
    let authorhex = author.pubkey().as_hex_string();
    let author2 = make_author();
    let del = make_event(
        &author2,
        5.into(),
        &[&["a", &format!("30023:{}:testing", authorhex)]],
        "",
        Some(e.created_at() + 1),
    )
    .unwrap();
    let r = store.store_event(&del);
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(matches!(err.inner, InnerError::InvalidDelete));

    // Test has_event() still original event
    assert!(store.has_event(e.id()).unwrap());

    // and read it back works
    let maybe_ecopy = store.get_event_by_id(e.id()).unwrap();
    assert!(maybe_ecopy.is_some());
}

#[test]
fn test_resubmission_of_deleted_by_pnaddr_event_is_rejected() {
    let (store, author, e, _temp) = setup(30023.into(), &[&["d", "testing"]], "");

    // Store a delete event
    let authorhex = author.pubkey().as_hex_string();
    let del = make_event(
        &author,
        5.into(),
        &[&["a", &format!("30023:{}:testing", authorhex)]],
        "",
        Some(e.created_at() + 1),
    )
    .unwrap();
    let _ = store.store_event(&del).unwrap();

    // Test has_event() does not have original event
    assert!(!store.has_event(e.id()).unwrap());

    // Test resubmission fails
    assert!(store.store_event(&e).is_err());
}

#[test]
fn test_submission_of_any_older_deleted_by_pnaddr_event_is_rejected() {
    let (store, author, e, _temp) = setup(30023.into(), &[&["d", "testing"]], "");

    // Store a delete event
    let authorhex = author.pubkey().as_hex_string();
    let del = make_event(
        &author,
        5.into(),
        &[&["a", &format!("30023:{}:testing", authorhex)]],
        "",
        Some(e.created_at() + 1),
    )
    .unwrap();
    let _ = store.store_event(&del).unwrap();

    // Test has_event() does not have original event
    assert!(!store.has_event(e.id()).unwrap());

    // Store a different but still older event with same naddr
    let e2 = make_event(
        &author,
        30023.into(),
        &[&["d", "testing"]],
        "Hi",
        Some(e.created_at() - 1),
    )
    .unwrap();
    assert!(store.store_event(&e2).is_err());
}

#[test]
fn test_submission_of_any_newer_deleted_by_pnaddr_event_is_accepted() {
    let (store, author, e, _temp) = setup(30023.into(), &[&["d", "testing"]], "");

    // Store a delete event
    let authorhex = author.pubkey().as_hex_string();
    let del = make_event(
        &author,
        5.into(),
        &[&["a", &format!("30023:{}:testing", authorhex)]],
        "",
        Some(e.created_at() + 1),
    )
    .unwrap();
    let _ = store.store_event(&del).unwrap();

    // Test has_event() does not have original event
    assert!(!store.has_event(e.id()).unwrap());

    // Store a different but still older event with same naddr
    let e2 = make_event(
        &author,
        30023.into(),
        &[&["d", "testing"]],
        "Hi",
        Some(e.created_at() + 2),
    )
    .unwrap();
    assert!(store.store_event(&e2).is_ok());

    assert!(store.has_event(e2.id()).unwrap());
}

#[test]
fn test_deleted_by_pnaddr_doesnt_affect_newer_events() {
    let (store, author, e, _temp) = setup(30023.into(), &[&["d", "testing"]], "");

    // Store a delete event before it
    let authorhex = author.pubkey().as_hex_string();
    let del = make_event(
        &author,
        5.into(),
        &[&["a", &format!("30023:{}:testing", authorhex)]],
        "",
        Some(e.created_at() - 1),
    )
    .unwrap();
    let _ = store.store_event(&del).unwrap();

    // Make sure e is not deleted
    assert!(store.has_event(e.id()).unwrap());
}

#[test]
fn test_deleted_by_pnaddr_is_bound_by_d_tag() {
    let (store, author, e, _temp) = setup(30023.into(), &[&["d", "chucky"]], "");

    // Store a delete event
    let authorhex = author.pubkey().as_hex_string();
    let del = make_event(
        &author,
        5.into(),
        &[&["a", &format!("30023:{}:testing", authorhex)]],
        "",
        Some(e.created_at() + 1),
    )
    .unwrap();
    let _ = store.store_event(&del).unwrap();

    // Test has_event() still has original event
    assert!(store.has_event(e.id()).unwrap());

    // and read it back works
    let maybe_ecopy = store.get_event_by_id(e.id()).unwrap();
    assert_eq!(maybe_ecopy.unwrap(), &*e);
}

#[test]
fn test_replaceable_event_removes_previous() {
    let (store, author, e, _temp) = setup(10003.into(), &[TAG_T_NOSTR], "");
    let replacement = make_event(
        &author,
        10003.into(),
        &[TAG_T_NOSTR],
        "replaced",
        Some(e.created_at() + 1),
    )
    .unwrap();
    let _ = store.store_event(&replacement).unwrap();

    // test via find_replaceable_event()
    let e2 = store
        .find_replaceable_event(author.pubkey(), 10003.into())
        .unwrap()
        .unwrap();
    assert_eq!(e2, &*replacement);

    // test via find_events()
    let filter = OwnedFilter::new(
        &[],
        &[e.pubkey()],
        &[e.kind()],
        &OwnedTags::empty(),
        None,
        None,
        None,
    )
    .unwrap();
    let (events, _) = store
        .find_events(&filter, true, 0, 0, |_| ScreenResult::Match)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], &*replacement);
}

#[test]
fn test_paramterized_replaceable_event_removes_previous() {
    let (store, author, e, _temp) = setup(30023.into(), &[&["d", "testing"]], "");
    let addr = Addr {
        kind: 30023.into(),
        author: author.pubkey(),
        d: b"testing".to_vec(),
    };
    let replacement = make_event(
        &author,
        30023.into(),
        &[&["d", "testing"]],
        "replaced",
        Some(e.created_at() + 1),
    )
    .unwrap();
    let _ = store.store_event(&replacement).unwrap();

    // test via find_replaceable_event()
    let e2 = store
        .find_parameterized_replaceable_event(&addr)
        .unwrap()
        .unwrap();
    assert_eq!(e2, &*replacement);

    // test via find_events()
    let tags = OwnedTags::new(&[&["d", "testing"]]).unwrap();
    let filter =
        OwnedFilter::new(&[], &[addr.author], &[addr.kind], &tags, None, None, None).unwrap();
    let (events, _) = store
        .find_events(&filter, true, 0, 0, |_| ScreenResult::Match)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], &*replacement);
}

#[test]
fn test_stats() {
    let (store, author, e, _temp) = setup(1.into(), &[TAG_CLIENT], "GM");
    let second = make_event(&make_author(), 1.into(), &[TAG_E_TEST], "", None).unwrap();
    store.store_event(&second).unwrap();

    let stats = store.stats().unwrap();
    assert_eq!(stats.event_bytes, 417);
    assert_eq!(stats.index_stats.general_entries, 9);
    assert_eq!(stats.index_stats.i_index_entries, 2);
    assert_eq!(stats.index_stats.ci_index_entries, 2);
    assert_eq!(stats.index_stats.tc_index_entries, 1); // only 1 indexable tag in second event
    assert_eq!(stats.index_stats.ac_index_entries, 2);
    assert_eq!(stats.index_stats.akc_index_entries, 2);
    assert_eq!(stats.index_stats.atc_index_entries, 1); // only 1 indexable tag in second event
    assert_eq!(stats.index_stats.ktc_index_entries, 1); // only 1 indexable tag in second event
    assert_eq!(stats.index_stats.deleted_index_entries, 0);

    // Remove the second event and check again
    store.remove_event(second.id()).unwrap();
    let stats = store.stats().unwrap();
    assert_eq!(stats.index_stats.deleted_index_entries, 0); // only used on actual delete events
    assert_eq!(stats.index_stats.i_index_entries, 1);

    // Store a delete event that removes the first event check again
    let ehexstr = e.id().as_hex_string();
    let del = make_event(&author, 5.into(), &[&["e", &ehexstr]], "", None).unwrap();
    let _ = store.store_event(&del).unwrap();
    let stats = store.stats().unwrap();
    assert_eq!(stats.index_stats.deleted_index_entries, 1);
    assert_eq!(stats.index_stats.i_index_entries, 1); // 1 because of the delete event itself
}

#[test]
fn test_rebuild() {
    let (store, _, _, _temp) = setup(30023.into(), &[&["d", "testing"]], "");
    let store = unsafe { store.rebuild().unwrap() };
    let filter = OwnedFilter::new(&[], &[], &[], &OwnedTags::empty(), None, None, None).unwrap();
    let (events, _) = store
        .find_events(&filter, true, 0, 0, |_| ScreenResult::Match)
        .unwrap();
    assert_eq!(events.len(), 1);
}

#[test]
fn test_naddr_is_deleted_asof() {
    let (store, author, e, _temp) = setup(30023.into(), &[&["d", "testing"]], "");
    let addr = Addr {
        kind: 30023.into(),
        author: author.pubkey(),
        d: b"testing".to_vec(),
    };
    assert!(matches!(store.naddr_is_deleted_asof(&addr), Ok(None)));

    // Store a delete event
    let time = e.created_at() + 1;
    let authorhex = author.pubkey().as_hex_string();
    let del = make_event(
        &author,
        5.into(),
        &[&["a", &format!("30023:{}:testing", authorhex)]],
        "",
        Some(time),
    )
    .unwrap();
    let _ = store.store_event(&del).unwrap();

    let deleted_asof = store.naddr_is_deleted_asof(&addr).unwrap();
    assert_eq!(deleted_asof, Some(time));
}

#[test]
fn test_remove_event() {
    let (store, _author, e, _temp) = setup(1.into(), &[TAG_CLIENT], "GM");
    store.remove_event(e.id()).unwrap();
    assert!(!store.has_event(e.id()).unwrap());
    let maybe_ecopy = store.get_event_by_id(e.id()).unwrap();
    assert!(maybe_ecopy.is_none());
}

#[test]
fn test_extra_tables() {
    let tempdir = tempfile::tempdir().unwrap();
    let store = Store::new(&tempdir, vec!["test1", "foobar"]).unwrap();

    let t1 = store.extra_table("test1").unwrap();
    let mut txn = store.write_txn().unwrap();
    t1.put(&mut txn, &[1, 2, 3], &[4, 5, 6]).unwrap();
    txn.commit().unwrap();

    let _ = store.extra_table("foobar").unwrap();

    let t3 = store.extra_table("juicy");
    assert!(t3.is_none());
}

/*
// The following are not yet implemented here:
//   test NIP-26 (delegated event signing)  [match either author; allow delegatee to delete]
//   test NIP-40 (expiration timestamp)

// The following are higher-level relay tests:
//   test NIP-04 (DMs)
//   test NIP-11 (relay info doc)
//   test NIP-29 (relay based groups)
//   test NIP-42 (auth)
//   test NIP-45 (count)
//   test NIP-50 (search)
//   test NIP-59 (giftwrap)
//   test NIP-65 (relay list metadata)
//   test NIP-94 (file metadata)
//   test NIP-96 (http file storage integration)
 */
