// Copyright 2024 pocket developers (see https://github.com/mikedilger/pocket)
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>
// This file may not be copied, modified, or distributed except according to those terms.

//! Defines nostr types that are always serialized, including borrowed and owned variants.
//! These types are highly efficient in situations when they are not mutated.
//! Defines highly efficient parsing from JSON bytes into these types.

#![deny(
    missing_debug_implementations,
    trivial_numeric_casts,
    clippy::string_slice,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    unused_lifetimes,
    unused_labels,
    unused_extern_crates,
    non_ascii_idents,
    keyword_idents,
    deprecated_in_future,
    unstable_features,
    single_use_lifetimes,
    unreachable_pub,
    missing_copy_implementations,
    missing_docs
)]

include!("macros.rs");

mod addr;
pub use addr::Addr;

mod error;
pub use error::{Error, InnerError};

mod event;
pub use event::{Event, OwnedEvent};

mod filter;
pub use filter::{Filter, OwnedFilter};

mod id;
pub use id::Id;

/// JSON parsing into these types
pub mod json;

mod kind;
pub use kind::Kind;

mod pubkey;
pub use pubkey::Pubkey;

mod sig;
pub use sig::Sig;

mod tags;
pub use tags::{OwnedTags, Tags, TagsIter, TagsStringIter};

mod time;
pub use time::Time;
