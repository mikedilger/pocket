mod error;
pub use error::{Error, InnerError};

mod event_store;
use event_store::EventStore;

mod lmdb;
pub use lmdb::IndexStats;
use lmdb::Lmdb;

pub use heed;

use crate::heed::types::Bytes;
use crate::heed::{Database, RoTxn, RwTxn};
use pocket_types::{Addr, Event, Filter, Id, Kind, Pubkey, Time};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub struct Stats {
    /// The number of bytes storing the events themselves
    pub event_bytes: usize,

    /// Statistics about the indexes (in LMDB)
    pub index_stats: IndexStats,
}

#[derive(Debug)]
pub struct Store {
    events: EventStore,
    indexes: Lmdb,
    dir: PathBuf,
    num_extra_tables: usize,
}

impl Store {
    /// Setup persistent storage.
    ///
    /// The directory must already exist and be writable. If it already has storage,
    /// it will open that storage and use it. Otherwise it will create new storage.
    ///
    /// Pass in the number of extra key-value tables you want. You can use them for
    /// any purpose, mapping opaque binary data to opaque binary data.
    pub fn new<P: AsRef<Path>>(directory: P, num_extra_tables: usize) -> Result<Store, Error> {
        let dir = directory.as_ref().to_owned();

        // Create the directory if it doesn't exist, ignoring errors
        let _ = std::fs::create_dir(&dir);

        let mut events_path = dir.clone();
        events_path.push("event.map");

        let mut indexes_path = dir.clone();
        indexes_path.push("lmdb");

        // Create the lmdb subdir if it doesn't exist, ignoring errors
        let _ = std::fs::create_dir(&indexes_path);

        let events = EventStore::new(&events_path)?;
        let indexes = Lmdb::new(&indexes_path, num_extra_tables)?;

        Ok(Store {
            events,
            indexes,
            dir,
            num_extra_tables,
        })
    }

    /// Get directory where this store resides
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Get database statistics
    pub fn stats(&self) -> Result<Stats, Error> {
        Ok(Stats {
            event_bytes: self.events.read_event_map_end(),
            index_stats: self.indexes.stats()?,
        })
    }

    /// Rebuild the database
    ///
    /// This compacts the database by removing unreferenced entries, and reindexes everything.
    ///
    /// # Safety
    /// Do not run while the database is in use.
    pub unsafe fn rebuild(self) -> Result<Store, Error> {
        let Store {
            events,
            indexes,
            dir,
            num_extra_tables,
        } = self;

        indexes.sync()?;
        drop(events);
        drop(indexes);

        println!("{}", dir.display());
        let dir = dir.clone();

        let mut events_path = dir.clone();
        events_path.push("event.map");

        let mut indexes_path = dir.clone();
        indexes_path.push("lmdb");

        let mut events_bak_path = dir.clone();
        events_bak_path.push("event.map.bak");

        let mut indexes_bak_path = dir.clone();
        indexes_bak_path.push("lmdb.bak");

        // Backup existing data (moving out of the way)
        fs::rename(&events_path, &events_bak_path)?;

        fs::rename(&indexes_path, &indexes_bak_path)?;

        // Open old data
        let old_events = EventStore::new(&events_bak_path)?;
        let old_indexes = Lmdb::new(&indexes_bak_path, num_extra_tables)?;

        // Open new data
        let new_events = EventStore::new(&events_path)?;
        let _ = std::fs::create_dir(&indexes_path);
        let new_indexes = Lmdb::new(&indexes_path, num_extra_tables)?;

        let old_store = Store {
            indexes: old_indexes,
            events: old_events,
            dir: dir.clone(),
            num_extra_tables,
        };

        let new_store = Store {
            indexes: new_indexes,
            events: new_events,
            dir: dir.clone(),
            num_extra_tables,
        };

        let old_txn = old_store.indexes.read_txn()?;
        let mut new_txn = new_store.indexes.write_txn()?;

        // Iterate through all IDs and copy and index all of those events
        // This populates all the indexes
        for i in old_store.indexes.i_iter(&old_txn)? {
            let (_key, val) = i?;
            //let id = Id(key[0..32].try_into().unwrap());
            let old_offset: u64 = val;
            let event = old_store.events.get_event_by_offset(old_offset as usize)?;
            let new_offset = new_store.events.store_event(event)? as u64;
            new_store.indexes.index(&mut new_txn, event, new_offset)?;
        }

        // Copy deleted IDs
        let mut deleted = old_store.indexes.dump_deleted()?;
        for id in deleted.drain(..) {
            new_store.indexes.mark_deleted(&mut new_txn, id)?;
        }

        let mut naddr_deleted = old_store.indexes.dump_naddr_deleted()?;
        for (addr, when) in naddr_deleted.drain(..) {
            new_store
                .indexes
                .mark_naddr_deleted(&mut new_txn, &addr, when)?;
        }

        // FIXME GINA copy the extra tables

        new_txn.commit()?;

        new_store.indexes.sync()?;

        Ok(new_store)
    }

    /// Sync the data to disk. This happens periodically, but sometimes it's useful to force
    /// it.
    pub fn sync(&self) -> Result<(), Error> {
        self.indexes.sync()?;
        Ok(())
    }

    /// Store an event.
    ///
    /// Returns the offset where the event is stored at, which can be used to fetch
    /// the event via get_event_by_offset().
    ///
    /// If the event already exists, you will get a InnerError::Duplicate
    ///
    /// If the event is ephemeral, it will be stored and you will get an offset, but
    /// it will not be indexed.
    pub fn store_event(&self, event: &Event) -> Result<u64, Error> {
        // TBD: should we validate the event?

        let mut txn = self.indexes.write_txn()?;

        // Return Duplicate if it already exists
        if self.indexes.get_offset_by_id(&txn, event.id())?.is_some() {
            return Err(InnerError::Duplicate.into());
        }

        // Handle deleted events
        {
            // Reject event if ID was deleted
            if self.indexes.is_deleted(&txn, event.id())? {
                return Err(InnerError::Deleted.into());
            }

            // Reject event if ADDR was deleted after it's created_at date
            // (non-parameterized)
            if event.kind().is_replaceable() {
                let addr = Addr {
                    kind: event.kind(),
                    author: event.pubkey(),
                    d: vec![],
                };
                if let Some(time) = self.indexes.when_is_naddr_deleted(&txn, &addr)? {
                    if event.created_at() <= time {
                        return Err(InnerError::Deleted.into());
                    }
                }
            }

            // Reject event if ADDR was deleted after it's created_at date
            // (parameterized)
            if event.kind().is_parameterized_replaceable() {
                if let Some(identifier) = event.tags()?.get_value(b"d") {
                    let addr = Addr {
                        kind: event.kind(),
                        author: event.pubkey(),
                        d: identifier.to_owned(),
                    };
                    if let Some(time) = self.indexes.when_is_naddr_deleted(&txn, &addr)? {
                        if event.created_at() <= time {
                            return Err(InnerError::Deleted.into());
                        }
                    }
                }
            }
        }

        // Pre-remove replaceable events being replaced
        {
            if event.kind().is_replaceable() {
                // Pre-remove any replaceable events that this replaces
                self.remove_replaceable(
                    &mut txn,
                    event.pubkey(),
                    event.kind(),
                    event.created_at(),
                )?;

                // If any remaining matching replaceable events exist, then
                // this event is invalid, return Replaced
                if self
                    .find_replaceable_event_inner(&txn, event.pubkey(), event.kind())?
                    .is_some()
                {
                    return Err(InnerError::Replaced.into());
                }
            }

            if event.kind().is_parameterized_replaceable() {
                let tags = event.tags()?;
                if let Some(identifier) = tags.get_value(b"d") {
                    let addr = Addr {
                        kind: event.kind(),
                        author: event.pubkey(),
                        d: identifier.to_owned(),
                    };

                    // Pre-remove any parameterized-replaceable events that this replaces
                    self.remove_parameterized_replaceable(&mut txn, &addr, Time::max())?;

                    // If any remaining matching parameterized replaceable events exist, then
                    // this event is invalid, return Replaced
                    if self
                        .find_parameterized_replaceable_event_inner(&txn, &addr)?
                        .is_some()
                    {
                        return Err(InnerError::Replaced.into());
                    }
                }
            }
        }

        // Store the event
        let offset = self.events.store_event(event)? as u64;

        // Index the event
        if !event.kind().is_ephemeral() {
            self.indexes.index(&mut txn, event, offset)?;
        }

        // Handle deletion events
        if event.kind() == 5.into() {
            self.handle_deletion_event(&mut txn, event)?;
        }

        txn.commit()?;

        Ok(offset)
    }

    fn handle_deletion_event(&self, txn: &mut RwTxn<'_>, event: &Event) -> Result<(), Error> {
        for mut tag in event.tags()?.iter() {
            if let Some(tagname) = tag.next() {
                if tagname == b"e" {
                    if let Some(id_hex) = tag.next() {
                        if let Ok(id) = Id::read_hex(id_hex) {
                            // Actually remove
                            if let Some(target) = self.get_event_by_id(id)? {
                                // author must match
                                if target.pubkey() != event.pubkey() {
                                    return Err(InnerError::InvalidDelete.into());
                                }
                                self.remove_by_id(txn, id)?;
                            }

                            // Mark deleted
                            // NOTE: if we didn't have the target event, we presume this is valid,
                            //       and if not, clients will just have to deal with that.
                            self.indexes.mark_deleted(txn, id)?;
                        }
                    }
                } else if tagname == b"a" {
                    if let Some(naddr_bytes) = tag.next() {
                        if let Ok(addr) = Addr::try_from_bytes(naddr_bytes) {
                            if addr.author != event.pubkey() {
                                return Err(InnerError::InvalidDelete.into());
                            }

                            // Mark deleted
                            self.indexes
                                .mark_naddr_deleted(txn, &addr, event.created_at())?;

                            // Remove events (up to the created_at of the deletion event)
                            if addr.kind.is_replaceable() {
                                self.remove_replaceable(
                                    txn,
                                    addr.author,
                                    addr.kind,
                                    event.created_at(),
                                )?;
                            } else if addr.kind.is_parameterized_replaceable() {
                                self.remove_parameterized_replaceable(
                                    txn,
                                    &addr,
                                    event.created_at(),
                                )?;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get an event by its offset.
    pub fn get_event_by_offset(&self, offset: u64) -> Result<&Event, Error> {
        unsafe { self.events.get_event_by_offset(offset as usize) }
    }

    /// Get an event by Id
    pub fn get_event_by_id(&self, id: Id) -> Result<Option<&Event>, Error> {
        let txn = self.indexes.read_txn()?;
        if let Some(offset) = self.indexes.get_offset_by_id(&txn, id)? {
            unsafe { Some(self.events.get_event_by_offset(offset as usize)).transpose() }
        } else {
            Ok(None)
        }
    }

    /// Do we have an event
    pub fn has_event(&self, id: Id) -> Result<bool, Error> {
        let txn = self.indexes.read_txn()?;
        Ok(self.indexes.get_offset_by_id(&txn, id)?.is_some())
    }

    /// Is the event deleted
    pub fn event_is_deleted(&self, id: Id) -> Result<bool, Error> {
        let txn = self.indexes.read_txn()?;
        self.indexes.is_deleted(&txn, id)
    }

    /// Is the naddr deleted, and if so, when?
    pub fn naddr_is_deleted_asof(&self, addr: &Addr) -> Result<Option<Time>, Error> {
        let txn = self.indexes.read_txn()?;
        self.indexes.when_is_naddr_deleted(&txn, addr)
    }

    /// Find all events that match the filter
    pub fn find_events<F>(
        &self,
        filter: &Filter,
        allow_scraping: bool,
        allow_scrape_if_limited_to: u32,
        allow_scrape_if_max_seconds: u64,
        screen: F,
    ) -> Result<Vec<&Event>, Error>
    where
        F: Fn(&Event) -> bool,
    {
        let txn = self.indexes.read_txn()?;

        // We insert into a BTreeSet to keep them time-ordered
        let mut output: BTreeSet<&Event> = BTreeSet::new();

        if filter.num_ids() > 0 {
            // Fetch by id
            for id in filter.ids() {
                // Stop if limited
                if output.len() >= filter.limit() as usize {
                    break;
                }
                if let Some(event) = self.get_event_by_id(id)? {
                    // and check each against the rest of the filter
                    if filter.event_matches(event)? && screen(event) {
                        output.insert(event);
                    }
                }
            }
        } else if filter.num_authors() > 0 && filter.num_kinds() > 0 {
            // We may bring since forward if we hit the limit without going back that
            // far, so we use a mutable since:
            let mut since = filter.since();

            for author in filter.authors() {
                for kind in filter.kinds() {
                    let iter = self
                        .indexes
                        .akc_iter(author, kind, since, filter.until(), &txn)?;

                    // Count how many we have found of this author-kind pair, so we
                    // can possibly update `since`
                    let mut paircount = 0;

                    'per_event: for result in iter {
                        let (_key, offset) = result?;
                        let event = unsafe { self.events.get_event_by_offset(offset as usize)? };

                        // If we have gone beyond since, we can stop early
                        // (We have to check because `since` might change in this loop)
                        if event.created_at() < since {
                            break 'per_event;
                        }

                        // check against the rest of the filter
                        if filter.event_matches(event)? && screen(event) {
                            // Accept the event
                            output.insert(event);
                            paircount += 1;

                            // Stop this pair if limited
                            if paircount >= filter.limit() as usize {
                                // Since we found the limit just among this pair,
                                // potentially move since forward
                                if event.created_at() > since {
                                    since = event.created_at();
                                }
                                break 'per_event;
                            }

                            // If kind is replaceable (and not parameterized)
                            // then don't take any more events for this author-kind
                            // pair.
                            // NOTE that this optimization is difficult to implement
                            // for other replaceable event situations
                            if kind.is_replaceable() {
                                break 'per_event;
                            }
                        }
                    }
                }
            }
        } else if filter.num_authors() > 0 && !filter.tags()?.is_empty() {
            // We may bring since forward if we hit the limit without going back that
            // far, so we use a mutable since:
            let mut since = filter.since();

            for author in filter.authors() {
                let tags = filter.tags()?;
                for mut tag in tags.iter() {
                    if let Some(tag0) = tag.next() {
                        if let Some(tagvalue) = tag.next() {
                            let iter = self.indexes.atc_iter(
                                author,
                                tag0[0],
                                tagvalue,
                                since,
                                filter.until(),
                                &txn,
                            )?;

                            // Count how many we have found of this author-tag pair, so we
                            // can possibly update `since`
                            let mut paircount = 0;

                            'per_event: for result in iter {
                                let (_key, offset) = result?;
                                let event =
                                    unsafe { self.events.get_event_by_offset(offset as usize)? };

                                // If we have gone beyond since, we can stop early
                                // (We have to check because `since` might change in this loop)
                                if event.created_at() < since {
                                    break 'per_event;
                                }

                                // check against the rest of the filter
                                if filter.event_matches(event)? && screen(event) {
                                    // Accept the event
                                    output.insert(event);
                                    paircount += 1;

                                    // Stop this pair if limited
                                    if paircount >= filter.limit() as usize {
                                        // Since we found the limit just among this pair,
                                        // potentially move since forward
                                        if event.created_at() > since {
                                            since = event.created_at();
                                        }
                                        break 'per_event;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if filter.num_kinds() > 0 && !filter.tags()?.is_empty() {
            // We may bring since forward if we hit the limit without going back that
            // far, so we use a mutable since:
            let mut since = filter.since();

            for kind in filter.kinds() {
                let tags = filter.tags()?;
                for mut tag in tags.iter() {
                    if let Some(tag0) = tag.next() {
                        if let Some(tagvalue) = tag.next() {
                            let iter = self.indexes.ktc_iter(
                                kind,
                                tag0[0],
                                tagvalue,
                                since,
                                filter.until(),
                                &txn,
                            )?;

                            // Count how many we have found of this kind-tag pair, so we
                            // can possibly update `since`
                            let mut paircount = 0;

                            'per_event: for result in iter {
                                let (_key, offset) = result?;
                                let event =
                                    unsafe { self.events.get_event_by_offset(offset as usize)? };

                                // If we have gone beyond since, we can stop early
                                // (We have to check because `since` might change in this loop)
                                if event.created_at() < since {
                                    break 'per_event;
                                }

                                // check against the rest of the filter
                                if filter.event_matches(event)? && screen(event) {
                                    // Accept the event
                                    output.insert(event);
                                    paircount += 1;

                                    // Stop this pair if limited
                                    if paircount >= filter.limit() as usize {
                                        // Since we found the limit just among this pair,
                                        // potentially move since forward
                                        if event.created_at() > since {
                                            since = event.created_at();
                                        }
                                        break 'per_event;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if !filter.tags()?.is_empty() {
            // We may bring since forward if we hit the limit without going back that
            // far, so we use a mutable since:
            let mut since = filter.since();

            let tags = filter.tags()?;
            for mut tag in tags.iter() {
                if let Some(tag0) = tag.next() {
                    if let Some(tagvalue) = tag.next() {
                        let iter =
                            self.indexes
                                .tc_iter(tag0[0], tagvalue, since, filter.until(), &txn)?;

                        let mut rangecount = 0;

                        'per_event: for result in iter {
                            let (_key, offset) = result?;
                            let event =
                                unsafe { self.events.get_event_by_offset(offset as usize)? };

                            if event.created_at() < since {
                                break 'per_event;
                            }

                            // check against the rest of the filter
                            if filter.event_matches(event)? && screen(event) {
                                // Accept the event
                                output.insert(event);
                                rangecount += 1;

                                // Stop this limited
                                if rangecount >= filter.limit() as usize {
                                    if event.created_at() > since {
                                        since = event.created_at();
                                    }
                                    break 'per_event;
                                }
                            }
                        }
                    }
                }
            }
        } else if filter.num_authors() > 0 {
            // We may bring since forward if we hit the limit without going back that
            // far, so we use a mutable since:
            let mut since = filter.since();

            for author in filter.authors() {
                let iter = self.indexes.ac_iter(author, since, filter.until(), &txn)?;

                let mut rangecount = 0;

                'per_event: for result in iter {
                    let (_key, offset) = result?;
                    let event = unsafe { self.events.get_event_by_offset(offset as usize)? };

                    if event.created_at() < filter.since() {
                        break 'per_event;
                    }

                    // check against the rest of the filter
                    if filter.event_matches(event)? && screen(event) {
                        // Accept the event
                        output.insert(event);
                        rangecount += 1;

                        // Stop this limited
                        if rangecount >= filter.limit() as usize {
                            if event.created_at() > since {
                                since = event.created_at();
                            }
                            break 'per_event;
                        }
                    }
                }
            }
        } else {
            // SCRAPE:
            let maxtime = filter.until().min(Time::now());

            let allow = allow_scraping
                || filter.limit() <= allow_scrape_if_limited_to
                || *(maxtime - filter.since()).as_ref() < allow_scrape_if_max_seconds;
            if !allow {
                return Err(InnerError::Scraper.into());
            }

            // This is INEFFICIENT as it scans through many events

            let iter = self.indexes.ci_iter(filter.since(), filter.until(), &txn)?;
            for result in iter {
                if output.len() >= filter.limit() as usize {
                    break;
                }
                let (_key, offset) = result?;
                let event = unsafe { self.events.get_event_by_offset(offset as usize)? };

                if filter.event_matches(event)? && screen(event) {
                    output.insert(event);
                }
            }
        }

        // Convert to a Vec, reverse time order, and apply limit
        Ok(output
            .iter()
            .rev()
            .take(filter.limit() as usize)
            .copied()
            .collect())
    }

    /// Find a replaceable event
    pub fn find_replaceable_event(
        &self,
        author: Pubkey,
        kind: Kind,
    ) -> Result<Option<&Event>, Error> {
        let txn = self.indexes.read_txn()?;
        self.find_replaceable_event_inner(&txn, author, kind)
    }

    fn find_replaceable_event_inner(
        &self,
        txn: &RoTxn<'_>,
        author: Pubkey,
        kind: Kind,
    ) -> Result<Option<&Event>, Error> {
        if !kind.is_replaceable() {
            return Err(InnerError::WrongEventKind.into());
        }

        let mut iter = self
            .indexes
            .akc_iter(author, kind, Time::min(), Time::max(), txn)?;

        if let Some(result) = iter.next() {
            let (_key, offset) = result?;
            let event = unsafe { self.events.get_event_by_offset(offset as usize)? };
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    /// Find a parameterized-replaceable event
    pub fn find_parameterized_replaceable_event(
        &self,
        addr: &Addr,
    ) -> Result<Option<&Event>, Error> {
        let txn = self.indexes.read_txn()?;
        self.find_parameterized_replaceable_event_inner(&txn, addr)
    }

    fn find_parameterized_replaceable_event_inner(
        &self,
        txn: &RoTxn<'_>,
        addr: &Addr,
    ) -> Result<Option<&Event>, Error> {
        if !addr.kind.is_parameterized_replaceable() {
            return Err(InnerError::WrongEventKind.into());
        }

        let iter = self.indexes.atc_iter(
            addr.author,
            b'd',
            addr.d.as_slice(),
            Time::min(),
            Time::max(),
            txn,
        )?;

        for result in iter {
            let (_key, offset) = result?;
            let event = unsafe { self.events.get_event_by_offset(offset as usize)? };

            // the atc index doesn't have kind, so we have to compare the kinds
            if event.kind() != addr.kind {
                continue;
            }

            return Ok(Some(event));
        }

        Ok(None)
    }

    /// Remove an event by id.
    ///
    /// This deindexes the event.
    ///
    /// This does not add to the deleted_ids record, which is for events
    /// that are deleted by other events
    fn remove_by_id(&self, txn: &mut RwTxn<'_>, id: Id) -> Result<(), Error> {
        if let Some(offset) = self.indexes.get_offset_by_id(txn, id)? {
            self.remove_by_offset(txn, offset)?;
        }

        Ok(())
    }

    /// Remove an event by offset.
    ///
    /// This deindexes the event.
    ///
    /// This does not add to the deleted_ids record, which is for events
    /// that are deleted by other events
    fn remove_by_offset(&self, txn: &mut RwTxn<'_>, offset: u64) -> Result<(), Error> {
        // Get event
        let event = unsafe { self.events.get_event_by_offset(offset as usize)? };

        // Remove from indexes
        self.indexes.deindex(txn, event)?;

        // Also remove from the id index
        self.indexes.deindex_id(txn, event.id())?;

        Ok(())
    }

    /// This removes an event without marking it as having been deleted by another event
    pub fn remove_event(&self, id: Id) -> Result<(), Error> {
        let mut txn = self.indexes.write_txn()?;
        self.remove_by_id(&mut txn, id)?;
        txn.commit()?;
        Ok(())
    }

    // Remove all replaceable events with the matching author-kind
    // Kind must be a replaceable (not parameterized replaceable) event kind
    fn remove_replaceable(
        &self,
        txn: &mut RwTxn<'_>,
        author: Pubkey,
        kind: Kind,
        until: Time,
    ) -> Result<(), Error> {
        if !kind.is_replaceable() {
            return Err(InnerError::WrongEventKind.into());
        }

        let loop_txn = self.indexes.read_txn()?;
        let iter = self
            .indexes
            .akc_iter(author, kind, Time::min(), until, &loop_txn)?;

        for result in iter {
            let (_key, offset) = result?;

            // Remove the event (this deindexes)
            self.remove_by_offset(txn, offset)?;
        }

        Ok(())
    }

    // Remove all parameterized-replaceable events with the matching author-kind-d
    // Kind must be a paramterized-replaceable event kind
    fn remove_parameterized_replaceable(
        &self,
        txn: &mut RwTxn<'_>,
        addr: &Addr,
        until: Time,
    ) -> Result<(), Error> {
        if !addr.kind.is_parameterized_replaceable() {
            return Err(InnerError::WrongEventKind.into());
        }

        let loop_txn = self.indexes.read_txn()?;
        let iter = self.indexes.atc_iter(
            addr.author,
            b'd',
            addr.d.as_slice(),
            Time::min(),
            until,
            &loop_txn,
        )?;

        for result in iter {
            let (_key, offset) = result?;

            // Our index doesn't have Kind embedded, so we have to check it
            let matches = {
                let event = self.get_event_by_offset(offset)?;
                event.kind() == addr.kind
            };

            if matches {
                // Remove the event (this deindexes)
                self.remove_by_offset(txn, offset)?;
            }
        }

        Ok(())
    }

    /// Get access to an extra LMDB table
    pub fn extra_table(&self, index: usize) -> Option<Database<Bytes, Bytes>> {
        self.indexes.extra_table(index)
    }

    /// Get a read transaction for use with extra_table()
    pub fn read_txn(&self) -> Result<RoTxn, Error> {
        self.indexes.read_txn()
    }

    /// Get a write transaction for use with extra_table()
    pub fn write_txn(&self) -> Result<RwTxn, Error> {
        self.indexes.write_txn()
    }
}
