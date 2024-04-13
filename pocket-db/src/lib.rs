mod error;
use error::{Error, InnerError};

mod event_store;
use event_store::EventStore;

mod lmdb;
pub use lmdb::IndexStats;
use lmdb::Lmdb;

use heed::RwTxn;
use pocket_types::{Event, Filter, Id, Time};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

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
}

impl Store {
    /// Setup persistent storage.
    ///
    /// The directory must already exist and be writable. If it already has storage,
    /// it will open that storage and use it. Otherwise it will create new storage.
    pub fn new<P: AsRef<Path>>(directory: P) -> Result<Store, Error> {
        let mut events_path = directory.as_ref().to_path_buf();
        events_path.push("event.map");

        let mut indexes_path = directory.as_ref().to_path_buf();
        indexes_path.push("lmdb");

        let events = EventStore::new(&events_path)?;
        let indexes = Lmdb::new(&indexes_path)?;

        Ok(Store { events, indexes })
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
    /// This compacts the database by removing deleted entries, and reindexes everything.
    ///
    /// # Safety
    /// Do not run while the database is in use.
    pub unsafe fn rebuild<P: AsRef<Path>>(directory: P) -> Result<(), Error> {
        let mut events_path = directory.as_ref().to_path_buf();
        events_path.push("event.map");

        let mut indexes_path = directory.as_ref().to_path_buf();
        indexes_path.push("lmdb");

        let mut events_bak_path = directory.as_ref().to_path_buf();
        events_bak_path.push("event.map.bak");

        let mut indexes_bak_path = directory.as_ref().to_path_buf();
        indexes_bak_path.push("lmdb.bak");

        // Backup existing data (moving out of the way)
        fs::rename(&events_path, &events_bak_path)?;
        fs::rename(&indexes_path, &indexes_bak_path)?;

        // Open old data
        let old_events = EventStore::new(&events_bak_path)?;
        let old_indexes = Lmdb::new(&indexes_bak_path)?;

        // Open new data
        let new_events = EventStore::new(&events_path)?;
        let new_indexes = Lmdb::new(&indexes_path)?;

        let old_store = Store {
            indexes: old_indexes,
            events: old_events,
        };

        let new_store = Store {
            indexes: new_indexes,
            events: new_events,
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

        new_txn.commit()?;

        new_store.indexes.sync()?;

        Ok(())
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
        let offset;

        // Only if it doesn't already exist
        if self.indexes.get_offset_by_id(&txn, event.id())?.is_none() {
            // Reject event if it was deleted
            {
                if self.indexes.is_deleted(&txn, event.id())? {
                    return Err(InnerError::Deleted.into());
                }
            }

            // Store the event
            offset = self.events.store_event(event)? as u64;

            // Index the event
            if !event.kind().is_ephemeral() {
                self.indexes.index(&mut txn, event, offset)?;
            }

            // If replaceable or parameterized replaceable,
            // find and delete all but the first one in the group
            if event.kind().is_replaceable() || event.kind().is_parameterized_replaceable() {
                self.delete_replaced(&mut txn, event)?;
            }

            // Handle deletion events
            if event.kind() == 5.into() {
                self.handle_deletion_event(&mut txn, event)?;
            }

            txn.commit()?;
        } else {
            return Err(InnerError::Duplicate.into());
        }

        Ok(offset)
    }

    fn handle_deletion_event(&self, txn: &mut RwTxn<'_>, event: &Event) -> Result<(), Error> {
        for mut tag in event.tags()?.iter() {
            if let Some(tagname) = tag.next() {
                if tagname == b"e" {
                    if let Some(id_hex) = tag.next() {
                        if let Ok(id) = Id::read_hex(id_hex) {
                            // Add deletion pair to the event_deleted table
                            self.indexes.mark_deleted(txn, id)?;

                            // Delete pair
                            if let Some(target) = self.get_event_by_id(id)? {
                                if target.pubkey() == event.pubkey() {
                                    self.delete_by_id(txn, id)?;
                                }
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

    /// Delete an event by id.
    ///
    /// This deindexes the event.
    ///
    /// This does not add to the deleted_ids record, which is for events
    /// that are deleted by other events
    fn delete_by_id(&self, txn: &mut RwTxn<'_>, id: Id) -> Result<(), Error> {
        if let Some(offset) = self.indexes.get_offset_by_id(txn, id)? {
            self.delete_by_offset(txn, offset)?;
        }

        Ok(())
    }

    /// Delete an event by offset.
    ///
    /// This deindexes the event.
    ///
    /// This does not add to the deleted_ids record, which is for events
    /// that are deleted by other events
    fn delete_by_offset(&self, txn: &mut RwTxn<'_>, offset: u64) -> Result<(), Error> {
        // Get event
        let event = unsafe { self.events.get_event_by_offset(offset as usize)? };

        // Remove from indexes
        self.indexes.deindex(txn, event)?;

        // Also remove from the id index
        self.indexes.deindex_id(txn, event.id())?;

        Ok(())
    }

    // This deletes an event without marking it as having been deleted by another event
    pub fn delete_event(&self, id: Id) -> Result<(), Error> {
        let mut txn = self.indexes.write_txn()?;
        self.delete_by_id(&mut txn, id)?;
        txn.commit()?;
        Ok(())
    }

    // If the event is replaceable or parameterized replaceable
    // this deletes all the events in that group except the most recent one.
    fn delete_replaced(&self, txn: &mut RwTxn<'_>, event: &Event) -> Result<(), Error> {
        if event.kind().is_replaceable() {
            let loop_txn = self.indexes.read_txn()?;
            let iter = self.indexes.akc_iter(
                event.pubkey(),
                event.kind(),
                Time::min(),
                Time::max(),
                &loop_txn,
            )?;
            let mut first = true;
            for result in iter {
                // Keep the first result
                if first {
                    first = false;
                    continue;
                }

                let (_key, offset) = result?;

                // Delete the event
                self.delete_by_offset(txn, offset)?;
            }
        } else if event.kind().is_parameterized_replaceable() {
            let tags = event.tags()?;
            if let Some(identifier) = tags.get_value(b"d") {
                let loop_txn = self.indexes.read_txn()?;
                let iter = self.indexes.atc_iter(
                    event.pubkey(),
                    b'd',
                    identifier,
                    Time::min(),
                    Time::max(),
                    &loop_txn,
                )?;
                let mut first = true;
                for result in iter {
                    // Keep the first result
                    if first {
                        first = false;
                        continue;
                    }

                    let (_key, offset) = result?;

                    // Delete the event
                    self.delete_by_offset(txn, offset)?;
                }
            }
        }

        Ok(())
    }
}
