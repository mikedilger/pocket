use crate::error::Error;
use heed::byteorder::BigEndian;
use heed::types::{Bytes, Unit, U64};
use heed::{Database, Env, EnvFlags, EnvOpenOptions, RoIter, RoRange, RoTxn, RwTxn};
use pocket_types::{Event, Id, Kind, Pubkey, Time};
use std::ops::{Bound, Deref};
use std::path::Path;

pub struct IndexStats {
    /// This is the bytes used on disk (disk file is sparse and may show as much larger)
    pub disk_usage: u64,

    /// This is the bytes used by non-free pages
    pub memory_usage: u64,

    /// Number of entries in the general database
    pub general_entries: u64,

    /// Number of entries in the IDs index
    pub i_index_entries: u64,

    /// Number of entries in the (CreatedAt + ID) index
    pub ci_index_entries: u64,

    /// Number of entries in the (Tag + CreatedAt + ID) index
    pub tc_index_entries: u64,

    /// Number of entries in the (Author + CreatedAt + ID) index
    pub ac_index_entries: u64,

    /// Number of entries in the (Author + Kind + CreatedAt + ID) index
    pub akc_index_entries: u64,

    /// Number of entries in the (Author + Tag + CreatedAt + ID) index
    pub atc_index_entries: u64,

    /// Number of entries in the (Kind + Tag + CreatedAt + ID) index
    pub ktc_index_entries: u64,

    /// Number of entries in the deleted IDs index
    pub deleted_index_entries: u64,
}

impl IndexStats {
    /// bytes used by the IDs index
    pub fn i_index_bytes(&self) -> u64 {
        self.i_index_entries * (32 + 8)
    }

    /// bytes used by the (CreatedAt + ID) index
    pub fn ci_index_bytes(&self) -> u64 {
        self.i_index_entries * ((8 + 32) + 8)
    }

    /// bytes used by the (Tag + CreatedAt + ID) index
    pub fn tc_index_bytes(&self) -> u64 {
        self.i_index_entries * ((1 + 182 + 8 + 32) + 8)
    }

    /// bytes used by the (Author + CreatedAt + ID) index
    pub fn ac_index_bytes(&self) -> u64 {
        self.i_index_entries * ((32 + 8 + 32) + 8)
    }

    /// bytes used by the (Author + Kind + CreatedAt + ID) index
    pub fn akc_index_bytes(&self) -> u64 {
        self.i_index_entries * ((32 + 2 + 8 + 32) + 8)
    }

    /// bytes used by the (Author + Tag + CreatedAt + ID) index
    pub fn atc_index_bytes(&self) -> u64 {
        self.i_index_entries * ((32 + 1 + 182 + 8 + 32) + 8)
    }

    /// bytes used by the (Kind + Tag + CreatedAt + ID) index
    pub fn ktc_index_bytes(&self) -> u64 {
        self.i_index_entries * ((2 + 1 + 182 + 8 + 32) + 8)
    }

    /// bytes used by the deleted IDs index
    pub fn deleted_index_bytes(&self) -> u64 {
        self.deleted_index_entries * 32
    }
}

#[derive(Debug)]
pub struct Lmdb {
    env: Env,
    general: Database<Bytes, Bytes>,
    i_index: Database<Bytes, U64<BigEndian>>,
    ci_index: Database<Bytes, U64<BigEndian>>,
    tc_index: Database<Bytes, U64<BigEndian>>,
    ac_index: Database<Bytes, U64<BigEndian>>,
    akc_index: Database<Bytes, U64<BigEndian>>,
    atc_index: Database<Bytes, U64<BigEndian>>,
    ktc_index: Database<Bytes, U64<BigEndian>>,
    deleted_ids: Database<Bytes, Unit>,
}

impl Lmdb {
    pub fn new<P: AsRef<Path>>(directory: P) -> Result<Lmdb, Error> {
        let mut builder = EnvOpenOptions::new();
        unsafe {
            builder.flags(EnvFlags::NO_TLS);
        }
        builder.max_dbs(32);
        builder.map_size(1048576 * 1024 * 24); // 24 GB

        let env = unsafe { builder.open(directory)? };

        // Open/Create maps
        let mut txn = env.write_txn()?;
        let general = env
            .database_options()
            .types::<Bytes, Bytes>()
            .create(&mut txn)?;
        let i_index = env
            .database_options()
            .types::<Bytes, U64<BigEndian>>()
            .name("ids")
            .create(&mut txn)?;
        let ci_index = env
            .database_options()
            .types::<Bytes, U64<BigEndian>>()
            .name("ci")
            .create(&mut txn)?;
        let tc_index = env
            .database_options()
            .types::<Bytes, U64<BigEndian>>()
            .name("tci")
            .create(&mut txn)?;
        let ac_index = env
            .database_options()
            .types::<Bytes, U64<BigEndian>>()
            .name("aci")
            .create(&mut txn)?;
        let akc_index = env
            .database_options()
            .types::<Bytes, U64<BigEndian>>()
            .name("akci")
            .create(&mut txn)?;
        let atc_index = env
            .database_options()
            .types::<Bytes, U64<BigEndian>>()
            .name("atci")
            .create(&mut txn)?;
        let ktc_index = env
            .database_options()
            .types::<Bytes, U64<BigEndian>>()
            .name("ktci")
            .create(&mut txn)?;
        let deleted_ids = env
            .database_options()
            .types::<Bytes, Unit>()
            .name("deleted-ids")
            .create(&mut txn)?;
        txn.commit()?;

        let lmdb = Lmdb {
            env,
            general,
            i_index,
            ci_index,
            tc_index,
            ac_index,
            akc_index,
            atc_index,
            ktc_index,
            deleted_ids,
        };

        Ok(lmdb)
    }

    /// Sync the data to disk. This happens periodically, but sometimes it's useful to force
    /// it.
    pub fn sync(&self) -> Result<(), Error> {
        self.env.force_sync()?;
        Ok(())
    }

    /// Get a read transaction
    pub fn read_txn(&self) -> Result<RoTxn, Error> {
        Ok(self.env.read_txn()?)
    }

    /// Get a write transaction
    pub fn write_txn(&self) -> Result<RwTxn, Error> {
        Ok(self.env.write_txn()?)
    }

    pub fn stats(&self) -> Result<IndexStats, Error> {
        let txn = self.read_txn()?;
        Ok(IndexStats {
            disk_usage: self.env.real_disk_size()?,
            memory_usage: self.env.non_free_pages_size()?,
            general_entries: self.general.len(&txn)?,
            i_index_entries: self.i_index.len(&txn)?,
            ci_index_entries: self.ci_index.len(&txn)?,
            tc_index_entries: self.tc_index.len(&txn)?,
            ac_index_entries: self.ac_index.len(&txn)?,
            akc_index_entries: self.akc_index.len(&txn)?,
            atc_index_entries: self.atc_index.len(&txn)?,
            ktc_index_entries: self.ktc_index.len(&txn)?,
            deleted_index_entries: self.deleted_ids.len(&txn)?,
        })
    }

    // Index the event
    pub fn index(&self, txn: &mut RwTxn<'_>, event: &Event, offset: u64) -> Result<(), Error> {
        // Index by id
        self.i_index.put(txn, event.id().as_slice(), &offset)?;

        // Index by created_at and id
        self.ci_index.put(
            txn,
            &Self::key_ci_index(event.created_at(), event.id()),
            &offset,
        )?;

        // Index by author and kind (with created_at and id)
        self.akc_index.put(
            txn,
            &Self::key_akc_index(event.pubkey(), event.kind(), event.created_at(), event.id()),
            &offset,
        )?;

        self.ac_index.put(
            txn,
            &Self::key_ac_index(event.pubkey(), event.created_at(), event.id()),
            &offset,
        )?;

        for mut tsi in event.tags()?.iter() {
            if let Some(tagname) = tsi.next() {
                // FIXME make sure it is a letter too
                if tagname.len() == 1 {
                    if let Some(tagvalue) = tsi.next() {
                        // Index by tag (with created_at and id)
                        self.tc_index.put(
                            txn,
                            &Self::key_tc_index(
                                tagname[0],
                                tagvalue,
                                event.created_at(),
                                event.id(),
                            ),
                            &offset,
                        )?;

                        // Index by author and tag (with created_at and id)
                        self.atc_index.put(
                            txn,
                            &Self::key_atc_index(
                                event.pubkey(),
                                tagname[0],
                                tagvalue,
                                event.created_at(),
                                event.id(),
                            ),
                            &offset,
                        )?;

                        // Index by kind and tag (with created_at and id)
                        self.ktc_index.put(
                            txn,
                            &Self::key_ktc_index(
                                event.kind(),
                                tagname[0],
                                tagvalue,
                                event.created_at(),
                                event.id(),
                            ),
                            &offset,
                        )?;
                    }
                }
            }
        }

        Ok(())
    }

    // Remove the event from all indexes (except the 'id' index)
    pub fn deindex(&self, txn: &mut RwTxn<'_>, event: &Event) -> Result<(), Error> {
        for mut tsi in event.tags()?.iter() {
            if let Some(tagname) = tsi.next() {
                // FIXME make sure it is a letter too
                if tagname.len() == 1 {
                    if let Some(tagvalue) = tsi.next() {
                        // Index by author and tag (with created_at and id)
                        self.atc_index.delete(
                            txn,
                            &Self::key_atc_index(
                                event.pubkey(),
                                tagname[0],
                                tagvalue,
                                event.created_at(),
                                event.id(),
                            ),
                        )?;

                        // Index by kind and tag (with created_at and id)
                        self.ktc_index.delete(
                            txn,
                            &Self::key_ktc_index(
                                event.kind(),
                                tagname[0],
                                tagvalue,
                                event.created_at(),
                                event.id(),
                            ),
                        )?;

                        // Index by tag (with created_at and id)
                        self.tc_index.delete(
                            txn,
                            &Self::key_tc_index(
                                tagname[0],
                                tagvalue,
                                event.created_at(),
                                event.id(),
                            ),
                        )?;
                    }
                }
            }
        }

        self.ac_index.delete(
            txn,
            &Self::key_ac_index(event.pubkey(), event.created_at(), event.id()),
        )?;

        self.ci_index
            .delete(txn, &Self::key_ci_index(event.created_at(), event.id()))?;

        self.akc_index.delete(
            txn,
            &Self::key_akc_index(event.pubkey(), event.kind(), event.created_at(), event.id()),
        )?;

        // We leave it in the id map. If someone wants to load the replaced event by id
        // they can still do it.
        // self.i_index.delete(&mut txn, event.id().0.as_slice())?;

        Ok(())
    }

    pub fn deindex_id(&self, txn: &mut RwTxn<'_>, id: Id) -> Result<(), Error> {
        self.i_index.delete(txn, id.as_slice())?;
        Ok(())
    }

    pub fn get_offset_by_id(&self, txn: &RoTxn<'_>, id: Id) -> Result<Option<u64>, Error> {
        Ok(self.i_index.get(txn, id.as_slice())?)
    }

    pub fn is_deleted(&self, txn: &RoTxn<'_>, id: Id) -> Result<bool, Error> {
        Ok(self.deleted_ids.get(txn, id.as_slice())?.is_some())
    }

    pub fn mark_deleted(&self, txn: &mut RwTxn<'_>, id: Id) -> Result<(), Error> {
        self.deleted_ids.put(txn, id.as_slice(), &())?;
        Ok(())
    }

    pub fn dump_deleted(&self) -> Result<Vec<Id>, Error> {
        let mut output: Vec<Id> = Vec::new();
        let txn = self.read_txn()?;
        for i in self.deleted_ids.iter(&txn)? {
            let (key, _val) = i?;
            let id = key[0..32].try_into().unwrap(); //.into();
            output.push(id);
        }
        Ok(output)
    }

    pub fn i_iter<'a>(
        &'a self,
        txn: &'a RoTxn,
    ) -> Result<RoIter<'_, Bytes, U64<BigEndian>>, Error> {
        Ok(self.i_index.iter(txn)?)
    }

    pub fn ci_iter<'a>(
        &'a self,
        since: Time,
        until: Time,
        txn: &'a RoTxn,
    ) -> Result<RoRange<'_, Bytes, U64<BigEndian>>, Error> {
        let start_prefix = Self::key_ci_index(until, [0; 32].into());
        let end_prefix = Self::key_ci_index(since, [255; 32].into());
        let range = (
            Bound::Included(&*start_prefix),
            Bound::Excluded(&*end_prefix),
        );
        Ok(self.ci_index.range(txn, &range)?)
    }

    pub fn tc_iter<'a>(
        &'a self,
        tagbyte: u8,
        tagvalue: &[u8],
        since: Time,
        until: Time,
        txn: &'a RoTxn,
    ) -> Result<RoRange<'_, Bytes, U64<BigEndian>>, Error> {
        let start_prefix = Self::key_tc_index(
            tagbyte,
            tagvalue,
            until, // scan goes backwards in time
            [0; 32].into(),
        );
        let end_prefix = Self::key_tc_index(tagbyte, tagvalue, since, [255; 32].into());
        let range = (
            Bound::Included(&*start_prefix),
            Bound::Excluded(&*end_prefix),
        );
        Ok(self.tc_index.range(txn, &range)?)
    }

    pub fn ac_iter<'a>(
        &'a self,
        author: Pubkey,
        since: Time,
        until: Time,
        txn: &'a RoTxn,
    ) -> Result<RoRange<'_, Bytes, U64<BigEndian>>, Error> {
        let start_prefix = Self::key_ac_index(author, until, [0; 32].into());
        let end_prefix = Self::key_ac_index(author, since, [255; 32].into());
        let range = (
            Bound::Included(&*start_prefix),
            Bound::Excluded(&*end_prefix),
        );
        Ok(self.ac_index.range(txn, &range)?)
    }

    pub fn akc_iter<'a>(
        &'a self,
        author: Pubkey,
        kind: Kind,
        since: Time,
        until: Time,
        txn: &'a RoTxn,
    ) -> Result<RoRange<'_, Bytes, U64<BigEndian>>, Error> {
        let start_prefix = Self::key_akc_index(author, kind, until, [0; 32].into());
        let end_prefix = Self::key_akc_index(author, kind, since, [255; 32].into());
        let range = (
            Bound::Included(&*start_prefix),
            Bound::Excluded(&*end_prefix),
        );
        Ok(self.akc_index.range(txn, &range)?)
    }

    pub fn atc_iter<'a>(
        &'a self,
        author: Pubkey,
        tagbyte: u8,
        tagvalue: &[u8],
        since: Time,
        until: Time,
        txn: &'a RoTxn,
    ) -> Result<RoRange<'_, Bytes, U64<BigEndian>>, Error> {
        let start_prefix = Self::key_atc_index(
            author,
            tagbyte,
            tagvalue,
            until, // scan goes backwards in time
            [0; 32].into(),
        );
        let end_prefix = Self::key_atc_index(author, tagbyte, tagvalue, since, [255; 32].into());
        let range = (
            Bound::Included(&*start_prefix),
            Bound::Excluded(&*end_prefix),
        );
        Ok(self.atc_index.range(txn, &range)?)
    }

    pub fn ktc_iter<'a>(
        &'a self,
        kind: Kind,
        tagbyte: u8,
        tagvalue: &[u8],
        since: Time,
        until: Time,
        txn: &'a RoTxn,
    ) -> Result<RoRange<'_, Bytes, U64<BigEndian>>, Error> {
        let start_prefix = Self::key_ktc_index(
            kind,
            tagbyte,
            tagvalue,
            until, // scan goes backwards in time
            [0; 32].into(),
        );
        let end_prefix = Self::key_ktc_index(kind, tagbyte, tagvalue, since, [255; 32].into());
        let range = (
            Bound::Included(&*start_prefix),
            Bound::Excluded(&*end_prefix),
        );
        Ok(self.ktc_index.range(txn, &range)?)
    }

    fn key_ci_index(created_at: Time, id: Id) -> Vec<u8> {
        let mut key: Vec<u8> =
            Vec::with_capacity(std::mem::size_of::<Time>() + std::mem::size_of::<Id>());
        key.extend((u64::MAX - *created_at.deref()).to_be_bytes().as_slice());
        key.extend(id.as_slice());
        key
    }

    // For looking up event by Tag
    // tagletter(1) + fixlentag(182) + reversecreatedat(8) + id(32)
    fn key_tc_index(letter: u8, tag_value: &[u8], created_at: Time, id: Id) -> Vec<u8> {
        const PADLEN: usize = 182;
        let mut key: Vec<u8> =
            Vec::with_capacity(PADLEN + std::mem::size_of::<Time>() + std::mem::size_of::<Id>());
        key.push(letter);
        if tag_value.len() <= PADLEN {
            key.extend(tag_value);
            key.extend(core::iter::repeat(0).take(PADLEN - tag_value.len()));
        } else {
            key.extend(&tag_value[..PADLEN]);
        }
        key.extend((u64::MAX - *created_at.deref()).to_be_bytes().as_slice());
        key.extend(id.as_slice());
        key
    }

    // For looking up event by Author
    // author(32) + reversecreatedat(8) + id(32)
    fn key_ac_index(author: Pubkey, created_at: Time, id: Id) -> Vec<u8> {
        let mut key: Vec<u8> = Vec::with_capacity(
            std::mem::size_of::<Pubkey>() + std::mem::size_of::<Time>() + std::mem::size_of::<Id>(),
        );
        key.extend(author.as_slice());
        key.extend((u64::MAX - *created_at.deref()).to_be_bytes().as_slice());
        key.extend(id.as_slice());
        key
    }

    // For looking up event by Author and Kind
    // author(32) + kind(2) + reversecreatedat(8) + id(32)
    fn key_akc_index(author: Pubkey, kind: Kind, created_at: Time, id: Id) -> Vec<u8> {
        let mut key: Vec<u8> = Vec::with_capacity(
            std::mem::size_of::<Pubkey>()
                + std::mem::size_of::<Kind>()
                + std::mem::size_of::<Time>()
                + std::mem::size_of::<Id>(),
        );
        key.extend(author.as_slice());
        key.extend(kind.deref().to_be_bytes());
        key.extend((u64::MAX - *created_at.deref()).to_be_bytes().as_slice());
        key.extend(id.as_slice());
        key
    }

    // For looking up event by Author and Tag
    // author(32) + tagletter(1) + fixlentag(182) + reversecreatedat(8) + id(32)
    fn key_atc_index(
        author: Pubkey,
        letter: u8,
        tag_value: &[u8],
        created_at: Time,
        id: Id,
    ) -> Vec<u8> {
        const PADLEN: usize = 182;
        let mut key: Vec<u8> = Vec::with_capacity(
            std::mem::size_of::<Pubkey>()
                + PADLEN
                + std::mem::size_of::<Time>()
                + std::mem::size_of::<Id>(),
        );
        key.extend(author.as_slice());
        key.push(letter);
        if tag_value.len() <= PADLEN {
            key.extend(tag_value);
            key.extend(core::iter::repeat(0).take(PADLEN - tag_value.len()));
        } else {
            key.extend(&tag_value[..PADLEN]);
        }
        key.extend((u64::MAX - *created_at.deref()).to_be_bytes().as_slice());
        key.extend(id.as_slice());
        key
    }

    // For looking up event by Kind and Tag
    // kind(2) + tagletter(1) + fixlentag(182) + reversecreatedat(8) + id(32)
    fn key_ktc_index(
        kind: Kind,
        letter: u8,
        tag_value: &[u8],
        created_at: Time,
        id: Id,
    ) -> Vec<u8> {
        const PADLEN: usize = 182;
        let mut key: Vec<u8> = Vec::with_capacity(
            std::mem::size_of::<Kind>()
                + PADLEN
                + std::mem::size_of::<Time>()
                + std::mem::size_of::<Id>(),
        );
        key.extend(kind.deref().to_be_bytes());
        key.push(letter);
        if tag_value.len() <= PADLEN {
            key.extend(tag_value);
            key.extend(core::iter::repeat(0).take(PADLEN - tag_value.len()));
        } else {
            key.extend(&tag_value[..PADLEN]);
        }
        key.extend((u64::MAX - *created_at.deref()).to_be_bytes().as_slice());
        key.extend(id.as_slice());
        key
    }
}
