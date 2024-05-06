/// Statistics about the indexes
#[derive(Debug, Clone)]
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

    /// Number of entries in the deleted naddr index
    pub deleted_naddr_index_entries: u64,

    /// Number of entries in custom databases
    pub custom_entries: Vec<(&'static str, u64)>,
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

    /// bytes used by the deleted naddr index
    pub fn deleted_naddr_index_bytes(&self) -> u64 {
        self.deleted_naddr_index_entries * (2 + 32 + 1 + 182)
    }
}
