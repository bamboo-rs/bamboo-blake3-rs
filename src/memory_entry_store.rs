use super::entry_store::{EntryStore, Error, GetEntrySequenceInvalid, Result};
use snafu::ensure;
use std::io::Write;

pub struct MemoryEntryStore {
    pub store: Vec<Vec<u8>>,
}

impl MemoryEntryStore {
    pub fn new() -> MemoryEntryStore {
        MemoryEntryStore { store: Vec::new() }
    }
    pub fn clear(&mut self) {
        self.store.clear()
    }
}

impl EntryStore for MemoryEntryStore {
    fn get_last_seq(&self) -> u64 {
        self.store.len() as u64
    }
    fn get_entry(&self, seq_num: u64) -> Result<Vec<u8>> {
        ensure!(seq_num > 0, GetEntrySequenceInvalid { seq_num });
        self.store
            .get(seq_num as usize - 1)
            .map(|vec| vec.to_vec())
            .ok_or(Error::GetEntrySequenceInvalid { seq_num })
    }
    fn get_entry_ref<'a>(&'a self, seq_num: u64) -> Result<&'a [u8]> {
        ensure!(seq_num != 0, GetEntrySequenceInvalid { seq_num });
        self.store
            .get(seq_num as usize - 1)
            .map(|vec| vec.as_slice())
            .ok_or(Error::GetEntrySequenceInvalid { seq_num })
    }
    fn get_last_entry(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.store.last().map(|item| item.clone()))
    }
    fn get_last_entry_ref<'a>(&'a self) -> Result<Option<&'a [u8]>> {
        Ok(self.store.last().map(|item| &item[..]))
    }
    fn append_entry(&mut self, entry: &[u8]) -> Result<()> {
        let mut vec = Vec::with_capacity(entry.len());
        vec.extend_from_slice(entry);
        self.store.push(vec);
        Ok(())
    }
    fn get_writer_for_next_entry(&mut self) -> &mut dyn Write {
        let vec = Vec::new();
        self.store.push(vec);
        self.store.last_mut().unwrap()
    }
}
