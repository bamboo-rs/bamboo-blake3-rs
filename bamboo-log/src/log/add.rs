use super::Log;
use crate::entry::decode;
use crate::entry_store::EntryStore;
use crate::yamf_hash::new_blake2b;
use lipmaa_link::lipmaa;

use crate::error::*;

impl<Store: EntryStore> Log<Store> {
    /// Add a valid message to the Log.
    ///
    /// Typically you would use this when you have an entry published by some other author and you
    /// want to add it to your store. This method does a bunch of checking to make sure the entry
    /// is legit.
    ///
    /// Caveat:
    /// - the lipmaa link that this message references must already exist in the Log. That means if you
    /// are doing partial replication, you must sort your messages by sequence number and add them
    /// from oldest to newest.
    pub fn add(&mut self, entry_bytes: &[u8], payload: Option<&[u8]>) -> Result<()> {
        // Decode the entry that we want to add.
        let entry = decode(entry_bytes).map_err(|_| Error::AddEntryDecodeFailed)?;

        // If we have the payload, check that its hash and length match what is encoded in the
        // entry.
        if let Some(payload) = payload {
            let payload_hash = new_blake2b(payload);
            if payload_hash != entry.payload_hash {
                return Err(Error::AddEntryPayloadHashDidNotMatch)
            }
            if payload.len() as u64 != entry.payload_size {
                return Err(Error::AddEntryPayloadLengthDidNotMatch)
            }
        }

        let lipmaa_seq = match lipmaa(entry.seq_num) {
            0 => 1,
            n => n,
        };

        // Get the lipmaa entry.
        let lipmaa = self.store.get_entry_ref(lipmaa_seq);

        match (lipmaa, entry.lipmaa_link, entry.seq_num) {
            // Happy path 1: this is the first entry, so we won't find a lipmaa link in the store
            (Ok(None), None, seq_num) if seq_num == 1 => Ok(()),
            // Happy path 2: seq is larger than one and we can find the lipmaa link in the store
            (Ok(Some(lipmaa)), Some(ref entry_lipmaa), seq_num) if seq_num > 1 => {
                // Hash the lipmaa entry
                let lipmaa_hash = new_blake2b(lipmaa);
                // Make sure the lipmaa entry hash matches what's in the entry.
                if lipmaa_hash != *entry_lipmaa {
                    return Err(Error::AddEntryLipmaaHashDidNotMatch);
                }

                // Verify the author of the entry is the same as the author in the lipmaa link entry
                let lipmaa_entry = decode(lipmaa).map_err(|_| Error::AddEntryDecodeLipmaalinkFromStore)?;

                if entry.author != lipmaa_entry.author {
                    return Err(Error::AddEntryAuthorDidNotMatchLipmaaEntry);
                }
                Ok(())
            }
            (_, _, _) => Err(Error::AddEntryNoLipmaalinkInStore),
        }?;

        // Try and get the backlink entry. If we have it, hash it and check it is correct.
        let backlink = self.store.get_entry_ref(entry.seq_num - 1);

        match (backlink, entry.backlink, entry.seq_num) {
            // Happy path 1: This is the first entry and doesn't have a backlink.
            (_, None, seq_num) if seq_num == 1 => Ok(()),

            //Happy path 2: This does have a backlink and we found it.
            (Ok(Some(backlink)), Some(ref entry_backlink), seq_num) if seq_num > 1 => {
                let backlink_hash = new_blake2b(backlink);

                if backlink_hash != *entry_backlink {
                    return Err(Error::AddEntryBacklinkHashDidNotMatch);
                }
                Ok(())
            }
            //Happy path 3: We don't have the backlink for this entry, happens when doing partial
            //replication.
            (Ok(None), Some(_), seq_num) if seq_num > 1 => Ok(()),
            (_, _, _) => Err(Error::AddEntryBacklinkHashDidNotMatch),
        }?;

        // Get the last entry in the log and make sure it's not an end of feed message.
        // Only do this check if the store isn't empty.
        if self.store.get_last_seq() > 0 {
            let last_entry_bytes = self
                .store
                .get_last_entry_ref()
                .map_err(|_| Error::AddEntryGetLastEntryError)?
                .ok_or(Error::AddEntryGetLastEntryNotFound)?;

            let last_entry = decode(last_entry_bytes).map_err(|_| Error::AddEntryDecodeLastEntry)?;
            if last_entry.is_end_of_feed {
                return Err(Error::AddEntryToFeedThatHasEnded)
            }
        }

        // Verify the signature.
        let mut entry_to_verify =
            decode(&entry_bytes).map_err(|_| Error::AddEntryDecodeEntryBytesForSigning)?;
        let is_valid = entry_to_verify
            .verify_signature()
            .map_err(|_| Error::AddEntrySigNotValidError)?;
        if !is_valid {
            return Err(Error::AddEntryWithInvalidSignature)
        }

        //Ok, store it!
        self.store
            .add_entry(&entry_bytes, entry.seq_num)
            .map_err(|_| Error::AppendFailed)
    }
}

#[cfg(test)]
mod tests {
    use crate::entry_store::MemoryEntryStore;
    use crate::log::{Error, Log};
    use crate::signature::{Signature, ED25519_SIGNATURE_SIZE};
    use crate::yamf_hash::{new_blake2b, YamfHash};
    use crate::yamf_signatory::YamfSignatory;
    use crate::{Entry, EntryStore};
    use arrayvec::ArrayVec;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use std::convert::TryInto;

    fn n_valid_entries(n: u64) -> Log<MemoryEntryStore> {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let mut log = Log::new(
            MemoryEntryStore::new(),
            keypair.public.clone(),
            Some(keypair),
        );

        (1..n).into_iter().for_each(|i| {
            let payload = format!("message number {}", i);
            log.publish(&payload.as_bytes(), false).unwrap();
        });

        log
    }

    #[test]
    fn add_checks_payload_is_correct_length() {
        let remote_log = n_valid_entries(3);

        let mut log: Log<MemoryEntryStore> =
            Log::new(MemoryEntryStore::new(), remote_log.public_key, None);

        let mut first_entry: Entry<&[u8], &[u8], &[u8]> = remote_log
            .store
            .get_entry_ref(1)
            .unwrap()
            .unwrap()
            .try_into()
            .unwrap();

        first_entry.payload_size = 1; //Set an invalid payload length. Zero tolerance etc ;)

        let entry_bytes: ArrayVec<_> = first_entry.try_into().unwrap();

        match log.add(&entry_bytes, Some(b"message number 1")) {
            Err(Error::AddEntryPayloadLengthDidNotMatch { backtrace: _ }) => {}
            _ => panic!("Expected err"),
        }
    }

    #[test]
    fn add_checks_payload_is_correct_hash() {
        let remote_log = n_valid_entries(3);

        let mut log: Log<MemoryEntryStore> =
            Log::new(MemoryEntryStore::new(), remote_log.public_key, None);

        let first_entry = remote_log.store.get_entry(1).unwrap().unwrap();

        match log.add(&first_entry, Some(&[0, 1])) {
            Err(Error::AddEntryPayloadHashDidNotMatch { backtrace: _ }) => {}
            _ => panic!("Expected err"),
        }
    }

    #[test]
    fn add_checks_entry_not_after_end_of_feed() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let mut remote_log = Log::new(
            MemoryEntryStore::new(),
            keypair.public.clone(),
            Some(keypair),
        );

        let payload = format!("message number {}", 1);
        remote_log.publish(&payload.as_bytes(), true).unwrap();

        let first_entry = remote_log.store.get_entry_ref(1).unwrap().unwrap();

        let backlink = new_blake2b(first_entry);
        let lipmaa_link = new_blake2b(first_entry);

        let mut second_entry = Entry::<_, _, &[u8]> {
            is_end_of_feed: false,
            payload_hash: new_blake2b(&payload.as_bytes()),
            payload_size: payload.len() as u64,
            author: YamfSignatory::Ed25519(&remote_log.public_key.as_bytes()[..], None),
            seq_num: 2,
            backlink: Some(backlink),
            lipmaa_link: Some(lipmaa_link),
            sig: None,
        };

        let mut second_entry_bytes = Vec::new();
        second_entry.encode_write(&mut second_entry_bytes).unwrap();

        let signature = remote_log.key_pair.unwrap().sign(&second_entry_bytes);
        let sig_bytes = &signature.to_bytes()[..];
        let signature = Signature(sig_bytes.into());

        second_entry.sig = Some(signature);

        let mut second_entry_bytes = Vec::new();
        second_entry.encode_write(&mut second_entry_bytes).unwrap();

        let mut log: Log<MemoryEntryStore> =
            Log::new(MemoryEntryStore::new(), remote_log.public_key, None);

        log.add(&first_entry, None).unwrap();

        match log.add(&second_entry_bytes, None) {
            Err(Error::AddEntryToFeedThatHasEnded { backtrace: _ }) => {}
            _ => panic!("Expected err"),
        }
    }

    #[test]
    fn add_needs_lipmaa_link_in_store() {
        let remote_log = n_valid_entries(3);

        let mut log: Log<MemoryEntryStore> =
            Log::new(MemoryEntryStore::new(), remote_log.public_key, None);

        let second_entry = remote_log.store.get_entry(2).unwrap().unwrap();

        match log.add(&second_entry, None) {
            Err(Error::AddEntryNoLipmaalinkInStore) => {}
            _ => panic!("Expected err"),
        }
    }

    #[test]
    fn add_needs_valid_signature() {
        let remote_log = n_valid_entries(3);

        let mut log: Log<MemoryEntryStore> =
            Log::new(MemoryEntryStore::new(), remote_log.public_key, None);

        let mut first_entry: Entry<&[u8], &[u8], &[u8]> = remote_log
            .store
            .get_entry_ref(1)
            .unwrap()
            .unwrap()
            .try_into()
            .unwrap();

        let incorrect_sig_bytes = [0u8; ED25519_SIGNATURE_SIZE];
        first_entry.sig = match first_entry.sig {
            Some(Signature(_)) => Some(Signature(&incorrect_sig_bytes)),
            link => link,
        };

        let entry_bytes: ArrayVec<_> = first_entry.try_into().unwrap();

        match log.add(&entry_bytes, None) {
            Err(Error::AddEntryWithInvalidSignature { backtrace: _ }) => {}
            _ => panic!("Expected err"),
        }
    }

    #[test]
    fn add_checks_lipmaa_link_is_valid() {
        let remote_log = n_valid_entries(3);

        let mut log: Log<MemoryEntryStore> =
            Log::new(MemoryEntryStore::new(), remote_log.public_key, None);

        let first_entry_bytes = remote_log.store.get_entry(1).unwrap().unwrap();
        let mut second_entry: Entry<&[u8], &[u8], &[u8]> = remote_log
            .store
            .get_entry_ref(2)
            .unwrap()
            .unwrap()
            .try_into()
            .unwrap();

        log.add(&first_entry_bytes, None)
            .expect("error adding first entry, this is not normal");

        let incorrect_lipmaa = new_blake2b(b"noooo");

        second_entry.lipmaa_link = match second_entry.lipmaa_link {
            Some(YamfHash::Blake2b(_)) => Some(YamfHash::from(&incorrect_lipmaa)),
            link => link,
        }; //set the lipmaa link to be zero

        let entry_bytes: ArrayVec<_> = second_entry.try_into().unwrap();

        match log.add(&entry_bytes, None) {
            Err(Error::AddEntryLipmaaHashDidNotMatch) => {}
            _ => panic!("Expected err"),
        }
    }

    #[test]
    fn add_checks_backlink_is_valid() {
        let remote_log = n_valid_entries(3);

        let mut log: Log<MemoryEntryStore> =
            Log::new(MemoryEntryStore::new(), remote_log.public_key, None);

        let first_entry_bytes = remote_log.store.get_entry(1).unwrap().unwrap();

        let mut second_entry: Entry<_, _, _> = remote_log
            .store
            .get_entry_ref(2)
            .unwrap()
            .unwrap()
            .try_into()
            .unwrap();

        log.add(&first_entry_bytes, None)
            .expect("error adding first entry, this is not normal");

        let incorrect_backlink = new_blake2b(b"noooo");
        second_entry.backlink = match second_entry.backlink {
            Some(YamfHash::Blake2b(_)) => Some(YamfHash::from(&incorrect_backlink)),
            link => link,
        }; //set the lipmaa link to be zero

        let entry_bytes: ArrayVec<_> = second_entry.try_into().unwrap();

        match log.add(&entry_bytes, None) {
            Err(Error::AddEntryBacklinkHashDidNotMatch) => {}
            _ => panic!("Expected err"),
        }
    }
    #[test]
    fn add_checks_lipmaa_link_is_present() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let mut remote_log = Log::new(
            MemoryEntryStore::new(),
            keypair.public.clone(),
            Some(keypair),
        );

        let payload = format!("message number {}", 1);
        remote_log.publish(&payload.as_bytes(), false).unwrap();

        let first_entry = remote_log.store.get_entry_ref(1).unwrap().unwrap();

        let backlink = new_blake2b(first_entry);

        let mut second_entry = Entry::<_, _, &[u8]> {
            is_end_of_feed: false,
            payload_hash: new_blake2b(&payload.as_bytes()),
            payload_size: payload.len() as u64,
            author: YamfSignatory::Ed25519(&remote_log.public_key.as_bytes()[..], None),
            seq_num: 2,
            backlink: Some(backlink),
            lipmaa_link: None,
            sig: None,
        };

        let mut second_entry_bytes = Vec::new();
        second_entry.encode_write(&mut second_entry_bytes).unwrap();

        let signature = remote_log.key_pair.unwrap().sign(&second_entry_bytes);
        let sig_bytes = &signature.to_bytes()[..];
        let signature = Signature(sig_bytes.into());

        second_entry.sig = Some(signature);

        let mut second_entry_bytes = Vec::new();
        second_entry.encode_write(&mut second_entry_bytes).unwrap();

        let mut log: Log<MemoryEntryStore> =
            Log::new(MemoryEntryStore::new(), remote_log.public_key, None);

        log.add(&first_entry, None).unwrap();

        match log.add(&second_entry_bytes, None) {
            Err(Error::AddEntryDecodeFailed { source: _ }) => {}
            e => panic!("Expected err, {:?}", e),
        }
    }
    #[test]
    fn add_checks_back_link_is_present() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let mut remote_log = Log::new(
            MemoryEntryStore::new(),
            keypair.public.clone(),
            Some(keypair),
        );

        let payload = format!("message number {}", 1);
        remote_log.publish(&payload.as_bytes(), false).unwrap();

        let first_entry = remote_log.store.get_entry_ref(1).unwrap().unwrap();

        let lipmaa_link = new_blake2b(first_entry);

        let mut second_entry = Entry::<_, _, &[u8]> {
            is_end_of_feed: false,
            payload_hash: new_blake2b(&payload.as_bytes()),
            payload_size: payload.len() as u64,
            author: YamfSignatory::Ed25519(&remote_log.public_key.as_ref()[..], None),
            seq_num: 2,
            backlink: None,
            lipmaa_link: Some(lipmaa_link),
            sig: None,
        };

        let mut second_entry_bytes = Vec::new();
        second_entry.encode_write(&mut second_entry_bytes).unwrap();

        let signature = remote_log.key_pair.unwrap().sign(&second_entry_bytes);
        let sig_bytes = &signature.to_bytes()[..];
        let signature = Signature(sig_bytes.into());

        second_entry.sig = Some(signature);

        let mut second_entry_bytes = Vec::new();
        second_entry.encode_write(&mut second_entry_bytes).unwrap();

        let mut log: Log<MemoryEntryStore> =
            Log::new(MemoryEntryStore::new(), remote_log.public_key, None);

        log.add(&first_entry, None).unwrap();

        match log.add(&second_entry_bytes, None) {
            Err(Error::AddEntryDecodeFailed { source: _ }) => {}
            e => panic!("Expected err, {:?}", e),
        }
    }
}