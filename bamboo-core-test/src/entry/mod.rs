#[cfg(test)]
mod tests {

    use bamboo_core::entry::{decode, MAX_ENTRY_SIZE_};
    use bamboo_core::yamf_hash::BLAKE2B_HASH_SIZE;
    use bamboo_core::Error;
    use bamboo_core::{publish, verify, Entry, Signature, YamfHash, YamfSignatory};
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use varu64::encode_write as varu64_encode_write;

    #[test]
    fn encode_write_decode_entry() {
        let backlink_bytes = [0xAA; BLAKE2B_HASH_SIZE];
        let backlink = YamfHash::<&[u8]>::Blake2b(backlink_bytes[..].into());
        let payload_hash_bytes = [0xAB; BLAKE2B_HASH_SIZE];
        let payload_hash = YamfHash::<&[u8]>::Blake2b(payload_hash_bytes[..].into());
        let lipmaa_link_bytes = [0xAC; BLAKE2B_HASH_SIZE];
        let lipmaa_link = YamfHash::<&[u8]>::Blake2b(lipmaa_link_bytes[..].into());
        let payload_size = 512;
        let seq_num = 2;
        let sig_bytes = [0xDD; 128];
        let sig = Signature(&sig_bytes[..]);
        let author_bytes = [0xEE; 32];
        let author = YamfSignatory::Ed25519(&author_bytes[..], None);

        let mut entry_vec = Vec::new();

        entry_vec.push(1u8); // end of feed is true

        payload_hash.encode_write(&mut entry_vec).unwrap();
        varu64_encode_write(payload_size, &mut entry_vec).unwrap();
        author.encode_write(&mut entry_vec).unwrap();
        varu64_encode_write(seq_num, &mut entry_vec).unwrap();
        backlink.encode_write(&mut entry_vec).unwrap();
        lipmaa_link.encode_write(&mut entry_vec).unwrap();
        sig.encode_write(&mut entry_vec).unwrap();

        let entry = decode(&entry_vec).unwrap();

        match entry.payload_hash {
            YamfHash::Blake2b(ref hash) => {
                assert_eq!(hash.as_ref(), &payload_hash_bytes[..]);
            }
        }

        match entry.backlink {
            Some(YamfHash::Blake2b(ref hash)) => {
                assert_eq!(hash.as_ref(), &backlink_bytes[..]);
            }
            _ => panic!(),
        }
        match entry.lipmaa_link {
            Some(YamfHash::Blake2b(ref hash)) => {
                assert_eq!(hash.as_ref(), &lipmaa_link_bytes[..]);
            }
            _ => panic!(),
        }

        match entry.sig {
            Some(Signature(ref sig)) => {
                assert_eq!(sig.as_ref(), &sig_bytes[..]);
            }
            _ => panic!(),
        }

        match entry.author {
            YamfSignatory::Ed25519(ref auth, None) => {
                assert_eq!(auth.as_ref(), &author_bytes[..]);
            }
            _ => panic!(),
        }

        let mut encoded = Vec::new();

        entry.encode_write(&mut encoded).unwrap();

        assert_eq!(encoded, entry_vec);

        let mut encoded = [0u8; 512];

        let size = entry.encode(&mut encoded).unwrap();

        assert_eq!(&encoded[..size], &entry_vec[..]);
    }

    #[test]
    fn publish_first_entry() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let key_pair: Keypair = Keypair::generate(&mut csprng);

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = publish(
            &mut out,
            Some(&key_pair),
            payload.as_bytes(),
            false,
            0,
            None,
            None,
        )
        .unwrap();

        let mut entry = decode(&out[..size]).unwrap();
        assert!(entry.verify_signature().unwrap());
    }

    #[test]
    fn publish_entry_with_backlinks() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let key_pair: Keypair = Keypair::generate(&mut csprng);

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = publish(
            &mut out,
            Some(&key_pair),
            payload.as_bytes(),
            false,
            0,
            None,
            None,
        )
        .unwrap();

        let mut out2 = [0u8; 512];
        let size2 = publish(
            &mut out2,
            Some(&key_pair),
            payload.as_bytes(),
            false,
            1,
            Some(&out[..size]),
            Some(&out[..size]),
        )
        .unwrap();
        let mut entry2 = decode(&out2[..size2]).unwrap();

        assert!(entry2.verify_signature().unwrap());
    }
    #[test]
    fn publish_entry_with_missing_lipmaalink_errors() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let key_pair: Keypair = Keypair::generate(&mut csprng);

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = publish(
            &mut out,
            Some(&key_pair),
            payload.as_bytes(),
            false,
            0,
            None,
            None,
        )
        .unwrap();

        let mut out2 = [0u8; 512];

        match publish(
            &mut out2,
            Some(&key_pair),
            payload.as_bytes(),
            false,
            1,
            None,
            Some(&out[..size]),
        ) {
            Err(Error::PublishWithoutLipmaaEntry) => {}
            _ => panic!(),
        }
    }
    #[test]
    fn publish_entry_with_missing_backlink_errors() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let key_pair: Keypair = Keypair::generate(&mut csprng);

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = publish(
            &mut out,
            Some(&key_pair),
            payload.as_bytes(),
            false,
            0,
            None,
            None,
        )
        .unwrap();

        let mut out2 = [0u8; 512];

        match publish(
            &mut out2,
            Some(&key_pair),
            payload.as_bytes(),
            false,
            1,
            Some(&out[..size]),
            None,
        ) {
            Err(Error::PublishWithoutBacklinkEntry) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn publish_after_an_end_of_feed_message_errors() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let key_pair: Keypair = Keypair::generate(&mut csprng);

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = publish(
            &mut out,
            Some(&key_pair),
            payload.as_bytes(),
            true,
            0,
            None,
            None,
        )
        .unwrap();

        let mut out2 = [0u8; 512];
        match publish(
            &mut out2,
            Some(&key_pair),
            payload.as_bytes(),
            false,
            1,
            Some(&out[..size]),
            Some(&out[..size]),
        ) {
            Err(Error::PublishAfterEndOfFeed) => {}
            _ => panic!(),
        }
    }
    #[test]
    fn publish_with_out_buffer_too_small() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let key_pair: Keypair = Keypair::generate(&mut csprng);

        let payload = "hello bamboo!";
        let mut out = [0u8; 1];

        match publish(
            &mut out,
            Some(&key_pair),
            payload.as_bytes(),
            false,
            0,
            None,
            None,
        ) {
            Err(Error::EncodeBufferLength) => {}
            _ => {}
        }
    }

    #[test]
    fn publish_without_secret_key_errors() {
        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        match publish(&mut out, None, payload.as_bytes(), false, 0, None, None) {
            Err(Error::PublishWithoutKeypair) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn serde_entry() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let key_pair: Keypair = Keypair::generate(&mut csprng);

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = publish(
            &mut out,
            Some(&key_pair),
            payload.as_bytes(),
            false,
            0,
            None,
            None,
        )
        .unwrap();

        let entry = decode(&out[..size]).unwrap();

        let string = serde_json::to_string(&entry).unwrap();
        let parsed: Entry<Vec<u8>, Vec<u8>, Vec<u8>> = serde_json::from_str(&string).unwrap();

        assert_eq!(parsed.payload_hash, entry.payload_hash);
    }
    fn log_max_entry_size() {
        println!("max entry size is {:?}", MAX_ENTRY_SIZE_)
    }

    #[test]
    fn verify_entries() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let key_pair: Keypair = Keypair::generate(&mut csprng);

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = publish(
            &mut out,
            Some(&key_pair),
            payload.as_bytes(),
            false,
            0,
            None,
            None,
        )
        .unwrap();

        let mut out2 = [0u8; 512];
        let size2 = publish(
            &mut out2,
            Some(&key_pair),
            payload.as_bytes(),
            false,
            1,
            Some(&out[..size]),
            Some(&out[..size]),
        )
        .unwrap();

        let entry1_bytes = &out[..size];

        match verify(entry1_bytes, Some(payload.as_bytes()), None, None) {
            Ok(true) => {}
            err => panic!("{:?}", err),
        }

        let entry2_bytes = &out2[..size2];

        match verify(
            entry2_bytes,
            Some(payload.as_bytes()),
            Some(entry1_bytes),
            Some(entry1_bytes),
        ) {
            Ok(true) => {}
            err => panic!("{:?}", err),
        }
    }
}