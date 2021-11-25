use bamboo_blake3_rs_core::entry::decode;
use bamboo_blake3_rs_core::signature::ED25519_SIGNATURE_SIZE;
use bamboo_blake3_rs_core::HASH_LEN;
use core::slice;
use ed25519_dalek::PUBLIC_KEY_LENGTH;

mod error;
use error::DecodeError;

#[repr(C)]
pub struct CEntry {
    pub log_id: u64,
    pub is_end_of_feed: bool,
    pub payload_hash_bytes: [u8; HASH_LEN],
    pub payload_length: u64,
    pub author: [u8; PUBLIC_KEY_LENGTH],
    pub seq_num: u64,
    pub backlink: [u8; HASH_LEN],
    pub has_backlink: bool,
    pub lipmaa_link: [u8; HASH_LEN],
    pub has_lipmaa_link: bool,
    pub sig: [u8; ED25519_SIGNATURE_SIZE],
}

#[repr(C)]
pub struct DecodeEd25519Blade2bEntryArgs<'a> {
    pub out_decoded_entry: CEntry,
    pub entry_bytes: &'a u8,
    pub entry_length: usize,
}

/// Attempts to decode bytes as an entry.
///
/// Returns `Error` which will have a value of `0` if decoding was
/// successful.
#[no_mangle]
pub extern "C" fn decode_ed25519_blake2b_entry(
    args: &mut DecodeEd25519Blade2bEntryArgs,
) -> DecodeError {
    let entry_slice = unsafe { slice::from_raw_parts(args.entry_bytes, args.entry_length) };

    decode(entry_slice)
        .map_err(|err| err.into())
        .and_then::<(), _>(|entry| {
            args.out_decoded_entry.log_id = entry.log_id;
            args.out_decoded_entry.is_end_of_feed = entry.is_end_of_feed;
            args.out_decoded_entry.seq_num = entry.seq_num;
            args.out_decoded_entry.payload_length = entry.payload_size;
            args.out_decoded_entry.has_backlink = entry.backlink.is_some();
            args.out_decoded_entry.has_lipmaa_link = entry.lipmaa_link.is_some();

            if let Some(sig) = entry.sig {
                args.out_decoded_entry.sig[..].copy_from_slice(sig.0);
            }

            if let Some(lipmaa_link) = entry.lipmaa_link {
                args.out_decoded_entry.lipmaa_link[..].copy_from_slice(lipmaa_link.as_bytes())
            }
            if let Some(backlink) = entry.backlink {
                args.out_decoded_entry.backlink[..].copy_from_slice(backlink.as_bytes())
            }
            args.out_decoded_entry.payload_hash_bytes[..]
                .copy_from_slice(entry.payload_hash.as_bytes());

            args.out_decoded_entry.author[..].copy_from_slice(&entry.author.as_bytes()[..]);

            Err(DecodeError::NoError)
        })
        .unwrap_err()
}
