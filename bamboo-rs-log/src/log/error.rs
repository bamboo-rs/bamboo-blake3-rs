use snafu::Snafu;
use core::fmt::Debug;
use bamboo_rs_core_ed25519_yasmf::entry::decode::Error as DecodeError;
use bamboo_rs_core_ed25519_yasmf::entry::verify::Error as VerifyError;
use bamboo_rs_core_ed25519_yasmf::entry::publish::Error as PublishError;
use crate::entry_store::EntryStore;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
pub enum Error<ES: EntryStore + Debug> {
    AddEntryDecodeFailed{source: DecodeError},
    AddEntryGetLipmaaEntry{source: ES::Error},
    AddEntryGetBacklinkEntry{source: ES::Error},
    AddEntryFailedVerification{source: VerifyError},
    AddEntryFailedToAddEntryToLog{source: ES::Error},
    PublishEntryGetLipmaaEntry{source: ES::Error},
    PublishEntryGetBacklinkEntry{source: ES::Error},
    PublishNewEntryFailed{source: PublishError},
    PublishEntryAppendFailed{source: ES::Error},
    PublishWithoutKeypair,
}
