use crate::signature::Error as SigError;
use snafu::Snafu;
use yasmf_hash::error::Error as YasmfHashError;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(super)")]
pub enum Error {
    #[snafu(display("`out` buffer to encode into was length 0"))]
    EncodeBufferLength,
    #[snafu(display("Encode lipmaa link to yamf hash failed: {}", source))]
    EncodeLipmaaError { source: YasmfHashError },
    #[snafu(display("Encode back link to yamf hash failed: {}", source))]
    EncodeBacklinkError { source: YasmfHashError },
    #[snafu(display(
        "Lipmaa or backlinks were provided for first entry which should be impossible"
    ))]
    EncodeEntryHasLinksWhenSeqZero,
    #[snafu(display("Encode payload size failed"))]
    EncodePayloadSizeError,
    #[snafu(display("Encode payload hash failed: {}", source))]
    EncodePayloadHashError { source: YasmfHashError },
    #[snafu(display("Encode is_end_of_feed failed"))]
    EncodeIsEndOfFeedError,
    #[snafu(display("Encode author pub key failed"))]
    EncodeAuthorError,
    #[snafu(display("Encode log_id failed"))]
    EncodeLogIdError,
    #[snafu(display("Encode signature failed: {}", source))]
    EncodeSigError { source: SigError },
    #[snafu(display("Encode seq_num failed"))]
    EncodeSeqError,
    #[snafu(display("Entry seq_num was 0 which is not valid"))]
    EncodeSeqIsZero,
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
