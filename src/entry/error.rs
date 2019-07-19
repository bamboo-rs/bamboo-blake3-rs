use snafu::Snafu;
use std::io::Error as IoError;
use varu64::DecodeError as varu64DecodeError;

use crate::signature::Error as SigError;
use crate::yamf_hash::Error as HashError;
use crate::yamf_signatory::Error as SignatoryError;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(in crate::entry)")]
pub enum Error {
    //All the ways encoding an entry can fail
    #[snafu(display("Error when encoding is_end_of_feed: {}", source))]
    EncodeIsEndOfFeedError { source: IoError },
    #[snafu(display("Error when encoding payload hash: {}", source))]
    EncodePayloadHashError { source: HashError },
    #[snafu(display("Error when encoding payload size: {}", source))]
    EncodePayloadSizeError { source: IoError },
    #[snafu(display("Error when encoding author pub key: {}", source))]
    EncodeAuthorError { source: SignatoryError },
    #[snafu(display("Error when encoding sequence number: {}", source))]
    EncodeSeqError { source: IoError },
    #[snafu(display("Error when encoding backlink: {}", source))]
    EncodeBacklinkError { source: HashError },
    #[snafu(display("Error when encoding lipmaa link: {}", source))]
    EncodeLipmaaError { source: HashError },
    #[snafu(display("Error when encoding signature of entry. {}", source))]
    EncodeSigError { source: SigError },
    #[snafu(display("Error when encoding entry with seq 0 that has backlinks or lipmaalinks"))]
    EncodeEntryHasBacklinksWhenSeqZero,

    //All the ways decoding an entry can fail
    #[snafu(display("Error when decoding is_end_of_feed: {}", source))]
    DecodeIsEndOfFeedError { source: IoError },
    #[snafu(display("Error when decoding payload hash: {}", source))]
    DecodePayloadHashError { source: HashError },
    #[snafu(display("Error when decoding payload size: {}", source))]
    DecodePayloadSizeError { source: varu64DecodeError },
    #[snafu(display("Error when decoding author pub key: {}", source))]
    DecodeAuthorError { source: SignatoryError },
    #[snafu(display("Error when decoding sequence number: {}", source))]
    DecodeSeqError { source: varu64DecodeError },
    #[snafu(display("Error when decoding backlink: {}", source))]
    DecodeBacklinkError { source: HashError },
    #[snafu(display("Error when decoding lipmaa link: {}", source))]
    DecodeLipmaaError { source: HashError },
    #[snafu(display("Error when decoding signature of entry. {}", source))]
    DecodeSigError { source: SigError },

    #[snafu(display("Error when decoding, input had length 0"))]
    DecodeInputIsLengthZero,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;