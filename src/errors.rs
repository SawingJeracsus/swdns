use std::{error, fmt::Display, io, net::UdpSocket};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum BytePacketBufferError {
    #[error("Position out of the buffer size")]
    PosOutOfRange,
    #[error("Range don't fit in the buffer size")]
    RangeOutOfTheBuffer,
    #[error("Maximum jumps exceeded, Limit is - {limit}")]
    MaxJumpsExceeded { limit: usize },
    #[error("Label error should be smaller then 64 symbol length. Len received - {length} for the lable {label} in the input {input}")]
    LabelLengthTooBig {
        length: usize,
        label: String,
        input: String,
    },
}

pub type DnsServerResult<T> = Result<T, DnsServerError>;

#[derive(Error, Debug)]
pub enum DnsServerError {
    #[error("Udp Error occured - {error}")]
    UdpError { error: io::Error },
    #[error("Buffer error occured - {error}")]
    BytePacketBufferErr { error: BytePacketBufferError },
    #[error("Packet is corrupted. Sent id - {sent_id}, received id - {received_id}")]
    PacketIdCorrupted { sent_id: u16, received_id: u16 },
}

impl From<io::Error> for DnsServerError {
    fn from(err: io::Error) -> Self {
        Self::UdpError { error: err }
    }
}

impl From<BytePacketBufferError> for DnsServerError {
    fn from(err: BytePacketBufferError) -> Self {
        Self::BytePacketBufferErr { error: err }
    }
}
