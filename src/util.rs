//! Common helpers & error types.

use thiserror::Error;

pub mod packet_engine;

pub type Result<T> = std::result::Result<T, HTDNSError>;

#[derive(Debug, Error)]
pub enum HTDNSError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol error")]
    Protocol,

    #[error("Crypto error")]
    Crypto,

    #[error("FEC error")]
    Fec,
}
