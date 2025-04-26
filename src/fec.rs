//! Systematic Reed-Solomon (18,20) over 1 182-byte symbols.

use bytes::Bytes;
use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::util::{HTDNSError, Result};

pub const K: usize       = 18;
pub const N: usize       = 20;
pub const PARITY: usize  = N - K;
pub const SYMBOL_SIZE: usize = 1_182;

pub struct FecEngine { rs: ReedSolomon }
impl FecEngine {
    pub fn new() -> Result<Self> {
        Ok(Self { rs: ReedSolomon::new(K, PARITY).map_err(|_| HTDNSError::Fec)? })
    }

    pub fn encode_block(&self, data: &[Bytes]) -> Result<Vec<Bytes>> {
        if data.len() != K || data.iter().any(|b| b.len() != SYMBOL_SIZE) {
            return Err(HTDNSError::Fec);
        }
        let mut shards: Vec<Vec<u8>> = data.iter().map(|b| b.to_vec()).collect();
        shards.extend((0..PARITY).map(|_| vec![0u8; SYMBOL_SIZE]));
        self.rs.encode(&mut shards).map_err(|_| HTDNSError::Fec)?;
        Ok(shards.into_iter().map(Bytes::from).collect())
    }

    pub fn decode_block(&self, shards: &mut [Option<Bytes>]) -> Result<Vec<Bytes>> {
        if shards.len() != N { return Err(HTDNSError::Fec); }
        let mut tmp: Vec<Option<Vec<u8>>> = shards.iter_mut().map(|o| o.take().map(|b| b.to_vec())).collect();
        self.rs.reconstruct(&mut tmp).map_err(|_| HTDNSError::Fec)?;
        for (slot, v) in shards.iter_mut().zip(tmp.into_iter()) { *slot = v.map(Bytes::from); }
        Ok(shards[..K].iter().map(|o| o.clone().unwrap()).collect())
    }
}
