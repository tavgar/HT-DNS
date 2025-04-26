//! HT-DNS binary frame and Turbo-Tunnel re-assembler.

use bytes::Bytes;
use std::collections::BTreeMap;

use crate::util::{HTDNSError, Result};

pub const DEFAULT_MTU: usize = 1232;
pub const MAX_MTU:     usize = 4096;

/* ---------- frame ---------- */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    pub stream_id: u8,
    pub seq:       u32,      // 24-bit
    pub payload:   &'a [u8],
}
impl<'a> Frame<'a> {
    const HEADER: usize = 2 + 1 + 3; // len + id + seq24

    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        if self.seq >= (1 << 24) || self.payload.len() > MAX_MTU { return Err(HTDNSError::Protocol); }
        let need = Self::HEADER + self.payload.len();
        if out.len() < need { return Err(HTDNSError::Protocol); }
        let frame_len = (need - 2) as u16;
        out[..2].copy_from_slice(&frame_len.to_be_bytes());
        out[2] = self.stream_id;
        out[3] = (self.seq >> 16) as u8;
        out[4] = (self.seq >> 8)  as u8;
        out[5] =  self.seq        as u8;
        out[6..need].copy_from_slice(self.payload);
        Ok(need)
    }

    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        if buf.len() < Self::HEADER { return Err(HTDNSError::Protocol); }
        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if len + 2 != buf.len() || len < 4 { return Err(HTDNSError::Protocol); }
        let seq = ((buf[3] as u32) << 16) | ((buf[4] as u32) << 8) | buf[5] as u32;
        Ok(Frame { stream_id: buf[2], seq, payload: &buf[6..] })
    }
}

/* ---------- re-assembler ---------- */
pub struct Reassembler {
    next_seq: u32,
    window:   BTreeMap<u32, Bytes>,
    bitmap:   u64,
}
impl Reassembler {
    pub fn new() -> Self { Self { next_seq: 0, window: BTreeMap::new(), bitmap: 0 } }

    pub fn push<'b>(&mut self, frame: Frame<'b>) -> Vec<Bytes> {
        let mut ready = Vec::new();
        let seq = frame.seq;
        if seq < self.next_seq || seq.wrapping_sub(self.next_seq) >= 64 {
            return ready; // duplicate / way behind / too far ahead
        }
        self.window.entry(seq).or_insert_with(|| Bytes::copy_from_slice(frame.payload));
        while let Some(data) = self.window.remove(&self.next_seq) {
            ready.push(data);
            self.next_seq = (self.next_seq + 1) & 0xFF_FFFF;
        }
        self.bitmap = 0;
        for (&s, _) in self.window.range(self.next_seq..self.next_seq + 64) {
            let diff = s.wrapping_sub(self.next_seq);
            if diff < 64 { self.bitmap |= 1 << diff; }
        }
        ready
    }

    pub fn ack_base(&self)   -> u32 { self.next_seq }
    pub fn ack_bitmap(&self) -> u64 { self.bitmap  }
}
