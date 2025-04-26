//! Minimal HT-DNS server skeleton – crypto/FEC inbound only.

use bytes::Bytes;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    runtime::Runtime,
    sync::{mpsc, Mutex},
};

use crate::{
    crypto::{CryptoContext, CryptoProvider},
    fec::{FecEngine, K, N},
    proto::{Frame, Reassembler},
    util::{packet_engine::PacketEngine, HTDNSError, Result},
};

pub type ConnId = SocketAddr;

/* ---------- config ---------- */
#[derive(Clone)]
pub struct ServerConfig {
    pub bind:        SocketAddr,
    pub raw:         bool,
    pub workers:     usize,
    pub busy_poll:   bool,
    pub psk:         [u8; 32],
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind:        SocketAddr::from(([0,0,0,0], 53)),
            raw:         false,
            workers:     1,
            busy_poll:   false,
            psk:         [0u8;32],
        }
    }
}

/* ---------- session ---------- */
struct SessionState {
    crypto: CryptoContext,
    reasm:  Reassembler,
    fec:    FecEngine,
    shards: Vec<Option<Bytes>>,
}
impl SessionState {
    fn new(psk: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            crypto: CryptoContext::new(psk, b\"ht-dns\"),
            reasm:  Reassembler::new(),
            fec:    FecEngine::new()?,
            shards: vec![None; N],
        })
    }
}

/* ---------- server ---------- */
pub trait Server { fn start(self) -> Result<()>; }

pub struct HTDNSServer { cfg: ServerConfig }
impl HTDNSServer {
    pub fn new(cfg: ServerConfig) -> Result<Self> { Ok(Self { cfg }) }
}

impl Server for HTDNSServer {
    fn start(self) -> Result<()> {
        let (eng_tx, mut eng_rx) = mpsc::channel::<(Bytes, SocketAddr)>(16*1024);

        // spawn packet engine thread(s)
        for _ in 0..self.cfg.workers.max(1) {
            let tx_clone = eng_tx.clone();
            let mut pe   = PacketEngine::new(self.cfg.bind, tx_clone, self.cfg.raw, self.cfg.busy_poll)?;
            std::thread::spawn(move || { let _ = pe.run(); });
        }

        // map: conn -> session
        let sessions = Arc::new(Mutex::new(HashMap::<ConnId, SessionState>::new()));
        let psk      = self.cfg.psk;

        Runtime::new()?.block_on(async move {
            while let Some((pkt, addr)) = eng_rx.recv().await {
                let mut map = sessions.lock().await;
                let sess = map.entry(addr).or_insert_with(|| SessionState::new(&psk).unwrap());

                let outer = Frame::decode(&pkt)?;
                let plain = sess.crypto.open(outer.payload)?;
                let inner = Frame::decode(&plain)?;
                let ready = sess.reasm.push(inner);
                for chunk in ready {
                    let idx = (inner.seq as usize) % N;
                    sess.shards[idx] = Some(chunk);
                    if sess.shards.iter().filter(|s| s.is_some()).count() == K {
                        let mut tmp = sess.shards.clone();
                        let mut opt: Vec<Option<Bytes>> = tmp.into_iter().collect();
                        sess.fec.decode_block(&mut opt)?; // decoded data dropped (demo)
                        sess.shards = vec![None; N];
                    }
                }
            }
            Result::<()>::Ok(())
        })
    }
}
