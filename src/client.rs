//! HT-DNS client – local HTTP proxy + Turbo-Tunnel reliability (demo).

use bytes::Bytes;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    sync::{mpsc, Mutex},
    time,
};

use crate::{
    crypto::{CryptoContext, CryptoProvider},
    fec::{FecEngine, K, N},
    proto::{Frame, Reassembler, DEFAULT_MTU},
    util::{packet_engine::PacketEngine, HTDNSError, Result},
};

const WINDOW:    usize = 256;
const RETRAN_MS: u64   = 100;

/* ---------- config ---------- */
#[derive(Clone)]
pub struct ClientConfig {
    pub server:     SocketAddr,
    pub local:      SocketAddr,
    pub raw:        bool,
    pub workers:    usize,
    pub busy_poll:  bool,
    pub psk:        [u8; 32],
}
impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server:    SocketAddr::from(([127,0,0,1], 53)),
            local:     SocketAddr::from(([0,0,0,0], 0)),
            raw:       false,
            workers:   1,
            busy_poll: false,
            psk:       [0u8; 32],
        }
    }
}

/* ---------- proxy commands ---------- */
enum ProxyCmd { Request(Bytes) }

/* ---------- client ---------- */
pub trait Client { fn start(self) -> Result<()>; }

pub struct HTDNSClient { cfg: ClientConfig }
impl HTDNSClient {
    pub fn new(cfg: ClientConfig) -> Result<Self> { Ok(Self { cfg }) }

    async fn http_proxy_loop(tx: mpsc::Sender<ProxyCmd>) -> Result<()> {
        let lst = TcpListener::bind(\"127.0.0.1:8080\").await?;
        loop {
            let (mut sock, _) = lst.accept().await?;
            let tx2 = tx.clone();
            tokio::spawn(async move {
                let _ = Self::handle_http(&mut sock, tx2).await;
            });
        }
    }

    async fn handle_http(s: &mut TcpStream, tx: mpsc::Sender<ProxyCmd>) -> Result<()> {
        let mut buf = [0u8; 4096];
        let n = s.read(&mut buf).await?;
        if n == 0 { return Ok(()); }
        if let Some(line) = std::str::from_utf8(&buf[..n]).ok().and_then(|s| s.lines().next()) {
            let p: Vec<_> = line.split_whitespace().collect();
            if p.len() >= 2 && p[0] == \"GET\" {
                tx.send(ProxyCmd::Request(Bytes::copy_from_slice(p[1].as_bytes()))).await.ok();
                s.write_all(b\"HTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n\").await?;
            }
        }
        Ok(())
    }

    fn fragment(payload: &[u8], mtu: usize) -> Vec<Bytes> {
        payload.chunks(mtu).map(Bytes::copy_from_slice).collect()
    }
}

impl Client for HTDNSClient {
    fn start(self) -> Result<()> {
        // packet engine plumbing
        let (eng_tx, mut eng_rx) = mpsc::channel::<(Bytes, SocketAddr)>(16*1024);
        let (cli_tx, mut cli_rx) = mpsc::channel::<(Bytes, SocketAddr)>(16*1024);
        for _ in 0..self.cfg.workers.max(1) {
            let tx_clone = eng_tx.clone();
            let mut pe   = PacketEngine::new(self.cfg.local, tx_clone, self.cfg.raw, self.cfg.busy_poll)?;
            let mut rx   = cli_rx.clone();
            std::thread::spawn(move || {
                while let Ok((b, a)) = rx.blocking_recv() { pe.queue(b, a); }
                let _ = pe.run();
            });
        }

        // async runtime
        Runtime::new()?.block_on(async move {
            // proxy thread
            let (p_tx, mut p_rx) = mpsc::channel::<ProxyCmd>(1024);
            tokio::spawn(Self::http_proxy_loop(p_tx.clone()));

            let ctx  = CryptoContext::new(&self.cfg.psk, b\"ht-dns\");
            let fec  = FecEngine::new()?;
            let mut reasm  = Reassembler::new();
            let mut shards = vec![None; N];
            let mut seq: u32 = 0;
            let mut inflight: BTreeMap<u32, (Instant, Bytes, Duration)> = BTreeMap::new();
            let mut tick = time::interval(Duration::from_millis(RETRAN_MS));

            loop {
                tokio::select! {
                    Some((pkt,_)) = eng_rx.recv() => {
                        if let Ok(outer) = Frame::decode(&pkt) {
                            if let Ok(pt) = ctx.open(outer.payload) {
                                if let Ok(inner) = Frame::decode(&pt) {
                                    inflight.remove(&inner.seq);
                                    for data in reasm.push(inner) {
                                        let idx = (inner.seq as usize) % N;
                                        shards[idx] = Some(data);
                                        if shards.iter().filter(|s| s.is_some()).count() == K {
                                            let mut tmp = shards.clone();
                                            let mut opt: Vec<Option<Bytes>> = tmp.into_iter().collect();
                                            let _ = fec.decode_block(&mut opt); // ignore body
                                            shards = vec![None; N];
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(cmd) = p_rx.recv() => {
                        if let ProxyCmd::Request(body) = cmd {
                            for part in Self::fragment(&body, DEFAULT_MTU) {
                                let inner = Frame { stream_id: 0, seq: seq & 0xFF_FFFF, payload: &part };
                                let mut buf_i = vec![0u8; 6 + part.len()];
                                let n = inner.encode(&mut buf_i)?;
                                let cipher = ctx.seal(&buf_i[..n])?;
                                let outer  = Frame { stream_id: 0, seq: seq & 0xFF_FFFF, payload: &cipher };
                                let mut buf_o = vec![0u8; 6 + cipher.len()];
                                let m = outer.encode(&mut buf_o)?;
                                let bytes = Bytes::copy_from_slice(&buf_o[..m]);
                                cli_tx.send((bytes.clone(), self.cfg.server)).await?;
                                inflight.insert(seq, (Instant::now(), bytes, Duration::from_millis(RETRAN_MS)));
                                seq = seq.wrapping_add(1);
                            }
                        }
                    },
                    _ = tick.tick() => {
                        let now = Instant::now();
                        for (s, (ts, data, to)) in inflight.iter_mut() {
                            if now.duration_since(*ts) >= *to {
                                *ts = now;
                                *to *= 2;
                                cli_tx.send((data.clone(), self.cfg.server)).await?;
                            }
                        }
                    }
                }
            }
        })
    }
}
