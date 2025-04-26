//! MassDNS-style batch UDP engine (single thread, edge-triggered).
//! Linux-only: uses `sendmmsg` / `recvmmsg` & `SO_BUSY_POLL`.

use bytes::Bytes;
use mio::{Events, Interest, Poll, Token};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    os::unix::io::{AsRawFd, RawFd},
    time::Duration,
};
use tokio::sync::mpsc::Sender;

use crate::util::{HTDNSError, Result};

const TOKEN_SOCK: Token = Token(0);
const RING: usize = 1_024;
const BATCH: usize = 32;
const MAX_PKT: usize = 4096 + 64;
const SO_BUSY_POLL: i32 = 50; // linux constant

pub struct PacketEngine {
    sock: mio::net::UdpSocket,
    fd:   RawFd,
    poll: Poll,
    tx:   Sender<(Bytes, SocketAddr)>,
    send_q: VecDeque<(Bytes, SocketAddr)>,
}

impl PacketEngine {
    pub fn new(
        bind:      SocketAddr,
        tx:        Sender<(Bytes, SocketAddr)>,
        raw:       bool,
        busy_poll: bool,
    ) -> Result<Self> {
        let domain = if bind.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let ty     = if raw { Type::RAW } else { Type::DGRAM };
        let sock   = Socket::new(domain, ty.nonblocking(), Some(Protocol::UDP))?;
        sock.bind(&bind.into())?;
        if busy_poll { set_busy_poll(sock.as_raw_fd(), 20_000) } // 20 µs
        let fd   = sock.as_raw_fd();
        let std  = sock.into_udp_socket();
        let mut mio_sock = mio::net::UdpSocket::from_std(std);
        let poll = Poll::new()?;
        poll.registry()
            .register(&mut mio_sock, TOKEN_SOCK, Interest::READABLE | Interest::WRITABLE)?;
        Ok(Self { sock: mio_sock, fd, poll, tx, send_q: VecDeque::with_capacity(RING) })
    }

    /// enqueue outbound packet
    pub fn queue(&mut self, pkt: Bytes, dst: SocketAddr) {
        if self.send_q.len() < RING {
            self.send_q.push_back((pkt, dst));
        }
    }

    /// blocking polling loop – call inside dedicated thread
    pub fn run(&mut self) -> Result<()> {
        let mut events = Events::with_capacity(64);
        loop {
            self.poll.poll(&mut events, None)?;
            for ev in events.iter() {
                if ev.token() == TOKEN_SOCK {
                    if ev.is_readable()  { self.recv_batch()?; }
                    if ev.is_writable()  { self.flush_send()?; }
                }
            }
        }
    }

    fn flush_send(&mut self) -> Result<()> {
        while !self.send_q.is_empty() {
            let burst = BATCH.min(self.send_q.len());
            let mut batch = MsgBatch::new();
            for _ in 0..burst {
                let (pkt, addr) = self.send_q.pop_front().unwrap();
                batch.push(pkt, addr);
            }
            batch.send(self.fd)?;
        }
        Ok(())
    }

    fn recv_batch(&mut self) -> Result<()> {
        let mut batch = RecvBatch::new();
        let n = batch.recv(self.fd)?;
        for i in 0..n {
            if let Some(bytes) = batch.take(i) {
                // best-effort: drop if channel full
                let _ = self.tx.blocking_send((bytes, SocketAddr::new([0,0,0,0].into(), 0)));
            }
        }
        Ok(())
    }
}

/* ---------- linux helpers ---------- */
#[cfg(target_os = "linux")]
fn set_busy_poll(fd: RawFd, usec: u32) {
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_BUSY_POLL,
            &usec as *const _ as *const _,
            std::mem::size_of::<u32>() as _,
        );
    }
}

/* ---------- FFI for sendmmsg / recvmmsg ---------- */
#[repr(C)] struct Iovec   { base: *mut u8, len: usize }
#[repr(C)] struct Msghdr  {
    name: *mut u8, namelen: u32,
    iov: *mut Iovec, iovlen: usize,
    control: *mut u8, controllen: usize,
    flags: i32,
}
#[repr(C)] struct Mmsghdr { hdr: Msghdr, len: u32 }
#[repr(C)] struct Timespec { tv_sec: i64, tv_nsec: i64 }

extern "C" {
    fn sendmmsg(fd: i32, msgvec: *mut Mmsghdr, vlen: u32, flags: i32) -> i32;
    fn recvmmsg(fd: i32, msgvec: *mut Mmsghdr, vlen: u32, flags: i32, timeout: *mut Timespec) -> i32;
}

/* ---------- batching structs ---------- */
struct MsgBatch { bufs: Vec<Bytes>, addrs: Vec<SocketAddr> }
impl MsgBatch {
    fn new() -> Self { Self { bufs: Vec::with_capacity(BATCH), addrs: Vec::with_capacity(BATCH) } }
    fn push(&mut self, pkt: Bytes, addr: SocketAddr) { self.bufs.push(pkt); self.addrs.push(addr); }
    fn send(self, fd: RawFd) -> Result<()> {
        if self.bufs.is_empty() { return Ok(()); }
        let mut mm: Vec<Mmsghdr> = Vec::with_capacity(self.bufs.len());
        let mut iovecs: Vec<Iovec> = Vec::with_capacity(self.bufs.len());
        for (pkt, addr) in self.bufs.into_iter().zip(self.addrs.into_iter()) {
            let mut iov = Iovec { base: pkt.as_ptr() as *mut u8, len: pkt.len() };
            let mut hdr = Msghdr {
                name:    &addr as *const _ as *mut u8,
                namelen: std::mem::size_of::<SocketAddr>() as u32,
                iov:     &mut iov,
                iovlen:  1,
                control: std::ptr::null_mut(),
                controllen: 0,
                flags:   0,
            };
            mm.push(Mmsghdr { hdr, len: 0 });
            iovecs.push(iov); // keep ownership until syscall returns
        }
        let ret = unsafe { sendmmsg(fd, mm.as_mut_ptr(), mm.len() as u32, 0) };
        if ret < 0 { Err(HTDNSError::Io(io::Error::last_os_error())) } else { Ok(()) }
    }
}

struct RecvBatch { bufs: Vec<Vec<u8>>, mm: Vec<Mmsghdr> }
impl RecvBatch {
    fn new() -> Self {
        let mut bufs = Vec::with_capacity(BATCH);
        let mut mm   = Vec::with_capacity(BATCH);
        for _ in 0..BATCH {
            let mut buf = vec![0u8; MAX_PKT];
            let iov  = Iovec { base: buf.as_mut_ptr(), len: MAX_PKT };
            let hdr  = Msghdr { name: std::ptr::null_mut(), namelen: 0,
                                iov: &mut { let p = Box::into_raw(Box::new(iov)); unsafe { &mut *p } },
                                iovlen: 1, control: std::ptr::null_mut(),
                                controllen: 0, flags: 0 };
            mm.push(Mmsghdr { hdr, len: 0 });
            bufs.push(buf);
        }
        Self { bufs, mm }
    }
    fn recv(&mut self, fd: RawFd) -> Result<usize> {
        let ret = unsafe { recvmmsg(fd, self.mm.as_mut_ptr(), self.mm.len() as u32, 0, std::ptr::null_mut()) };
        if ret < 0 { Err(HTDNSError::Io(io::Error::last_os_error())) } else { Ok(ret as usize) }
    }
    fn take(&mut self, idx: usize) -> Option<Bytes> {
        if idx >= self.bufs.len() { return None; }
        let len = self.mm[idx].len as usize;
        if len == 0 { return None; }
        Some(Bytes::copy_from_slice(&self.bufs[idx][..len]))
    }
}
