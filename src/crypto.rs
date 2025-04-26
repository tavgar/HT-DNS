//! Session crypto: XChaCha20-Poly1305 + HKDF-SHA256 (self-contained, no extra crates).

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

use crate::util::{HTDNSError, Result};

/* ---------- public trait ---------- */
pub trait CryptoProvider {
    fn seal(&self, plaintext: &[u8])  -> Result<Vec<u8>>;
    fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/* ---------- context ---------- */
pub struct CryptoContext {
    cipher: XChaCha20Poly1305,
}

impl CryptoContext {
    pub fn new(psk: &[u8; 32], info: &[u8]) -> Self {
        let key = hkdf_sha256(psk, info);
        Self {
            cipher: XChaCha20Poly1305::new_from_slice(&key).unwrap(),
        }
    }

    pub fn seal_frame(
        &self,
        nonce: &[u8; 24],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>> {
        self.cipher
            .encrypt(XNonce::from_slice(nonce), Payload { msg: pt, aad })
            .map_err(|_| HTDNSError::Crypto)
    }

    pub fn open_frame(
        &self,
        nonce: &[u8; 24],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>> {
        self.cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
            .map_err(|_| HTDNSError::Crypto)
    }
}

/* ---------- zero-nonce helpers (demo) ---------- */
impl CryptoProvider for CryptoContext {
    fn seal(&self, pt: &[u8])  -> Result<Vec<u8>> { self.seal_frame(&[0u8; 24], b"", pt) }
    fn open(&self, ct: &[u8])  -> Result<Vec<u8>> { self.open_frame(&[0u8; 24], b"", ct) }
}

/* ---------- compact HKDF-SHA256 (no external crate) ---------- */
fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let salt = [0u8; 32];
    let prk  = hmac_sha256(&salt, ikm);
    let mut t = Vec::with_capacity(info.len() + 1);
    t.extend_from_slice(info);
    t.push(1);
    hmac_sha256(&prk, &t)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    fn xor_pad(dst: &mut [u8; 64], src: &[u8], byte: u8) {
        for i in 0..64 {
            dst[i] = (if i < src.len() { src[i] } else { 0 }) ^ byte;
        }
    }

    let mut k0 = [0u8; 64];
    if key.len() > 64 {
        k0[..32].copy_from_slice(&sha256(key));
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    xor_pad(&mut ipad, &k0, 0x36);
    xor_pad(&mut opad, &k0, 0x5c);

    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/* ---------- tiny, pure-Rust SHA-256 (not constant-time) ---------- */
fn sha256(msg: &[u8]) -> [u8; 32] {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ];

    // --- padding ---
    let bit_len = (msg.len() as u64) * 8;
    let mut padded = Vec::from(msg);
    padded.push(0x80);
    while (padded.len() + 8) % 64 != 0 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // --- process blocks ---
    let mut h = H0;
    let mut w = [0u32; 64];

    for chunk in padded.chunks(64) {
        for (i, w_i) in w.iter_mut().enumerate().take(16) {
            *w_i = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7)
                    ^ w[i - 15].rotate_right(18)
                    ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17)
                    ^ w[i - 2].rotate_right(19)
                    ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, &v) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}
