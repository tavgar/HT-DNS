//! Session crypto: XChaCha20-Poly1305 with HKDF-SHA256.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

use crate::util::{HTDNSError, Result};

/* ---------- public trait ---------- */
pub trait CryptoProvider {
    fn seal(&self, plaintext: &[u8])      -> Result<Vec<u8>>;
    fn open(&self, ciphertext: &[u8])     -> Result<Vec<u8>>;
}

/* ---------- context ---------- */
pub struct CryptoContext { cipher: XChaCha20Poly1305 }
impl CryptoContext {
    pub fn new(psk: &[u8; 32], info: &[u8]) -> Self {
        let key = hkdf_sha256(psk, info);
        Self { cipher: XChaCha20Poly1305::new_from_slice(&key).unwrap() }
    }

    pub fn seal_frame(&self, nonce: &[u8; 24], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        self.cipher.encrypt(XNonce::from_slice(nonce), Payload { msg: pt, aad })
                   .map_err(|_| HTDNSError::Crypto)
    }
    pub fn open_frame(&self, nonce: &[u8; 24], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        self.cipher.decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
                   .map_err(|_| HTDNSError::Crypto)
    }
}

/* ---------- trait impl (zero-nonce convenience) ---------- */
impl CryptoProvider for CryptoContext {
    fn seal(&self, pt: &[u8])  -> Result<Vec<u8>> { self.seal_frame(&[0u8;24], b\"\", pt) }
    fn open(&self, ct: &[u8])  -> Result<Vec<u8>> { self.open_frame(&[0u8;24], b\"\", ct) }
}

/* ---------- HKDF-SHA256 (minimal) ---------- */
fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let salt = [0u8; 32];
    let prk  = hmac_sha256(&salt, ikm);
    let mut out = info.to_vec();
    out.push(1u8);
    hmac_sha256(&prk, &out)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k0 = [0u8; 64];
    if key.len() > 64 { k0[..32].copy_from_slice(&sha256(key)); }
    else               { k0[..key.len()].copy_from_slice(key); }

    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }

    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/* ---------- toy SHA-256 (not constant-time, for HKDF only) ---------- */
fn sha256(msg: &[u8]) -> [u8; 32] {
    use sha2::Digest; // only in std lib since 1.77? – replace with tiny v if absent
    let hash = sha2::Sha256::digest(msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}
