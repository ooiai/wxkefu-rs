#![allow(dead_code)]
//! Key generation utilities for WeChat Customer Service callbacks.
//!
//! This module provides functions to generate:
//! - Token: an alphanumeric string (default 32 chars; max 32), used for SHA1 signature verification.
//! - EncodingAESKey: a 43-character Base64 string (letters/digits only, no padding) that decodes to 32 bytes
//!   when appending a single '='. Used to derive the AES-256 key for decrypting callback messages.
//!
//! No external dependencies are used. Entropy is sourced from /dev/urandom when available,
//! otherwise a best-effort pseudo-random generator is used. For production, prefer a proper CSPRNG.

use std::fs::File;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

/// Generate an alphanumeric Token of given length (default 32; allowed 1..=32).
///
/// Returns a string consisting of [A-Za-z0-9].
pub fn generate_token(len: usize) -> String {
    let len = if len == 0 || len > 32 { 32 } else { len };
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    // Fill entropy and map bytes to alnum indices.
    let mut buf = vec![0u8; len];
    fill_entropy(&mut buf);

    let mut out = String::with_capacity(len);
    for b in buf {
        out.push(ALNUM[(b as usize) % ALNUM.len()] as char);
    }
    out
}

/// Generate a 43-character EncodingAESKey (alphanumeric only) derived from 32 random bytes.
/// Appending a single '=' must decode back to 32 bytes when treated as standard Base64.
/// Per WeChat spec: "由英文或数字组成" means ONLY [A-Za-z0-9], no +/ symbols.
/// Uses rejection sampling to ensure the Base64 output contains no '+' or '/' characters.
pub fn generate_encoding_aes_key() -> String {
    loop {
        let mut key_bytes = [0u8; 32];
        fill_entropy(&mut key_bytes);

        let b64 = base64_encode(&key_bytes);
        let trimmed = b64.trim_end_matches('=').to_string();

        // WeChat requires exactly 43 chars with only alphanumeric characters (no +/)
        if trimmed.len() == 43 && trimmed.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return trimmed;
        }
    }
}

/// Verify the provided EncodingAESKey format:
/// - exactly 43 characters
/// - Base64-decodes to 32 bytes after appending '='
pub fn verify_encoding_aes_key(key: &str) -> bool {
    if key.len() != 43 {
        return false;
    }
    // Append '=' (standard for 32-byte key, results in 44 chars)
    let with_pad = format!("{key}=");
    match base64_decode(&with_pad) {
        Ok(bytes) => bytes.len() == 32,
        Err(_) => false,
    }
}

/// Fill the provided buffer with random bytes.
/// Attempts to read from /dev/urandom; if unavailable, uses a best-effort fallback PRNG.
fn fill_entropy(dst: &mut [u8]) {
    if try_fill_from_urandom(dst) {
        return;
    }
    // Fallback: xorshift64* PRNG seeded from system time and address data (not cryptographically secure).
    let mut seed = seed_from_system();
    for chunk in dst.chunks_mut(8) {
        seed = xorshift64star(seed);
        let bytes = seed.to_ne_bytes();
        let take = chunk.len().min(8);
        chunk.copy_from_slice(&bytes[..take]);
    }
}

/// Attempt to fill from /dev/urandom (Unix). Returns true on success.
#[cfg(unix)]
fn try_fill_from_urandom(dst: &mut [u8]) -> bool {
    if let Ok(mut f) = File::open("/dev/urandom") {
        let mut read_total = 0usize;
        while read_total < dst.len() {
            match f.read(&mut dst[read_total..]) {
                Ok(0) => break,
                Ok(n) => read_total += n,
                Err(_) => return false,
            }
        }
        return read_total == dst.len();
    }
    false
}

/// Non-Unix stub: /dev/urandom not available.
#[cfg(not(unix))]
fn try_fill_from_urandom(_dst: &mut [u8]) -> bool {
    false
}

/// Seed from system time, process, and address hints (best-effort).
fn seed_from_system() -> u64 {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or_else(|_| 0u64);
    let pid = std::process::id() as u64;
    let addr = (&t as *const u64 as usize) as u64;
    // Mix values using a simple xor and multiply
    t ^ (pid.wrapping_mul(0x9E3779B185EBCA87)) ^ (addr.rotate_left(17))
}

/// xorshift64* PRNG step
fn xorshift64star(mut x: u64) -> u64 {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    x.wrapping_mul(0x2545F4914F6CDD1D)
}

/// Standard Base64 encoding (A-Z a-z 0-9 + /), with '=' padding.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let len = input.len();
    let out_len = 4 * ((len + 2) / 3);
    let mut out = String::with_capacity(out_len);

    let mut i = 0;
    while i + 3 <= len {
        let b0 = input[i];
        let b1 = input[i + 1];
        let b2 = input[i + 2];
        i += 3;

        let v = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(ALPHABET[((v >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((v >> 12) & 0x3F) as usize] as char);
        out.push(ALPHABET[((v >> 6) & 0x3F) as usize] as char);
        out.push(ALPHABET[(v & 0x3F) as usize] as char);
    }

    let rem = len - i;
    if rem == 1 {
        let b0 = input[i];
        let v = (b0 as u32) << 16;
        out.push(ALPHABET[((v >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((v >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let b0 = input[i];
        let b1 = input[i + 1];
        let v = ((b0 as u32) << 16) | ((b1 as u32) << 8);
        out.push(ALPHABET[((v >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((v >> 12) & 0x3F) as usize] as char);
        out.push(ALPHABET[((v >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }

    out
}

/// Base64 decoding for standard alphabet (no whitespace handling).
fn base64_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let bytes = s.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err("length not multiple of 4");
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let c0 = bytes[i];
        let c1 = bytes[i + 1];
        let c2 = bytes[i + 2];
        let c3 = bytes[i + 3];
        i += 4;

        let v0 = val(c0).ok_or("invalid char")?;
        let v1 = val(c1).ok_or("invalid char")?;
        let v2 = if c2 == b'=' {
            0
        } else {
            val(c2).ok_or("invalid char")?
        };
        let v3 = if c3 == b'=' {
            0
        } else {
            val(c3).ok_or("invalid char")?
        };

        let t = ((v0 as u32) << 18) | ((v1 as u32) << 12) | ((v2 as u32) << 6) | (v3 as u32);
        out.push(((t >> 16) & 0xFF) as u8);
        if c2 != b'=' {
            out.push(((t >> 8) & 0xFF) as u8);
        }
        if c3 != b'=' {
            out.push((t & 0xFF) as u8);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_alnum_and_length() {
        for &len in &[8usize, 16, 32] {
            let t = generate_token(len);
            assert_eq!(t.len(), len);
            assert!(t.chars().all(|ch| ch.is_ascii_alphanumeric()));
        }
        // length above max clamps to 32
        let t = generate_token(64);
        assert_eq!(t.len(), 32);
        assert!(t.chars().all(|ch| ch.is_ascii_alphanumeric()));
        // length 0 defaults to 32
        let t = generate_token(0);
        assert_eq!(t.len(), 32);
    }

    #[test]
    fn b64_roundtrip() {
        let data = b"The quick brown fox jumps over the lazy dog.";
        let enc = base64_encode(data);
        let dec = base64_decode(&enc).expect("decode");
        assert_eq!(dec, data);
    }

    #[test]
    fn encoding_aes_key_generation_and_verify() {
        let key = generate_encoding_aes_key();
        assert_eq!(key.len(), 43);
        assert!(verify_encoding_aes_key(&key));

        // Make sure decode yields exactly 32 bytes
        let with_pad = format!("{key}=");
        let raw = base64_decode(&with_pad).expect("decode");
        assert_eq!(raw.len(), 32);
    }

    #[test]
    fn encoding_aes_key_is_base64_charset() {
        let key = generate_encoding_aes_key();
        assert_eq!(key.len(), 43);
        // Ensure key only contains alphanumeric chars (as required by WeChat: "英文或数字")
        assert!(key.bytes().all(|b| b.is_ascii_alphanumeric()));

        // Verify it decodes correctly as Base64 when padded
        let with_pad = format!("{key}=");
        let raw = base64_decode(&with_pad).expect("decode");
        assert_eq!(raw.len(), 32);
    }
}
