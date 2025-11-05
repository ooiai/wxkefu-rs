#![allow(dead_code)]
//! Callback utilities for WeChat Customer Service (Kf)
//!
//! Features:
//! - Signature verification (SHA1 over sorted parts)
//! - AES-256-CBC decryption using the 43-char EncodingAESKey
//! - Minimal XML/JSON helpers to extract the encrypted payload,
//! - A convenience function to verify-and-decrypt a raw callback body.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use sha1::{Digest, Sha1};
use std::convert::TryInto;
use thiserror::Error;

// AES-256-CBC (key = base64(EncodingAESKey + "="), iv = first 16 bytes of key)
use aes::Aes256;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
type Aes256CbcDec = cbc::Decryptor<Aes256>;

#[derive(Debug, Error)]
pub enum CallbackError {
    #[error("invalid base64: {0}")]
    Base64(String),
    #[error("invalid aes key length")]
    InvalidKey,
    #[error("crypto error")]
    Crypto,
    #[error("utf8 decode error: {0}")]
    Utf8(String),
    #[error("bad message format")]
    BadFormat,
    #[error("signature mismatch")]
    SignatureMismatch,
    #[error("xml extract failed")]
    XmlExtractFailed,
    #[error("json parse error: {0}")]
    Json(String),
}

/// Compute SHA1 signature by sorting parts lexicographically and concatenating.
pub fn sha1_signature(parts: &[&str]) -> String {
    let mut v = parts.to_vec();
    v.sort_unstable();
    let mut hasher = Sha1::new();
    for p in v {
        hasher.update(p.as_bytes());
    }
    let digest = hasher.finalize();
    // lowercase hex
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        use core::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

/// Verify URL signature (no encrypt parameter).
pub fn verify_url_signature(token: &str, timestamp: &str, nonce: &str, signature: &str) -> bool {
    let calc = sha1_signature(&[token, timestamp, nonce]);
    calc.eq_ignore_ascii_case(signature)
}

/// Verify message signature (includes encrypt parameter).
pub fn verify_msg_signature(
    token: &str,
    timestamp: &str,
    nonce: &str,
    encrypt: &str,
    signature: &str,
) -> bool {
    let calc = sha1_signature(&[token, timestamp, nonce, encrypt]);
    calc.eq_ignore_ascii_case(signature)
}

/// Decode EncodingAESKey (43 chars).
/// The AES key is base64(EncodingAESKey + "=") -> 32 bytes; iv is the first 16 bytes.
fn decode_aes_key(encoding_aes_key: &str) -> Result<[u8; 32], CallbackError> {
    let key_b64 = if encoding_aes_key.ends_with('=') {
        encoding_aes_key.to_string()
    } else {
        // The official key is 43 chars and needs one '=' padding
        let mut s = encoding_aes_key.to_string();
        s.push('=');
        s
    };
    let key = BASE64
        .decode(key_b64.as_bytes())
        .map_err(|e| CallbackError::Base64(e.to_string()))?;
    let arr: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| CallbackError::InvalidKey)?;
    Ok(arr)
}

/// Decrypt base64-encoded ciphertext from the callback Encrypt field.
///
/// The plaintext format is:
/// 16B random | 4B big-endian msg_len | msg(msg_len) | receiver_id
pub fn decrypt_b64_message(
    encoding_aes_key: &str,
    cipher_b64: &str,
    expected_receiver_id: Option<&str>,
) -> Result<String, CallbackError> {
    let key = decode_aes_key(encoding_aes_key)?;
    let iv = &key[..16];

    // Normalize base64: handle URL-safe alphabet ('-' -> '+', '_' -> '/') and missing padding.
    let normalized_b64 = {
        let mut t = cipher_b64.trim().replace('-', "+").replace('_', "/");
        match t.len() % 4 {
            2 => t.push_str("=="),
            3 => t.push('='),
            1 => t.push_str("==="),
            _ => {}
        }
        t
    };
    let cipher_bytes = BASE64
        .decode(normalized_b64.as_bytes())
        .map_err(|e| CallbackError::Base64(e.to_string()))?;

    let mut buf = cipher_bytes.clone();
    let plaintext = Aes256CbcDec::new_from_slices(&key, iv)
        .map_err(|_| CallbackError::InvalidKey)?
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| CallbackError::Crypto)?
        .to_vec();

    if plaintext.len() < 20 {
        return Err(CallbackError::BadFormat);
    }

    // Skip 16-byte random
    let content = &plaintext[16..];
    if content.len() < 4 {
        return Err(CallbackError::BadFormat);
    }

    // 4-byte BE length
    let msg_len = u32::from_be_bytes([content[0], content[1], content[2], content[3]]) as usize;
    if content.len() < 4 + msg_len {
        return Err(CallbackError::BadFormat);
    }

    let msg = &content[4..4 + msg_len];
    let receiver_id = &content[4 + msg_len..];

    if let Some(expect) = expected_receiver_id {
        let recv =
            std::str::from_utf8(receiver_id).map_err(|e| CallbackError::Utf8(e.to_string()))?;
        if recv != expect {
            return Err(CallbackError::BadFormat);
        }
    }

    let msg_str =
        String::from_utf8(msg.to_vec()).map_err(|e| CallbackError::Utf8(e.to_string()))?;
    Ok(msg_str)
}

/// Extract Encrypt field from an XML body (supports CDATA or plain text).
pub fn extract_encrypt_from_xml(xml: &str) -> Option<String> {
    // Try CDATA form: <Encrypt><![CDATA[...]]></Encrypt>
    if let (Some(s), Some(e)) = (xml.find("<Encrypt><![CDATA["), xml.find("]]></Encrypt>")) {
        let start = s + "<Encrypt><![CDATA[".len();
        if e > start {
            return Some(xml[start..e].to_string());
        }
    }
    // Fallback: <Encrypt>...</Encrypt>
    if let (Some(s), Some(e)) = (xml.find("<Encrypt>"), xml.find("</Encrypt>")) {
        let start = s + "<Encrypt>".len();
        if e > start {
            return Some(xml[start..e].to_string());
        }
    }
    None
}

/// Extract encrypt/encrypt field from a JSON body.
pub fn extract_encrypt_from_json(s: &str) -> Result<Option<String>, CallbackError> {
    let v: serde_json::Value =
        serde_json::from_str(s).map_err(|e| CallbackError::Json(e.to_string()))?;
    if let Some(e) = v.get("Encrypt").and_then(|x| x.as_str()) {
        return Ok(Some(e.to_string()));
    }
    if let Some(e) = v.get("encrypt").and_then(|x| x.as_str()) {
        return Ok(Some(e.to_string()));
    }
    Ok(None)
}

/// Detect callback wrapper format.
pub enum CallbackFormat {
    Xml,
    Json,
}

pub fn detect_format(body: &[u8]) -> CallbackFormat {
    let s = trim_ascii(body);
    if s.starts_with('{') || s.starts_with('[') {
        CallbackFormat::Json
    } else {
        CallbackFormat::Xml
    }
}

fn trim_ascii(b: &[u8]) -> &str {
    let s = std::str::from_utf8(b).unwrap_or_default();
    s.trim()
}

/// Convenience: verify-and-decrypt a raw callback body.
///
/// - token: the callback Token you configured
/// - encoding_aes_key: 43-char EncodingAESKey
/// - timestamp, nonce, signature: from query params
/// - expected_receiver_id: optional corp_id/app_id to verify against the decrypted tail
pub fn handle_callback_raw(
    token: &str,
    encoding_aes_key: &str,
    timestamp: &str,
    nonce: &str,
    signature: &str,
    body: &str,
    expected_receiver_id: Option<&str>,
) -> Result<String, CallbackError> {
    match detect_format(body.as_bytes()) {
        CallbackFormat::Xml => {
            let encrypt = extract_encrypt_from_xml(body).ok_or(CallbackError::XmlExtractFailed)?;
            if !verify_msg_signature(token, timestamp, nonce, &encrypt, signature) {
                return Err(CallbackError::SignatureMismatch);
            }
            decrypt_b64_message(encoding_aes_key, &encrypt, expected_receiver_id)
        }
        CallbackFormat::Json => {
            let encrypt = extract_encrypt_from_json(body)?.ok_or(CallbackError::BadFormat)?;
            if !verify_msg_signature(token, timestamp, nonce, &encrypt, signature) {
                return Err(CallbackError::SignatureMismatch);
            }
            decrypt_b64_message(encoding_aes_key, &encrypt, expected_receiver_id)
        }
    }
}

/// Convenience: verify-and-decrypt the GET echostr (encrypted echo) used for URL verification.
/// - token: callback Token
/// - encoding_aes_key: 43-char EncodingAESKey
/// - timestamp, nonce, msg_signature: query parameters
/// - echostr: encrypted echo string from the query
/// - expected_receiver_id: optional receiver id (e.g., corpid) to validate against decrypted tail
pub fn verify_and_decrypt_echostr(
    token: &str,
    encoding_aes_key: &str,
    timestamp: &str,
    nonce: &str,
    msg_signature: &str,
    echostr: &str,
    expected_receiver_id: Option<&str>,
) -> Result<String, CallbackError> {
    if !verify_msg_signature(token, timestamp, nonce, echostr, msg_signature) {
        return Err(CallbackError::SignatureMismatch);
    }
    decrypt_b64_message(encoding_aes_key, echostr, expected_receiver_id)
}

/// Convenience: verify-and-decrypt a POST callback body (XML/JSON wrapper).
/// This is a thin wrapper around `handle_callback_raw`.
pub fn verify_and_decrypt_post_body(
    token: &str,
    encoding_aes_key: &str,
    timestamp: &str,
    nonce: &str,
    msg_signature: &str,
    body: &str,
    expected_receiver_id: Option<&str>,
) -> Result<String, CallbackError> {
    handle_callback_raw(
        token,
        encoding_aes_key,
        timestamp,
        nonce,
        msg_signature,
        body,
        expected_receiver_id,
    )
}

/// Optional helper for OA-style unencrypted URL verification:
/// returns `echostr` if signature matches; otherwise `SignatureMismatch`.
pub fn verify_plain_url_echostr(
    token: &str,
    timestamp: &str,
    nonce: &str,
    signature: &str,
    echostr: &str,
) -> Result<String, CallbackError> {
    if verify_url_signature(token, timestamp, nonce, signature) {
        Ok(echostr.to_string())
    } else {
        Err(CallbackError::SignatureMismatch)
    }
}
