//! Callback helpers for WeChat Customer Service (WeCom Kf)
//!
//! This module implements the canonical algorithms described in the official Kf docs:
//! - Deterministic SHA1 signature verification (sort the parts, then SHA1 over the concatenation)
//! - AES-256-CBC decryption using the 43-char `EncodingAESKey`
//! - Minimal helpers to extract Encrypt/Token from XML/JSON
//! - Straightforward handling for plaintext callbacks (no Encrypt field)
//!
//! References
//! - API overview and access_token acquisition: https://kf.weixin.qq.com/api/doc/path/93304
//! - Callback interaction and event notification: https://kf.weixin.qq.com/api/doc/path/94745
//!
//! Key points
//! - URL verification (GET):
//!   - Kf uses `msg_signature` with an encrypted `echostr`. Verify signature and decrypt to reply.
//!   - OA/unencrypted mode uses `signature` with a plaintext `echostr`. Verify and return as-is.
//! - Message delivery (POST):
//!   - Body wrapper is typically XML (may also be JSON) with an `Encrypt`/`encrypt` field.
//!   - Verify signature against the Encrypt field and decrypt the ciphertext.
//! - AES key derivation:
//!   - `EncodingAESKey` is a 43-character Base64 string. Decode `EncodingAESKey + "="` to 32 bytes.
//!   - AES key = 32 bytes result; IV = first 16 bytes of the key.
//! - Decrypted plaintext layout:
//!   - 16 bytes random | 4 bytes big-endian msg_length | msg(msg_length) | receiver_id
//!   - Optionally verify `receiver_id` (e.g., your corpid `ww...`) against your expectation.

#![allow(dead_code)]

use aes::Aes256;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use serde_json::Value as JsonValue;
use sha1::{Digest, Sha1};
use std::convert::TryInto;
use thiserror::Error;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

#[derive(Debug, Error)]
pub enum CallbackError {
    #[error("invalid base64: {0}")]
    Base64(String),
    #[error("invalid EncodingAESKey (must be 43-chars, decoding to 32 bytes)")]
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
// Deterministic behavior per official docs: sort, concat, sha1(lowercase hex).
pub fn sha1_signature(parts: &[&str]) -> String {
    let mut v = parts.to_vec();
    v.sort_unstable();
    let mut hasher = Sha1::new();
    for p in v {
        hasher.update(p.as_bytes());
    }
    let digest = hasher.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        use core::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

/// Verify URL signature (OA/plaintext-style): sha1(sorted(token, timestamp, nonce)) == signature.
pub fn verify_url_signature(token: &str, timestamp: &str, nonce: &str, signature: &str) -> bool {
    let calc = sha1_signature(&[token, timestamp, nonce]);
    // Spec uses lowercase hex; ignore case in case upstream varies in casing.
    calc.eq_ignore_ascii_case(signature)
}

/// Verify message signature (Kf/encrypted):
/// sha1(sorted(token, timestamp, nonce, encrypt)) == msg_signature.
pub fn verify_msg_signature(
    token: &str,
    timestamp: &str,
    nonce: &str,
    encrypt: &str,
    msg_signature: &str,
) -> bool {
    let calc = sha1_signature(&[token, timestamp, nonce, encrypt]);
    calc.eq_ignore_ascii_case(msg_signature)
}

/// Decode the 43-char `EncodingAESKey` into a 32-byte AES key.
/// - Returns (key32, iv16) where iv16 = first 16 bytes of key32.
pub fn derive_key_iv(encoding_aes_key: &str) -> Result<([u8; 32], [u8; 16]), CallbackError> {
    let s = encoding_aes_key.trim();
    if s.len() != 43 {
        return Err(CallbackError::InvalidKey);
    }
    // Per docs: Base64 decode of EncodingAESKey + "=" yields 32 bytes.
    // Be tolerant to admin-issued keys: try with "=" first, then fallback to "==".
    let decoded = BASE64
        .decode(format!("{s}=").as_bytes())
        .or_else(|_| BASE64.decode(format!("{s}==").as_bytes()))
        .map_err(|e| CallbackError::Base64(e.to_string()))?;
    if decoded.len() != 32 {
        return Err(CallbackError::InvalidKey);
    }
    let key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| CallbackError::InvalidKey)?;
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&key[..16]);
    Ok((key, iv))
}

/// Minimal Base64 padding helper in case upstream omits padding.
/// Note: The official Encrypt field is standard Base64; this is defensive only.
fn pad_b64(mut s: String) -> String {
    s.retain(|c| !c.is_whitespace()); // normalize potential whitespace
    match s.len() % 4 {
        2 => s.push_str("=="),
        3 => s.push('='),
        1 => s.push_str("==="),
        _ => {}
    }
    s
}

/// Decrypt ciphertext from the callback Encrypt field.
/// Plaintext format: 16B random | 4B BE msg_len | msg(msg_len) | receiver_id
pub fn decrypt_b64_message(
    encoding_aes_key: &str,
    cipher_b64: &str,
    expected_receiver_id: Option<&str>,
) -> Result<String, CallbackError> {
    let (key, iv) = derive_key_iv(encoding_aes_key)?;
    let b64 = pad_b64(cipher_b64.trim().to_string());
    let mut cipher = BASE64
        .decode(b64.as_bytes())
        .map_err(|e| CallbackError::Base64(e.to_string()))?;

    let plaintext = Aes256CbcDec::new_from_slices(&key, &iv)
        .map_err(|_| CallbackError::InvalidKey)?
        .decrypt_padded_mut::<Pkcs7>(&mut cipher)
        .map_err(|_| CallbackError::Crypto)?;

    if plaintext.len() < 20 {
        return Err(CallbackError::BadFormat);
    }

    // Skip 16 random bytes
    let content = &plaintext[16..];
    if content.len() < 4 {
        return Err(CallbackError::BadFormat);
    }
    let msg_len = u32::from_be_bytes([content[0], content[1], content[2], content[3]]) as usize;
    if msg_len > 1_000_000 || content.len() < 4 + msg_len {
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

    String::from_utf8(msg.to_vec()).map_err(|e| CallbackError::Utf8(e.to_string()))
}

/// Extract Encrypt field from XML: supports CDATA or plain text.
pub fn extract_encrypt_from_xml(xml: &str) -> Option<String> {
    // CDATA form: <Encrypt><![CDATA[...]]></Encrypt>
    if let (Some(s), Some(e)) = (xml.find("<Encrypt><![CDATA["), xml.find("]]></Encrypt>")) {
        let start = s + "<Encrypt><![CDATA[".len();
        if e > start {
            return Some(xml[start..e].to_string());
        }
    }
    // Plain text form: <Encrypt>...</Encrypt>
    if let (Some(s), Some(e)) = (xml.find("<Encrypt>"), xml.find("</Encrypt>")) {
        let start = s + "<Encrypt>".len();
        if e > start {
            return Some(xml[start..e].to_string());
        }
    }
    None
}

/// Extract Encrypt/encrypt field from JSON.
pub fn extract_encrypt_from_json(s: &str) -> Result<Option<String>, CallbackError> {
    let v: JsonValue = serde_json::from_str(s).map_err(|e| CallbackError::Json(e.to_string()))?;
    if let Some(e) = v.get("Encrypt").and_then(|x| x.as_str()) {
        return Ok(Some(e.to_string()));
    }
    if let Some(e) = v.get("encrypt").and_then(|x| x.as_str()) {
        return Ok(Some(e.to_string()));
    }
    Ok(None)
}

/// Extract Token from decrypted plaintext.
/// - JSON: "token" or "Token"
/// - XML: <Token>...</Token> or CDATA variant
pub fn extract_event_token(plaintext: &str) -> Option<String> {
    // JSON first
    if let Ok(v) = serde_json::from_str::<JsonValue>(plaintext) {
        if let Some(t) = v
            .get("token")
            .and_then(|x| x.as_str())
            .or_else(|| v.get("Token").and_then(|x| x.as_str()))
        {
            return Some(t.to_string());
        }
    }
    // XML fallback
    extract_token_from_xml(plaintext)
}

/// Extract <Token>...</Token> or CDATA variant from XML.
pub fn extract_token_from_xml(xml: &str) -> Option<String> {
    // CDATA
    if let (Some(s), Some(e)) = (xml.find("<Token><![CDATA["), xml.find("]]></Token>")) {
        let start = s + "<Token><![CDATA[".len();
        if e > start {
            return Some(xml[start..e].to_string());
        }
    }
    // Plain
    if let (Some(s), Some(e)) = (xml.find("<Token>"), xml.find("</Token>")) {
        let start = s + "<Token>".len();
        if e > start {
            return Some(xml[start..e].to_string());
        }
    }
    None
}

pub enum CallbackFormat {
    Xml,
    Json,
}

fn trim_ascii(s: &str) -> &str {
    s.trim()
}

pub fn detect_format(body: &[u8]) -> CallbackFormat {
    let s = std::str::from_utf8(body).unwrap_or_default();
    let t = trim_ascii(s);
    if t.starts_with('{') || t.starts_with('[') {
        CallbackFormat::Json
    } else {
        CallbackFormat::Xml
    }
}

/// Verify-and-decrypt the GET echostr for URL verification (Kf/encrypted).
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

/// Strict variant: only uses decoded `echostr` for signature verification.
/// The `echostr_raw_percent_encoded` is ignored intentionally to adhere to deterministic behavior.
pub fn verify_and_decrypt_echostr_candidates(
    token: &str,
    encoding_aes_key: &str,
    timestamp: &str,
    nonce: &str,
    msg_signature: &str,
    echostr_decoded: &str,
    _echostr_raw_percent_encoded: Option<&str>,
    expected_receiver_id: Option<&str>,
) -> Result<String, CallbackError> {
    verify_and_decrypt_echostr(
        token,
        encoding_aes_key,
        timestamp,
        nonce,
        msg_signature,
        echostr_decoded,
        expected_receiver_id,
    )
}

/// Verify-and-decrypt a POST callback body (XML/JSON wrapper).
/// - If body has Encrypt/encrypt: verify signature and decrypt, returning the plaintext.
/// - Otherwise: return body as-is (plaintext callback).
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

/// Convenience: verify-and-decrypt a raw callback body (XML or JSON).
/// - Encrypted: verify msg_signature with Encrypt, then decrypt
/// - Plaintext: return body as-is
pub fn handle_callback_raw(
    token: &str,
    encoding_aes_key: &str,
    timestamp: &str,
    nonce: &str,
    msg_signature: &str,
    body: &str,
    expected_receiver_id: Option<&str>,
) -> Result<String, CallbackError> {
    match detect_format(body.as_bytes()) {
        CallbackFormat::Xml => {
            if let Some(encrypt) = extract_encrypt_from_xml(body) {
                if !verify_msg_signature(token, timestamp, nonce, &encrypt, msg_signature) {
                    return Err(CallbackError::SignatureMismatch);
                }
                decrypt_b64_message(encoding_aes_key, &encrypt, expected_receiver_id)
            } else {
                Ok(body.to_string())
            }
        }
        CallbackFormat::Json => match extract_encrypt_from_json(body)? {
            Some(encrypt) => {
                if !verify_msg_signature(token, timestamp, nonce, &encrypt, msg_signature) {
                    return Err(CallbackError::SignatureMismatch);
                }
                decrypt_b64_message(encoding_aes_key, &encrypt, expected_receiver_id)
            }
            None => Ok(body.to_string()),
        },
    }
}

/// Optional helper for unencrypted URL verification (OA-style).
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

/// Validate that `EncodingAESKey` looks correct: 43 alphanumeric characters (per official docs).
/// Note: Strict Base64 validation is deferred to decryption time to accommodate admin-issued keys.
pub fn verify_encoding_aes_key(key: &str) -> bool {
    let s = key.trim();
    s.len() == 43 && s.chars().all(|c| c.is_ascii_alphanumeric())
}

/* ---------------------------
Optional: very simple plaintext helpers
--------------------------- */

/// A minimal message enum for simple plaintext handling.
/// For strict alignment with docs, we do not attempt exhaustive modeling here.
#[derive(Debug, Clone)]
pub enum KfMessage {
    /// The decrypted or plaintext body as-is.
    Plain(String),
    /// Minimal event notification for XML sample in docs (kf_msg_or_event).
    Event(KfEvent),
    /// Fallback for anything else we don't model.
    Unknown(String),
}

#[derive(Debug, Clone)]
pub enum KfEvent {
    /// Event envelope described in the doc sample:
    /// <MsgType>event</MsgType><Event>kf_msg_or_event</Event>
    KfMsgOrEventNotification {
        to_user_name: Option<String>,
        create_time: Option<u64>,
        token: Option<String>,
        open_kfid: Option<String>,
    },
    /// Unknown event (raw content available)
    Unknown(String),
}

/// Parse plaintext into a minimal `KfMessage`.
/// - If JSON or XML can be recognized as the simple event in docs, produce `Event`.
/// - Otherwise return `Plain` or `Unknown`.
pub fn parse_kf_plaintext(plaintext: &str) -> Result<KfMessage, CallbackError> {
    let s = plaintext.trim();

    // Try JSON first (we only extract "token" for convenience, not full schema).
    if s.starts_with('{') {
        // Keep as plain for strict simplicity (app logic can parse as needed).
        return Ok(KfMessage::Plain(s.to_string()));
    }

    // Try XML minimal event detection (kf_msg_or_event)
    let msg_type = get_xml_text(s, "MsgType")
        .or_else(|| get_xml_cdata(s, "MsgType"))
        .unwrap_or_default();
    if msg_type.eq_ignore_ascii_case("event") {
        let event_name = get_xml_text(s, "Event")
            .or_else(|| get_xml_cdata(s, "Event"))
            .unwrap_or_default();
        if event_name == "kf_msg_or_event" {
            let to_user_name =
                get_xml_text(s, "ToUserName").or_else(|| get_xml_cdata(s, "ToUserName"));
            let create_time = get_xml_text(s, "CreateTime").and_then(|x| x.parse::<u64>().ok());
            let token = extract_token_from_xml(s);
            let open_kfid = get_xml_text(s, "OpenKfId").or_else(|| get_xml_cdata(s, "OpenKfId"));
            return Ok(KfMessage::Event(KfEvent::KfMsgOrEventNotification {
                to_user_name,
                create_time,
                token,
                open_kfid,
            }));
        }
        return Ok(KfMessage::Event(KfEvent::Unknown(s.to_string())));
    }

    // Default to plain for anything else
    Ok(KfMessage::Plain(s.to_string()))
}

fn get_xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    if let (Some(s), Some(e)) = (xml.find(&open), xml.find(&close)) {
        let start = s + open.len();
        if e > start {
            return Some(xml[start..e].to_string());
        }
    }
    None
}

fn get_xml_cdata(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}><![CDATA[");
    let close = format!("]]></{tag}>");
    if let (Some(s), Some(e)) = (xml.find(&open), xml.find(&close)) {
        let start = s + open.len();
        if e > start {
            return Some(xml[start..e].to_string());
        }
    }
    None
}
