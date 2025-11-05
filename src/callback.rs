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
///
/// Accept both sorted and concatenated forms to be tolerant to edge transports.
pub fn verify_url_signature(token: &str, timestamp: &str, nonce: &str, signature: &str) -> bool {
    let calc_sorted = sha1_signature(&[token, timestamp, nonce]);
    let calc_concat = sha1_signature_concat(&[token, timestamp, nonce]);
    calc_sorted.eq_ignore_ascii_case(signature) || calc_concat.eq_ignore_ascii_case(signature)
}

/// Compute SHA1 signature by concatenating parts in the given order (no sorting).
pub fn sha1_signature_concat(parts: &[&str]) -> String {
    let mut hasher = Sha1::new();
    for p in parts {
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

/// Verify message signature (includes encrypt parameter).
///
/// Accept both sorted and concatenated forms; be liberal in what we accept by trying multiple
/// normalization variants of `encrypt` before computing SHA1:
/// - as-is
/// - spaces replaced by '+'
/// - URL percent-decoded
/// - URL percent-decoded, then spaces replaced by '+'
/// For each of the above, also try mapping URL-safe Base64 ('-' -> '+', '_' -> '/') to tolerate
/// proxies that rewrote characters.
pub fn verify_msg_signature(
    token: &str,
    timestamp: &str,
    nonce: &str,
    encrypt: &str,
    signature: &str,
) -> bool {
    // Minimal percent-decoder (does not transform '+').
    fn percent_decode(input: &str) -> Option<String> {
        let b = input.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                let h1 = b[i + 1] as char;
                let h2 = b[i + 2] as char;
                let v1 = h1.to_digit(16)?;
                let v2 = h2.to_digit(16)?;
                out.push((v1 * 16 + v2) as u8);
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8(out).ok()
    }

    fn urlsafe_to_std(s: &str) -> String {
        s.replace('-', "+").replace('_', "/")
    }

    let mut candidates: Vec<String> = Vec::new();

    // Base variants
    let base = encrypt.to_string();
    candidates.push(base.clone());
    candidates.push(base.replace(' ', "+"));

    // Percent-decoded variants
    if let Some(dec) = percent_decode(&base) {
        candidates.push(dec.clone());
        candidates.push(dec.replace(' ', "+"));
    }

    // URL-safe base64 mapped variants
    let mut more = Vec::new();
    for c in &candidates {
        let mapped = urlsafe_to_std(c);
        if mapped != *c {
            more.push(mapped);
        }
    }
    candidates.extend(more);

    // Deduplicate to avoid redundant hashing in pathological cases
    // (small N, so O(N^2) is fine here).
    let mut uniq: Vec<String> = Vec::new();
    'outer: for c in candidates {
        for u in &uniq {
            if u == &c {
                continue 'outer;
            }
        }
        uniq.push(c);
    }

    for c in uniq {
        let calc_sorted = sha1_signature(&[token, timestamp, nonce, &c]);
        if calc_sorted.eq_ignore_ascii_case(signature) {
            return true;
        }
        let calc_concat = sha1_signature_concat(&[token, timestamp, nonce, &c]);
        if calc_concat.eq_ignore_ascii_case(signature) {
            return true;
        }
    }
    false
}

/// Decode EncodingAESKey (43 chars).
/// The AES key is base64(EncodingAESKey + "=") -> 32 bytes; iv is the first 16 bytes.
/// WeChat generates 43-char keys that need lenient Base64 decoding.
fn decode_aes_key(encoding_aes_key: &str) -> Result<[u8; 32], CallbackError> {
    let s0 = encoding_aes_key.trim();

    // Manual lenient Base64 decoder for WeChat's 43-char keys
    fn lenient_base64_decode(s: &str) -> Result<Vec<u8>, String> {
        // Add padding to make length multiple of 4
        let padded = match s.len() % 4 {
            0 => s.to_string(),
            n => format!("{}{}", s, "=".repeat(4 - n)),
        };

        // Manual Base64 decode
        fn b64_val(c: u8) -> Option<u8> {
            match c {
                b'A'..=b'Z' => Some(c - b'A'),
                b'a'..=b'z' => Some(c - b'a' + 26),
                b'0'..=b'9' => Some(c - b'0' + 52),
                b'+' => Some(62),
                b'/' => Some(63),
                b'=' => Some(0),
                _ => None,
            }
        }

        let bytes = padded.as_bytes();
        let mut result = Vec::new();

        for chunk in bytes.chunks(4) {
            if chunk.len() != 4 {
                return Err("invalid length".to_string());
            }

            let v0 = b64_val(chunk[0]).ok_or("invalid char")?;
            let v1 = b64_val(chunk[1]).ok_or("invalid char")?;
            let v2 = if chunk[2] == b'=' {
                0
            } else {
                b64_val(chunk[2]).ok_or("invalid char")?
            };
            let v3 = if chunk[3] == b'=' {
                0
            } else {
                b64_val(chunk[3]).ok_or("invalid char")?
            };

            let combined =
                ((v0 as u32) << 18) | ((v1 as u32) << 12) | ((v2 as u32) << 6) | (v3 as u32);

            result.push(((combined >> 16) & 0xFF) as u8);
            if chunk[2] != b'=' {
                result.push(((combined >> 8) & 0xFF) as u8);
            }
            if chunk[3] != b'=' {
                result.push((combined & 0xFF) as u8);
            }
        }

        Ok(result)
    }

    // Try lenient decode
    match lenient_base64_decode(s0) {
        Ok(bytes) if bytes.len() == 32 => {
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| CallbackError::InvalidKey)?;
            Ok(arr)
        }
        Ok(_) => Err(CallbackError::InvalidKey),
        Err(e) => Err(CallbackError::Base64(e)),
    }
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

    fn percent_decode(input: &str) -> Option<String> {
        let b = input.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                let h1 = b[i + 1] as char;
                let h2 = b[i + 2] as char;
                let v1 = h1.to_digit(16)?;
                let v2 = h2.to_digit(16)?;
                out.push((v1 * 16 + v2) as u8);
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8(out).ok()
    }
    fn urlsafe_to_std(s: &str) -> String {
        s.replace('-', "+").replace('_', "/")
    }
    fn pad_b64(s: String) -> String {
        // Strip all whitespace (newlines, tabs, spaces) that may be present in MIME-style Base64
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        let mut result = cleaned;
        match result.len() % 4 {
            2 => result.push_str("=="),
            3 => result.push('='),
            1 => result.push_str("==="),
            _ => {}
        }
        result
    }

    // Build normalization candidates in a liberal order.
    let base = cipher_b64.to_string();
    let mut candidates: Vec<String> = vec![
        base.clone(),
        base.trim().to_string(),
        base.replace(' ', "+"),
        urlsafe_to_std(&base),
        urlsafe_to_std(&base.trim().to_string()),
        urlsafe_to_std(&base.replace(' ', "+")),
    ];
    if let Some(dec) = percent_decode(&base) {
        candidates.push(dec.clone());
        candidates.push(dec.replace(' ', "+"));
        candidates.push(urlsafe_to_std(&dec));
        candidates.push(urlsafe_to_std(&dec.replace(' ', "+")));
    }

    // Deduplicate candidates
    let mut uniq: Vec<String> = Vec::new();
    'outer: for c in candidates {
        for u in &uniq {
            if u == &c {
                continue 'outer;
            }
        }
        uniq.push(c);
    }

    let mut saw_decode_ok = false;
    let mut saw_decrypt_ok = false;

    for cand in uniq {
        let padded = pad_b64(cand);

        let cipher_bytes = match BASE64.decode(padded.as_bytes()) {
            Ok(b) => {
                saw_decode_ok = true;
                b
            }
            Err(_) => continue,
        };

        let mut buf = cipher_bytes.clone();
        let plaintext = match Aes256CbcDec::new_from_slices(&key, iv)
            .map_err(|_| CallbackError::InvalidKey)?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
        {
            Ok(p) => {
                saw_decrypt_ok = true;
                p.to_vec()
            }
            Err(_) => continue,
        };

        if plaintext.len() < 20 {
            continue;
        }
        let content = &plaintext[16..];
        if content.len() < 4 {
            continue;
        }

        let msg_len = u32::from_be_bytes([content[0], content[1], content[2], content[3]]) as usize;
        if content.len() < 4 + msg_len {
            continue;
        }

        let msg = &content[4..4 + msg_len];
        let receiver_id = &content[4 + msg_len..];

        if let Some(expect) = expected_receiver_id {
            if let Ok(recv) = std::str::from_utf8(receiver_id) {
                if recv != expect {
                    continue;
                }
            } else {
                continue;
            }
        }

        let msg_str = match String::from_utf8(msg.to_vec()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        return Ok(msg_str);
    }

    if saw_decode_ok && saw_decrypt_ok {
        Err(CallbackError::BadFormat)
    } else if saw_decode_ok {
        Err(CallbackError::Crypto)
    } else {
        Err(CallbackError::Base64("no candidate decoded".to_string()))
    }
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

/// Verify and decrypt echostr by trying multiple signature candidates for `echostr`.
/// - First try `echostr_decoded` (already percent-decoded by framework).
/// - Then, if provided, try `echostr_raw_percent_encoded` (the raw string as seen in the original URI).
/// If signature matches using the raw-encoded string, decryption still uses the decoded string.
pub fn verify_and_decrypt_echostr_candidates(
    token: &str,
    encoding_aes_key: &str,
    timestamp: &str,
    nonce: &str,
    msg_signature: &str,
    echostr_decoded: &str,
    echostr_raw_percent_encoded: Option<&str>,
    expected_receiver_id: Option<&str>,
) -> Result<String, CallbackError> {
    if verify_msg_signature(token, timestamp, nonce, echostr_decoded, msg_signature) {
        return decrypt_b64_message(encoding_aes_key, echostr_decoded, expected_receiver_id);
    }
    if let Some(raw) = echostr_raw_percent_encoded {
        if verify_msg_signature(token, timestamp, nonce, raw, msg_signature) {
            return decrypt_b64_message(encoding_aes_key, echostr_decoded, expected_receiver_id);
        }
    }
    Err(CallbackError::SignatureMismatch)
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

/// Extract the short-lived event token (valid for ~10 minutes) from decrypted plaintext.
/// Supports both JSON and XML payloads:
/// - JSON: looks for "token" (lowercase) or "Token"
/// - XML: looks for <Token>...</Token> or CDATA form <Token><![CDATA[...]]></Token>
pub fn extract_event_token(plaintext: &str) -> Option<String> {
    // Try JSON first
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(plaintext) {
        if let Some(t) = v
            .get("token")
            .and_then(|x| x.as_str())
            .or_else(|| v.get("Token").and_then(|x| x.as_str()))
        {
            return Some(t.to_string());
        }
    }
    // Fallback to XML
    extract_token_from_xml(plaintext)
}

/// Extract <Token>...</Token> or its CDATA variant from an XML plaintext.
pub fn extract_token_from_xml(xml: &str) -> Option<String> {
    // CDATA form
    if let (Some(s), Some(e)) = (xml.find("<Token><![CDATA["), xml.find("]]></Token>")) {
        let start = s + "<Token><![CDATA[".len();
        if e > start {
            return Some(xml[start..e].to_string());
        }
    }
    // Plain text form
    if let (Some(s), Some(e)) = (xml.find("<Token>"), xml.find("</Token>")) {
        let start = s + "<Token>".len();
        if e > start {
            return Some(xml[start..e].to_string());
        }
    }
    None
}

/// Verify that the encoding AES key is valid.
pub fn verify_encoding_aes_key(key: &str) -> bool {
    // WeChat Kf requires a 43-character string that decodes to 32 bytes
    if key.trim().len() != 43 {
        return false;
    }
    // Try lenient decode
    fn lenient_base64_decode(s: &str) -> Option<Vec<u8>> {
        let padded = match s.len() % 4 {
            0 => s.to_string(),
            n => format!("{}{}", s, "=".repeat(4 - n)),
        };
        fn b64_val(c: u8) -> Option<u8> {
            match c {
                b'A'..=b'Z' => Some(c - b'A'),
                b'a'..=b'z' => Some(c - b'a' + 26),
                b'0'..=b'9' => Some(c - b'0' + 52),
                b'+' => Some(62),
                b'/' => Some(63),
                b'=' => Some(0),
                _ => None,
            }
        }
        let bytes = padded.as_bytes();
        let mut result = Vec::new();
        for chunk in bytes.chunks(4) {
            if chunk.len() != 4 {
                return None;
            }
            let v0 = b64_val(chunk[0])?;
            let v1 = b64_val(chunk[1])?;
            let v2 = if chunk[2] == b'=' {
                0
            } else {
                b64_val(chunk[2])?
            };
            let v3 = if chunk[3] == b'=' {
                0
            } else {
                b64_val(chunk[3])?
            };
            let combined =
                ((v0 as u32) << 18) | ((v1 as u32) << 12) | ((v2 as u32) << 6) | (v3 as u32);
            result.push(((combined >> 16) & 0xFF) as u8);
            if chunk[2] != b'=' {
                result.push(((combined >> 8) & 0xFF) as u8);
            }
            if chunk[3] != b'=' {
                result.push((combined & 0xFF) as u8);
            }
        }
        Some(result)
    }

    match lenient_base64_decode(key.trim()) {
        Some(bytes) => bytes.len() == 32,
        None => false,
    }
}

/// Derive raw AES key and IV (first 16 bytes of key) from EncodingAESKey.
pub fn derive_key_iv(encoding_aes_key: &str) -> Result<([u8; 32], [u8; 16]), CallbackError> {
    let key = decode_aes_key(encoding_aes_key)?;
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&key[..16]);
    Ok((key, iv))
}

/// Typed message models for Kf plaintext (JSON or XML).
#[derive(Debug, Clone)]
pub enum KfMessage {
    Text(TextMsg),
    Image(MediaMsg),
    Voice(MediaMsg),
    Video(MediaMsg),
    File(MediaMsg),
    Location(LocationMsg),
    Miniprogram(MiniprogramMsg),
    ChannelsShopProduct(ChannelsShopProductMsg),
    ChannelsShopOrder(ChannelsShopOrderMsg),
    MergedMsg(MergedMsg),
    Channels(ChannelsMsg),
    Note,
    Event(KfEvent),
    UnknownJson {
        msgtype: String,
        raw: serde_json::Value,
    },
    UnknownXml {
        name: String,
        raw: String,
    },
}

#[derive(Debug, Clone)]
pub struct TextMsg {
    pub content: String,
    pub menu_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MediaMsg {
    pub media_id: String,
}

#[derive(Debug, Clone)]
pub struct LocationMsg {
    pub latitude: f64,
    pub longitude: f64,
    pub name: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MiniprogramMsg {
    pub title: Option<String>,
    pub appid: Option<String>,
    pub pagepath: Option<String>,
    pub thumb_media_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChannelsShopProductMsg {
    pub product_id: Option<String>,
    pub head_image: Option<String>,
    pub title: Option<String>,
    pub sales_price: Option<String>,
    pub shop_nickname: Option<String>,
    pub shop_head_image: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChannelsShopOrderMsg {
    pub order_id: Option<String>,
    pub product_titles: Option<String>,
    pub price_wording: Option<String>,
    pub state: Option<String>,
    pub image_url: Option<String>,
    pub shop_nickname: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MergedItem {
    pub send_time: Option<u64>,
    pub msgtype: Option<String>,
    pub sender_name: Option<String>,
    pub msg_content: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MergedMsg {
    pub title: Option<String>,
    pub item: Vec<MergedItem>,
}

#[derive(Debug, Clone)]
pub struct ChannelsMsg {
    pub sub_type: Option<u32>,
    pub nickname: Option<String>,
    pub title: Option<String>,
}

#[derive(Debug, Clone)]
pub enum KfEvent {
    EnterSession {
        open_kfid: Option<String>,
        external_userid: Option<String>,
        scene: Option<String>,
        scene_param: Option<String>,
        welcome_code: Option<String>,
        wechat_channels_nickname: Option<String>,
        wechat_channels_scene: Option<u32>,
    },
    MsgSendFail {
        open_kfid: Option<String>,
        external_userid: Option<String>,
        fail_msgid: Option<String>,
        fail_type: Option<u32>,
    },
    UserRecallMsg {
        open_kfid: Option<String>,
        external_userid: Option<String>,
        recall_msgid: Option<String>,
    },
    KfMsgOrEventNotification {
        to_user_name: Option<String>,
        create_time: Option<u64>,
        token: Option<String>,
        open_kfid: Option<String>,
    },
    Unknown {
        event_type: Option<String>,
        raw: serde_json::Value,
    },
}

/// Parse Kf plaintext (JSON preferred, XML fallback) into typed models.
pub fn parse_kf_plaintext(plaintext: &str) -> Result<KfMessage, CallbackError> {
    let s = plaintext.trim();
    if s.starts_with('{') || s.starts_with('[') {
        parse_kf_json(plaintext)
    } else {
        parse_kf_xml(plaintext)
    }
}

fn parse_kf_json(plaintext: &str) -> Result<KfMessage, CallbackError> {
    let v: serde_json::Value =
        serde_json::from_str(plaintext).map_err(|e| CallbackError::Json(e.to_string()))?;
    let msgtype = v
        .get("msgtype")
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string();

    match msgtype.as_str() {
        "text" => {
            let text = v.get("text").cloned().unwrap_or_default();
            let content = text
                .get("content")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            let menu_id = text
                .get("menu_id")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            Ok(KfMessage::Text(TextMsg { content, menu_id }))
        }
        "image" => {
            let image = v.get("image").cloned().unwrap_or_default();
            let media_id = image
                .get("media_id")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            Ok(KfMessage::Image(MediaMsg { media_id }))
        }
        "voice" => {
            let voice = v.get("voice").cloned().unwrap_or_default();
            let media_id = voice
                .get("media_id")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            Ok(KfMessage::Voice(MediaMsg { media_id }))
        }
        "video" => {
            let video = v.get("video").cloned().unwrap_or_default();
            let media_id = video
                .get("media_id")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            Ok(KfMessage::Video(MediaMsg { media_id }))
        }
        "file" => {
            let file = v.get("file").cloned().unwrap_or_default();
            let media_id = file
                .get("media_id")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            Ok(KfMessage::File(MediaMsg { media_id }))
        }
        "location" => {
            let loc = v.get("location").cloned().unwrap_or_default();
            let latitude = loc
                .get("latitude")
                .and_then(|x| x.as_f64())
                .unwrap_or_default();
            let longitude = loc
                .get("longitude")
                .and_then(|x| x.as_f64())
                .unwrap_or_default();
            let name = loc
                .get("name")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let address = loc
                .get("address")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            Ok(KfMessage::Location(LocationMsg {
                latitude,
                longitude,
                name,
                address,
            }))
        }
        "miniprogram" => {
            let mp = v.get("miniprogram").cloned().unwrap_or_default();
            let title = mp
                .get("title")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let appid = mp
                .get("appid")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let pagepath = mp
                .get("pagepath")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let thumb_media_id = mp
                .get("thumb_media_id")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            Ok(KfMessage::Miniprogram(MiniprogramMsg {
                title,
                appid,
                pagepath,
                thumb_media_id,
            }))
        }
        "channels_shop_product" => {
            let p = v.get("channels_shop_product").cloned().unwrap_or_default();
            Ok(KfMessage::ChannelsShopProduct(ChannelsShopProductMsg {
                product_id: p
                    .get("product_id")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                head_image: p
                    .get("head_image")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                title: p
                    .get("title")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                sales_price: p
                    .get("sales_price")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                shop_nickname: p
                    .get("shop_nickname")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                shop_head_image: p
                    .get("shop_head_image")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
            }))
        }
        "channels_shop_order" => {
            let o = v.get("channels_shop_order").cloned().unwrap_or_default();
            Ok(KfMessage::ChannelsShopOrder(ChannelsShopOrderMsg {
                order_id: o
                    .get("order_id")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                product_titles: o
                    .get("product_titles")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                price_wording: o
                    .get("price_wording")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                state: o
                    .get("state")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                image_url: o
                    .get("image_url")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                shop_nickname: o
                    .get("shop_nickname")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
            }))
        }
        "merged_msg" => {
            let m = v.get("merged_msg").cloned().unwrap_or_default();
            let title = m
                .get("title")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let mut items = Vec::new();
            if let Some(arr) = m.get("item").and_then(|x| x.as_array()) {
                for it in arr {
                    items.push(MergedItem {
                        send_time: it.get("send_time").and_then(|x| x.as_u64()),
                        msgtype: it
                            .get("msgtype")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string()),
                        sender_name: it
                            .get("sender_name")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string()),
                        msg_content: it
                            .get("msg_content")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string()),
                    });
                }
            }
            Ok(KfMessage::MergedMsg(MergedMsg { title, item: items }))
        }
        "channels" => {
            let c = v.get("channels").cloned().unwrap_or_default();
            Ok(KfMessage::Channels(ChannelsMsg {
                sub_type: c.get("sub_type").and_then(|x| x.as_u64()).map(|n| n as u32),
                nickname: c
                    .get("nickname")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
                title: c
                    .get("title")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
            }))
        }
        "note" => Ok(KfMessage::Note),
        "event" => {
            let ev = v.get("event").cloned().unwrap_or_default();
            let et = ev
                .get("event_type")
                .and_then(|x| x.as_str())
                .unwrap_or_default();
            let event = match et {
                "enter_session" => KfEvent::EnterSession {
                    open_kfid: ev
                        .get("open_kfid")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                    external_userid: ev
                        .get("external_userid")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                    scene: ev
                        .get("scene")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                    scene_param: ev
                        .get("scene_param")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                    welcome_code: ev
                        .get("welcome_code")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                    wechat_channels_nickname: ev
                        .get("wechat_channels")
                        .and_then(|wc| wc.get("nickname"))
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                    wechat_channels_scene: ev
                        .get("wechat_channels")
                        .and_then(|wc| wc.get("scene"))
                        .and_then(|x| x.as_u64())
                        .map(|n| n as u32),
                },
                "msg_send_fail" => KfEvent::MsgSendFail {
                    open_kfid: ev
                        .get("open_kfid")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                    external_userid: ev
                        .get("external_userid")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                    fail_msgid: ev
                        .get("fail_msgid")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                    fail_type: ev
                        .get("fail_type")
                        .and_then(|x| x.as_u64())
                        .map(|n| n as u32),
                },
                "user_recall_msg" => KfEvent::UserRecallMsg {
                    open_kfid: ev
                        .get("open_kfid")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                    external_userid: ev
                        .get("external_userid")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                    recall_msgid: ev
                        .get("recall_msgid")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                },
                _ => KfEvent::Unknown {
                    event_type: Some(et.to_string()),
                    raw: ev,
                },
            };
            Ok(KfMessage::Event(event))
        }
        _ => Ok(KfMessage::UnknownJson { msgtype, raw: v }),
    }
}

fn parse_kf_xml(plaintext: &str) -> Result<KfMessage, CallbackError> {
    // Minimal XML event parsing for <MsgType>event</MsgType> with <Event>kf_msg_or_event</Event>
    let msg_type = get_xml_text(plaintext, "MsgType")
        .or_else(|| get_xml_cdata(plaintext, "MsgType"))
        .unwrap_or_default();
    if msg_type.eq_ignore_ascii_case("event") {
        let ev = get_xml_text(plaintext, "Event")
            .or_else(|| get_xml_cdata(plaintext, "Event"))
            .unwrap_or_default();
        if ev == "kf_msg_or_event" {
            let to_user_name = get_xml_text(plaintext, "ToUserName")
                .or_else(|| get_xml_cdata(plaintext, "ToUserName"));
            let create_time =
                get_xml_text(plaintext, "CreateTime").and_then(|s| s.parse::<u64>().ok());
            let token = extract_token_from_xml(plaintext);
            let open_kfid = get_xml_text(plaintext, "OpenKfId")
                .or_else(|| get_xml_cdata(plaintext, "OpenKfId"));
            return Ok(KfMessage::Event(KfEvent::KfMsgOrEventNotification {
                to_user_name,
                create_time,
                token,
                open_kfid,
            }));
        }
        return Ok(KfMessage::UnknownXml {
            name: ev,
            raw: plaintext.to_string(),
        });
    }
    Ok(KfMessage::UnknownXml {
        name: msg_type,
        raw: plaintext.to_string(),
    })
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
