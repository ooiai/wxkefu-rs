#![allow(dead_code)]
//! WeChat Kf callback crypto/signature helpers.
//!
//! What this module provides
//! - Signature verification for callback requests (msg_signature)
//! - AES-256-CBC decryption for encrypted callback payloads (XML with <Encrypt>)
//! - Optional URL verification (echostr) decryption
//!
//! Background
//! - WeChat Kf signs requests with SHA1 over the lexicographically sorted list of:
//!   [token, timestamp, nonce, encrypt(or echostr)]
//! - The payload is encrypted using AES-256-CBC with PKCS7 padding. The key comes from
//!   the 43-character EncodingAESKey you configure in the Kf Admin console.
//!   IMPORTANT: EncodingAESKey is BASE64 of the 256-bit AES key (not hex).
//! - The IV is the first 16 bytes of the AES key.
//!
//! Typical callback steps
//! 1) Verify the signature from the query string (msg_signature, timestamp, nonce)
//! 2) Decrypt the body (XML) to get the plaintext XML
//! 3) Parse the plaintext XML; for kf_msg_or_event, use the embedded <Token> to pull messages via sync_msg
//!
//! Example (Axum server)
//! This is a minimal server showing GET URL verification and POST message decryption.
//! Note: Replace TOKEN / ENCODING_AES_KEY / CORP_ID with your own.
//!
//! ```ignore
//! use axum::{extract::Query, routing::{get, post}, Router, response::IntoResponse};
//! use std::net::SocketAddr;
//! use std::sync::Arc;
//! use wxkefu_rs::callback::{CallbackCrypto, VerifyError};
//!
//! #[derive(Debug, serde::Deserialize)]
//! struct WxQuery {
//!     msg_signature: String,
//!     timestamp: String,
//!     nonce: String,
//!     echostr: Option<String>,
//! }
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     tracing_subscriber::fmt().init();
//!
//!     // Load from env or config center
//!     let token = std::env::var("WXKF_TOKEN").expect("missing WXKF_TOKEN");
//!     let encoding_aes_key = std::env::var("WXKF_ENCODING_AES_KEY").expect("missing WXKF_ENCODING_AES_KEY");
//!     let corpid = std::env::var("WXKF_CORP_ID").expect("missing WXKF_CORP_ID");
//!
//!     // Build crypto helper
//!     let crypto = Arc::new(CallbackCrypto::new(token, encoding_aes_key, corpid)?);
//!
//!     // GET: URL verification (echostr)
//!     let crypto_get = crypto.clone();
//!     let verify = get(move |Query(q): Query<WxQuery>| {
//!         let crypto = crypto_get.clone();
//!         async move {
//!             match q.echostr {
//!                 Some(echostr) => match crypto.verify_and_decrypt_echostr(&q.msg_signature, &q.timestamp, &q.nonce, &echostr) {
//!                     Ok(plain) => plain.into_response(),
//!                     Err(err) => {
//!                         tracing::warn!("verify echostr failed: {}", err);
//!                         (axum::http::StatusCode::BAD_REQUEST, "invalid").into_response()
//!                     }
//!                 },
//!                 None => (axum::http::StatusCode::BAD_REQUEST, "missing echostr").into_response(),
//!             }
//!         }
//!     });
//!
//!     // POST: encrypted callback body
//!     let crypto_post = crypto.clone();
//!     let callback = post(move |Query(q): Query<WxQuery>, body: String| {
//!         let crypto = crypto_post.clone();
//!         async move {
//!             match crypto.verify_and_decrypt_xml(&q.msg_signature, &q.timestamp, &q.nonce, &body) {
//!                 Ok(plaintext_xml) => {
//!                     // You will typically parse plaintext_xml (quick-xml or roxmltree) to get fields such as:
//!                     // - <Event>kf_msg_or_event</Event>
//!                     // - <Token>...</Token> (use this when calling sync_msg within 10 minutes)
//!                     tracing::info!("Decrypted plaintext XML: {}", plaintext_xml);
//!                     // Must reply "success" to acknowledge receipt
//!                     "success"
//!                 }
//!                 Err(err) => {
//!                     tracing::warn!("decrypt callback failed: {}", err);
//!                     (axum::http::StatusCode::BAD_REQUEST, "invalid")
//!                 }
//!             }
//!         }
//!     });
//!
//!     let app = Router::new()
//!         .route("/wx/kf/callback", verify)
//!         .route("/wx/kf/callback", callback);
//!
//!     let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
//!     tracing::info!("listening on {}", addr);
//!     axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
//!     Ok(())
//! }
//! ```
//!
//! Notes
//! - The Token is only used for signature verification; never expose it.
//! - EncodingAESKey is only used for crypto; treat it as a secret (never log it).
//! - If you enforce appid/corpid match in plaintext, be aware some integrations ignore it;
//!   this module by default does NOT enforce it (compatible with many existing systems).

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as BASE64, STANDARD_NO_PAD as BASE64_NO_PAD};
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use sha1::{Digest, Sha1};
use std::fmt;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

/// Errors from callback verification and crypto.
#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    #[error("invalid base64 key length: expect 43 characters (unpadded base64)")]
    BadEncodingAesKeyLength,
    #[error("invalid encoding_aes_key base64: {0}")]
    BadEncodingAesKey(String),
    #[error("aes key must decode to 32 bytes (AES-256)")]
    BadAesKeySize,
    #[error("signature mismatch")]
    SignatureMismatch,
    #[error("invalid xml: missing <Encrypt>")]
    MissingEncryptTag,
    #[error("invalid ciphertext: base64 decode failed: {0}")]
    BadCiphertextBase64(String),
    #[error("aes decrypt failed")]
    AesDecryptFailed,
    #[error("invalid padding")]
    InvalidPadding,
    #[error("invalid plaintext frame")]
    InvalidPlaintextFrame,
    #[error("xml parse error: {0}")]
    XmlParse(String),
}

impl VerifyError {
    fn xml<E: fmt::Display>(e: E) -> Self {
        VerifyError::XmlParse(e.to_string())
    }
}

/// Helper for WeChat Kf callback signature and AES crypto.
///
/// - token: used for signature calculation
/// - encoding_aes_key: 43-character base64 for the 32-byte AES key
/// - appid_or_corpid: your appid (OA/MP) or corpid (WeCom/Kf). Not enforced by default.
#[derive(Clone, Debug)]
pub struct CallbackCrypto {
    token: String,
    aes_key: [u8; 32],
    appid_or_corpid: String,
}

impl CallbackCrypto {
    /// Create a new crypto helper.
    ///
    /// encoding_aes_key must be 43 chars base64 (unpadded). Spaces are ignored. Missing '=' padding will be added automatically.
    pub fn new<T: Into<String>, U: Into<String>, V: Into<String>>(
        token: T,
        encoding_aes_key: U,
        appid_or_corpid: V,
    ) -> Result<Self, VerifyError> {
        let token = token.into();
        // Remove any kind of ASCII whitespace (space, tab, CR, LF, etc.)
        let raw = encoding_aes_key.into();
        let mut key_b64: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        // Base64 requires length % 4 == 0; the official key often omits trailing '='
        while key_b64.len() % 4 != 0 {
            key_b64.push('=');
        }
        // Try decoding with padding first; if it fails, try without padding as a fallback.
        let key = match BASE64.decode(key_b64.as_bytes()) {
            Ok(k) => k,
            Err(_e) => match BASE64_NO_PAD.decode(key_b64.as_bytes()) {
                Ok(k) => k,
                Err(e2) => {
                    let tail: String = key_b64
                        .chars()
                        .rev()
                        .take(6)
                        .collect::<Vec<char>>()
                        .into_iter()
                        .rev()
                        .collect();
                    return Err(VerifyError::BadEncodingAesKey(format!(
                        "{}; cleaned_len={}; tail='{}' (tip: ensure no hidden whitespace/newlines; 43~44 chars are typical and padding is added automatically)",
                        e2,
                        key_b64.len(),
                        tail
                    )));
                }
            },
        };
        if key.len() != 32 {
            return Err(VerifyError::BadAesKeySize);
        }
        let mut aes_key = [0u8; 32];
        aes_key.copy_from_slice(&key);
        let appid_or_corpid = appid_or_corpid.into();
        Ok(Self {
            token,
            aes_key,
            appid_or_corpid,
        })
    }

    /// Compute signature: sha1(sort(token, timestamp, nonce, data).join("")) lower-hex.
    pub fn signature(&self, timestamp: &str, nonce: &str, data: &str) -> String {
        let mut v = [self.token.as_str(), timestamp, nonce, data];
        v.sort_unstable();
        let joined = v.concat();
        let mut hasher = Sha1::new();
        hasher.update(joined.as_bytes());
        hex_lower(hasher.finalize())
    }

    /// Verify and decrypt GET echostr (URL verification).
    pub fn verify_and_decrypt_echostr(
        &self,
        msg_signature: &str,
        timestamp: &str,
        nonce: &str,
        echostr: &str,
    ) -> Result<String, VerifyError> {
        let expect = self.signature(timestamp, nonce, echostr);
        if expect != msg_signature {
            return Err(VerifyError::SignatureMismatch);
        }
        self.decrypt_cipher_text(echostr)
    }

    /// Verify and decrypt an encrypted callback XML body.
    ///
    /// - Extracts <Encrypt>...</Encrypt> from xml
    /// - Verifies signature using msg_signature, timestamp, nonce
    /// - Decrypts the base64 cipher text to plaintext xml
    pub fn verify_and_decrypt_xml(
        &self,
        msg_signature: &str,
        timestamp: &str,
        nonce: &str,
        encrypted_xml: &str,
    ) -> Result<String, VerifyError> {
        let cipher = extract_encrypt_part(encrypted_xml)?;
        let expect = self.signature(timestamp, nonce, &cipher);
        if expect != msg_signature {
            return Err(VerifyError::SignatureMismatch);
        }
        self.decrypt_cipher_text(&cipher)
    }

    /// Decrypt a base64 ciphertext to plaintext xml.
    ///
    /// Plaintext frame layout:
    /// - 16 bytes: random
    /// - 4 bytes: message length (big-endian)
    /// - N bytes: message xml
    /// - M bytes: appid/corpid
    ///
    /// Padding: PKCS7 (custom block size 32 in WeChat docs; AES uses 16. We will decode using 16.)
    pub fn decrypt_cipher_text(&self, cipher_b64: &str) -> Result<String, VerifyError> {
        let encrypted = BASE64
            .decode(cipher_b64.as_bytes())
            .map_err(|e| VerifyError::BadCiphertextBase64(e.to_string()))?;
        let iv = &self.aes_key[..16];

        // AES-256-CBC NoPadding + manual PKCS7 removal
        let mut buf = encrypted.clone();
        let decrypted = Aes256CbcDec::new((&self.aes_key).into(), iv.into())
            .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
            .map_err(|_| VerifyError::AesDecryptFailed)?
            .to_vec();

        let unpadded = pkcs7_unpad(&decrypted).map_err(|_| VerifyError::InvalidPadding)?;
        if unpadded.len() < 20 {
            return Err(VerifyError::InvalidPlaintextFrame);
        }
        let msg_len = u32::from_be_bytes(
            unpadded[16..20]
                .try_into()
                .map_err(|_| VerifyError::InvalidPlaintextFrame)?,
        ) as usize;
        if unpadded.len() < 20 + msg_len {
            return Err(VerifyError::InvalidPlaintextFrame);
        }
        let msg = &unpadded[20..20 + msg_len];
        let _from_appid = &unpadded[20 + msg_len..];

        // Optional strict check:
        // if _from_appid != self.appid_or_corpid.as_bytes() {
        //     return Err(VerifyError::InvalidPlaintextFrame);
        // }

        Ok(String::from_utf8_lossy(msg).into_owned())
    }

    // encrypt_plaintext removed: not required for Kf callback flow and depended on rand/NoPaddingAdapt.
}

/// Extracts the text inside <Encrypt>...</Encrypt> from an XML string.
fn extract_encrypt_part(xml: &str) -> Result<String, VerifyError> {
    // Prefer CDATA section first: <Encrypt><![CDATA[...]]></Encrypt>
    if let Some(start) = xml.find("<Encrypt><![CDATA[") {
        let from = start + "<Encrypt><![CDATA[".len();
        if let Some(end) = xml[from..].find("]]></Encrypt>") {
            return Ok(xml[from..from + end].to_string());
        }
    }
    // Fallback to plain text node: <Encrypt>...</Encrypt>
    if let Some(start_tag) = xml.find("<Encrypt>") {
        let from = start_tag + "<Encrypt>".len();
        if let Some(end_tag) = xml[from..].find("</Encrypt>") {
            return Ok(xml[from..from + end_tag].to_string());
        }
    }
    Err(VerifyError::MissingEncryptTag)
}

/// Lowercase hex for a sha1 digest.
fn hex_lower(d: sha1::digest::Output<Sha1>) -> String {
    let mut s = String::with_capacity(40);
    for b in d {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Simple PKCS7 unpad for block size 16/32.
/// Returns a subslice without the padding.
fn pkcs7_unpad(data: &[u8]) -> Result<&[u8], ()> {
    if data.is_empty() {
        return Err(());
    }
    let pad = *data.last().unwrap() as usize;
    if pad == 0 || pad > 32 || pad > data.len() {
        return Err(());
    }
    // All padding bytes must be equal to pad
    if data[data.len() - pad..].iter().any(|&b| b as usize != pad) {
        return Err(());
    }
    Ok(&data[..data.len() - pad])
}

/// PKCS7 pad to a multiple of `block`.
fn pkcs7_pad(data: &[u8], block: usize) -> Vec<u8> {
    let rem = data.len() % block;
    let pad = if rem == 0 { block } else { block - rem };
    let mut out = Vec::with_capacity(data.len() + pad);
    out.extend_from_slice(data);
    out.extend(std::iter::repeat(pad as u8).take(pad));
    out
}
