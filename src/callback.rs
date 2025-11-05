#![allow(dead_code)]
//! WeCom Kf callback handling and message decryption
//!
//! The callback system works as follows:
//! 1. WeChat Kf server pushes events to your configured callback URL
//! 2. Events are signed using Token for authenticity verification
//! 3. Message content is encrypted with EncodingAESKey for confidentiality
//! 4. Your service decrypts and processes the events
//!
//! Configuration required:
//! - URL: Your callback service endpoint (publicly accessible)
//! - Token: Custom string (English/digits, max 32 bytes) for signature calculation
//! - EncodingAESKey: Encryption key (English/digits, exactly 43 bytes)
//!
//! API doc (CN): https://kf.weixin.qq.com/api/doc/path/93303
//!
//! ## Signature Verification
//!
//! The signature is calculated as:
//! 1. Sort query parameters: msg_signature, timestamp, nonce (and others if present)
//! 2. Concatenate: [sorted_string]
//! 3. Calculate SHA1 hash
//! 4. Compare with provided msg_signature
//!
//! ## Message Decryption
//!
//! Messages are encrypted using AES-128-CBC (PKCS7 padding):
//! 1. Decode the encrypted message from base64
//! 2. Decrypt using AES-128-CBC with the 32-byte key derived from EncodingAESKey
//! 3. Remove PKCS7 padding
//! 4. Parse the decrypted XML to extract the message
//!
//! ## Example Usage
//!
//! ```ignore
//! use wxkefu_rs::callback::{CallbackConfig, CallbackValidator, MessageDecryptor};
//!
//! // Configuration (typically from environment or config file)
//! let config = CallbackConfig {
//!     token: "your_token".to_string(),
//!     encoding_aes_key: "your_43_char_aes_key".to_string(),
//! };
//!
//! // Create validator
//! let validator = CallbackValidator::new(&config)?;
//!
//! // Verify signature from incoming request
//! let signature = "msg_signature_from_query";
//! let timestamp = "1348831860";
//! let nonce = "nonce_value";
//! let is_valid = validator.verify_signature(signature, timestamp, nonce)?;
//!
//! if !is_valid {
//!     return Err("Invalid signature");
//! }
//!
//! // Decrypt and parse the message
//! let encrypted_msg = "base64_encoded_encrypted_message";
//! let decrypted = validator.decrypt_message(encrypted_msg)?;
//! let event = CallbackEvent::parse_xml(&decrypted)?;
//! ```

use aes::Aes128;
use base64::{Engine, engine::general_purpose::STANDARD};
use cbc::Decryptor;
use cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use generic_array::GenericArray;
use sha1::{Digest, Sha1};
use std::error::Error as StdError;
use std::fmt;

/// Custom error type for callback operations
#[derive(Debug, Clone)]
pub enum CallbackError {
    InvalidKeySize { expected: usize, got: usize },
    InvalidBase64(String),
    DecryptionFailed(String),
    InvalidPadding,
    XmlParseError(String),
    SignatureVerificationFailed,
    InvalidConfiguration(String),
}

impl fmt::Display for CallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallbackError::InvalidKeySize { expected, got } => {
                write!(f, "Invalid key size: expected {}, got {}", expected, got)
            }
            CallbackError::InvalidBase64(e) => write!(f, "Invalid base64: {}", e),
            CallbackError::DecryptionFailed(e) => write!(f, "Decryption failed: {}", e),
            CallbackError::InvalidPadding => write!(f, "Invalid PKCS7 padding"),
            CallbackError::XmlParseError(e) => write!(f, "XML parse error: {}", e),
            CallbackError::SignatureVerificationFailed => {
                write!(f, "Signature verification failed")
            }
            CallbackError::InvalidConfiguration(e) => write!(f, "Invalid configuration: {}", e),
        }
    }
}

impl StdError for CallbackError {}

/// Callback configuration
#[derive(Debug, Clone)]
pub struct CallbackConfig {
    /// Token for signature calculation (English/digits, max 32 bytes)
    pub token: String,
    /// AES key for message encryption/decryption (must be exactly 43 bytes)
    pub encoding_aes_key: String,
}

impl CallbackConfig {
    /// Create a new callback configuration
    pub fn new(token: String, encoding_aes_key: String) -> Result<Self, CallbackError> {
        // Validate token length
        if token.is_empty() || token.len() > 32 {
            return Err(CallbackError::InvalidConfiguration(
                "Token must be 1-32 characters".to_string(),
            ));
        }

        // Validate token characters (English/digits only)
        if !token.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(CallbackError::InvalidConfiguration(
                "Token must contain only English and digits".to_string(),
            ));
        }

        // Validate AES key length (must be exactly 43 bytes)
        if encoding_aes_key.len() != 43 {
            return Err(CallbackError::InvalidConfiguration(format!(
                "EncodingAESKey must be exactly 43 bytes, got {}",
                encoding_aes_key.len()
            )));
        }

        // Validate AES key characters (English/digits only)
        if !encoding_aes_key.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(CallbackError::InvalidConfiguration(
                "EncodingAESKey must contain only English and digits".to_string(),
            ));
        }

        Ok(CallbackConfig {
            token,
            encoding_aes_key,
        })
    }
}

/// Callback validator for signature verification and message decryption
pub struct CallbackValidator {
    token: String,
    aes_key: Vec<u8>,
}

impl CallbackValidator {
    /// Create a new callback validator
    pub fn new(config: &CallbackConfig) -> Result<Self, CallbackError> {
        // Decode the 43-byte AES key to get 32-byte key
        // Handle base64 strings without padding (add padding if needed)
        let mut key_str = config.encoding_aes_key.clone();
        while key_str.len() % 4 != 0 {
            key_str.push('=');
        }

        let aes_key = STANDARD
            .decode(&key_str)
            .map_err(|e| CallbackError::InvalidBase64(e.to_string()))?;

        if aes_key.len() != 32 {
            return Err(CallbackError::InvalidKeySize {
                expected: 32,
                got: aes_key.len(),
            });
        }

        Ok(CallbackValidator {
            token: config.token.clone(),
            aes_key,
        })
    }

    /// Verify the signature of an incoming callback
    ///
    /// # Arguments
    /// * `msg_signature` - The signature from the query parameter `msg_signature`
    /// * `timestamp` - The timestamp from the query parameter `timestamp`
    /// * `nonce` - The nonce from the query parameter `nonce`
    ///
    /// # Returns
    /// `Ok(true)` if signature is valid, `Ok(false)` if invalid
    pub fn verify_signature(
        &self,
        msg_signature: &str,
        timestamp: &str,
        nonce: &str,
    ) -> Result<bool, CallbackError> {
        // Sort the parameters
        let mut params = vec![self.token.as_str(), timestamp, nonce];
        params.sort();

        // Concatenate sorted parameters
        let sorted_string = params.join("");

        // Calculate SHA1 hash
        let mut hasher = Sha1::new();
        hasher.update(sorted_string.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        // Compare with provided signature
        Ok(hash == msg_signature)
    }

    /// Decrypt a message encrypted with AES-128-CBC
    ///
    /// # Arguments
    /// * `encrypted_msg` - Base64-encoded encrypted message
    ///
    /// # Returns
    /// Decrypted message as UTF-8 string
    pub fn decrypt_message(&self, encrypted_msg: &str) -> Result<String, CallbackError> {
        // Decode base64
        let encrypted = STANDARD
            .decode(encrypted_msg)
            .map_err(|e| CallbackError::InvalidBase64(e.to_string()))?;

        // The IV is the first 16 bytes of the encrypted data
        if encrypted.len() < 16 {
            return Err(CallbackError::DecryptionFailed(
                "Encrypted message too short".to_string(),
            ));
        }

        let (iv, ciphertext) = encrypted.split_at(16);

        // Decrypt using AES-128-CBC
        let mut buffer = ciphertext.to_vec();
        let key = GenericArray::from_slice(&self.aes_key);
        let iv = GenericArray::from_slice(iv);
        let mut decryptor = Decryptor::<Aes128>::new(key, iv);

        let decrypted = decryptor
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|e| CallbackError::DecryptionFailed(format!("Decryption error: {}", e)))?;

        // Convert to string
        String::from_utf8(decrypted.to_vec())
            .map_err(|e| CallbackError::DecryptionFailed(format!("UTF-8 error: {}", e)))
    }
}

/// Parsed callback event from WeChat Kf
#[derive(Debug, Clone)]
pub struct CallbackEvent {
    /// ToUserName: WeChat Kf enterprise ID (usually starts with `ww`)
    pub to_user_name: String,
    /// CreateTime: Unix timestamp
    pub create_time: u64,
    /// MsgType: Usually "event"
    pub msg_type: String,
    /// Event: Event type (e.g., "kf_msg_or_event")
    pub event: String,
    /// Token: Short-lived token for calling sync_msg API
    pub token: String,
    /// OpenKfId: Kf account ID with new messages
    pub open_kfid: String,
}

impl CallbackEvent {
    /// Parse XML-encoded callback event
    ///
    /// Example input:
    /// ```xml
    /// <xml>
    ///   <ToUserName><![CDATA[ww12345678910]]></ToUserName>
    ///   <CreateTime>1348831860</CreateTime>
    ///   <MsgType><![CDATA[event]]></MsgType>
    ///   <Event><![CDATA[kf_msg_or_event]]></Event>
    ///   <Token><![CDATA[ENCApHxnGDNAVNY4AaSJKj4Tb5mwsEMzxhFmHVGcra996NR]]></Token>
    ///   <OpenKfId><![CDATA[wkxxxxxxx]]></OpenKfId>
    /// </xml>
    /// ```
    pub fn parse_xml(xml_str: &str) -> Result<Self, CallbackError> {
        // Simple XML parsing using quick-xml
        use quick_xml::de::from_str;
        use serde::Deserialize;

        #[derive(Debug, Deserialize)]
        struct XmlEvent {
            #[serde(rename = "ToUserName")]
            to_user_name: String,
            #[serde(rename = "CreateTime")]
            create_time: u64,
            #[serde(rename = "MsgType")]
            msg_type: String,
            #[serde(rename = "Event")]
            event: String,
            #[serde(rename = "Token")]
            token: String,
            #[serde(rename = "OpenKfId")]
            open_kfid: String,
        }

        let xml_event: XmlEvent = from_str(xml_str)
            .map_err(|e| CallbackError::XmlParseError(format!("Failed to parse XML: {}", e)))?;

        Ok(CallbackEvent {
            to_user_name: xml_event.to_user_name,
            create_time: xml_event.create_time,
            msg_type: xml_event.msg_type,
            event: xml_event.event,
            token: xml_event.token,
            open_kfid: xml_event.open_kfid,
        })
    }
}

/// Simplified callback response to WeChat Kf
///
/// When you receive a callback, you should respond with:
/// - HTTP 200 status code
/// - Response body: `"success"` (or empty)
///
/// This ensures WeChat Kf knows your server received the event.
#[derive(Debug, Clone)]
pub struct CallbackResponse {
    /// Always "success" to indicate successful processing
    pub message: String,
}

impl CallbackResponse {
    /// Create a success response
    pub fn success() -> Self {
        CallbackResponse {
            message: "success".to_string(),
        }
    }

    /// Serialize to response body
    pub fn to_string(&self) -> String {
        "success".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        // Valid config - using 43-char base64 key without padding
        let result = CallbackConfig::new(
            "mytoken123".to_string(),
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE".to_string(),
        );
        assert!(result.is_ok());

        // Token too long
        let result = CallbackConfig::new(
            "a".repeat(33),
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE".to_string(),
        );
        assert!(result.is_err());

        // Invalid token characters
        let result = CallbackConfig::new(
            "my-token".to_string(),
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE".to_string(),
        );
        assert!(result.is_err());

        // AES key wrong length (too short)
        let result = CallbackConfig::new(
            "mytoken".to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        );
        assert!(result.is_err());

        // AES key wrong length (too long with padding)
        let result = CallbackConfig::new(
            "mytoken".to_string(),
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=".to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_verification() {
        let config = CallbackConfig::new(
            "mytoken".to_string(),
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE".to_string(),
        )
        .unwrap();
        let validator = CallbackValidator::new(&config).unwrap();

        // Calculate expected signature
        let timestamp = "1348831860";
        let nonce = "nonce_value";
        let mut params = vec!["mytoken", timestamp, nonce];
        params.sort();
        let sorted_string = params.join("");
        let mut hasher = Sha1::new();
        hasher.update(sorted_string.as_bytes());
        let expected_sig = format!("{:x}", hasher.finalize());

        // Verify correct signature
        let result = validator
            .verify_signature(&expected_sig, timestamp, nonce)
            .unwrap();
        assert!(result);

        // Verify incorrect signature
        let result = validator
            .verify_signature("invalid_signature", timestamp, nonce)
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_event_parsing() {
        let xml = r#"<xml>
   <ToUserName><![CDATA[ww12345678910]]></ToUserName>
   <CreateTime>1348831860</CreateTime>
   <MsgType><![CDATA[event]]></MsgType>
   <Event><![CDATA[kf_msg_or_event]]></Event>
   <Token><![CDATA[ENCApHxnGDNAVNY4AaSJKj4Tb5mwsEMzxhFmHVGcra996NR]]></Token>
   <OpenKfId><![CDATA[wkxxxxxxx]]></OpenKfId>
</xml>"#;

        let event = CallbackEvent::parse_xml(xml).unwrap();
        assert_eq!(event.to_user_name, "ww12345678910");
        assert_eq!(event.create_time, 1348831860);
        assert_eq!(event.msg_type, "event");
        assert_eq!(event.event, "kf_msg_or_event");
        assert_eq!(
            event.token,
            "ENCApHxnGDNAVNY4AaSJKj4Tb5mwsEMzxhFmHVGcra996NR"
        );
        assert_eq!(event.open_kfid, "wkxxxxxxx");
    }
}
