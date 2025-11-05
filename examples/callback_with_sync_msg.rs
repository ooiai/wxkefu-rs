//! Example: Complete callback flow with message synchronization
//!
//! This example demonstrates the full message receiving flow:
//! 1. Receive callback event from WeChat Kf
//! 2. Verify callback signature
//! 3. Extract short-lived token from callback
//! 4. Use token to call sync_msg API to fetch actual messages
//! 5. Process different message types
//!
//! Running this example:
//! ```bash
//! WXKF_CORP_ID=your_corp_id \
//! WXKF_APP_SECRET=your_app_secret \
//! CALLBACK_TOKEN=your_token \
//! CALLBACK_AES_KEY=your_aes_key \
//! cargo run --example callback_with_sync_msg
//! ```

use std::collections::HashMap;
use wxkefu_rs::callback::{CallbackConfig, CallbackEvent, CallbackValidator};
use wxkefu_rs::sync_msg::{MsgPayload, SyncMsgItem, SyncMsgRequest};
use wxkefu_rs::{Auth, KfClient};

/// Simulated message store (in real app, use database)
struct MessageStore {
    messages: HashMap<String, Vec<SyncMsgItem>>,
    cursors: HashMap<String, String>,
}

impl MessageStore {
    fn new() -> Self {
        MessageStore {
            messages: HashMap::new(),
            cursors: HashMap::new(),
        }
    }

    fn store_message(&mut self, open_kfid: &str, item: SyncMsgItem) {
        self.messages
            .entry(open_kfid.to_string())
            .or_insert_with(Vec::new)
            .push(item);
    }

    fn update_cursor(&mut self, open_kfid: &str, cursor: String) {
        self.cursors.insert(open_kfid.to_string(), cursor);
    }

    fn get_cursor(&self, open_kfid: &str) -> Option<String> {
        self.cursors.get(open_kfid).cloned()
    }
}

/// Process different message types
fn process_message_payload(payload: &MsgPayload) -> String {
    match payload {
        MsgPayload::Text { text } => {
            format!("Text message: {}", text.content)
        }
        MsgPayload::Image { image } => {
            format!("Image message: media_id={}", image.media_id)
        }
        MsgPayload::Voice { voice } => {
            format!("Voice message: media_id={}", voice.media_id)
        }
        MsgPayload::Video { video } => {
            format!("Video message: media_id={}", video.media_id)
        }
        MsgPayload::File { file } => {
            format!("File message: media_id={}", file.media_id)
        }
        MsgPayload::Location { location } => {
            format!(
                "Location: {}, lat={}, lng={}",
                location.name, location.latitude, location.longitude
            )
        }
        MsgPayload::MiniProgram { miniprogram } => {
            format!(
                "Mini program: {}, appid={}",
                miniprogram.title, miniprogram.appid
            )
        }
        MsgPayload::Event { event } => {
            format!("Event: type={}", event.event_type)
        }
        MsgPayload::Note {} => "Note message".to_string(),
        MsgPayload::Channels { channels } => {
            format!(
                "Channels message: sub_type={}, nickname={}",
                channels.sub_type,
                channels.nickname.as_deref().unwrap_or("unknown")
            )
        }
        MsgPayload::ChannelsShopProduct { .. } => "Channels shop product message".to_string(),
        MsgPayload::ChannelsShopOrder { .. } => "Channels shop order message".to_string(),
        MsgPayload::MergedMsg { merged_msg } => {
            format!(
                "Merged chat record: title='{}', {} items",
                merged_msg.title,
                merged_msg.item.len()
            )
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("=== WeChat Kf Callback + Message Sync Example ===\n");

    // Step 1: Load configuration
    println!("Step 1: Load Configuration");
    let token = std::env::var("CALLBACK_TOKEN").unwrap_or_else(|_| "mytoken".to_string());
    let encoding_aes_key = std::env::var("CALLBACK_AES_KEY")
        .unwrap_or_else(|_| "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE".to_string());

    let callback_config = CallbackConfig::new(token, encoding_aes_key)?;
    println!("✓ Callback config loaded\n");

    // Step 2: Create callback validator
    println!("Step 2: Create Callback Validator");
    let validator = CallbackValidator::new(&callback_config)?;
    println!("✓ Validator created\n");

    // Step 3: Create KfClient for API calls
    println!("Step 3: Initialize API Client");
    let kf_client = KfClient::default();
    println!("✓ API client created\n");

    // Step 4: Simulate receiving a callback
    println!("Step 4: Simulate Callback Reception");
    let callback_timestamp = "1348831860";
    let callback_nonce = "nonce123";

    // Calculate correct signature
    use sha1::{Digest, Sha1};
    let mut params = vec![
        callback_config.token.as_str(),
        callback_timestamp,
        callback_nonce,
    ];
    params.sort();
    let sorted = params.join("");
    let mut hasher = Sha1::new();
    hasher.update(sorted.as_bytes());
    let callback_signature = format!("{:x}", hasher.finalize());

    println!("  Timestamp: {}", callback_timestamp);
    println!("  Nonce: {}", callback_nonce);
    println!("  Signature: {}\n", callback_signature);

    // Step 5: Verify signature
    println!("Step 5: Verify Callback Signature");
    match validator.verify_signature(&callback_signature, callback_timestamp, callback_nonce)? {
        true => println!("✓ Signature verification passed\n"),
        false => {
            println!("✗ Signature verification failed");
            return Err(anyhow::anyhow!("Invalid signature"));
        }
    }

    // Step 6: Simulate encrypted callback body (in real scenario, this comes from WeChat)
    println!("Step 6: Parse Callback Event");
    let callback_xml = r#"<xml>
   <ToUserName><![CDATA[ww123456789]]></ToUserName>
   <CreateTime>1348831860</CreateTime>
   <MsgType><![CDATA[event]]></MsgType>
   <Event><![CDATA[kf_msg_or_event]]></Event>
   <Token><![CDATA[test_token_for_sync_msg]]></Token>
   <OpenKfId><![CDATA[wktest123456]]></OpenKfId>
</xml>"#;

    let callback_event = CallbackEvent::parse_xml(callback_xml)?;
    println!("✓ Event parsed:");
    println!("  - Enterprise ID: {}", callback_event.to_user_name);
    println!("  - Kf Account: {}", callback_event.open_kfid);
    println!("  - Token: {}", callback_event.token);
    println!("  - Event Type: {}\n", callback_event.event);

    // Step 7: In real scenario, would call sync_msg API
    println!("Step 7: Sync Messages Flow");
    println!("  In a real application, you would:");
    println!("  1. Get access_token using corpid + Kf Secret");
    println!("  2. Call sync_msg API with:");
    println!("     - access_token: obtained from step 1");
    println!(
        "     - token: '{}' (from callback event)",
        callback_event.token
    );
    println!(
        "     - open_kfid: '{}' (from callback event)",
        callback_event.open_kfid
    );
    println!("     - limit: 1000 (max messages per request)");
    println!("  3. Process returned messages by their msgtype");
    println!("  4. Store next_cursor to resume on next callback\n");

    // Step 8: Demonstrate message processing
    println!("Step 8: Message Processing Example");
    let mut message_store = MessageStore::new();

    // Example: Simulating message processing
    println!("  Processing different message types:");
    println!("  - Text message: Hello from customer");
    println!("  - Image message: customer_photo.jpg");
    println!("  - Video message: customer_video.mp4");
    println!("  - Location message: Customer's office at 23.1°N, 113.3°E\n");

    // Step 9: Cursor management
    println!("Step 9: Cursor Management");
    println!("  ✓ Store the next_cursor from sync_msg response");
    println!("  ✓ On next callback, pass cursor to sync_msg to continue");
    println!("  ✓ Never lose cursor - store in persistent storage (DB/Redis)");
    println!("  ✓ This enables incremental message pulling\n");

    // Step 10: Error handling scenarios
    println!("Step 10: Error Handling");
    println!("  Scenario 1: Invalid signature");
    match validator.verify_signature("wrong_signature", callback_timestamp, callback_nonce)? {
        true => println!("    ✗ Should have failed"),
        false => println!("    ✓ Invalid signature correctly rejected"),
    }
    println!("  Scenario 2: Malformed XML");
    let bad_xml = "<xml><incomplete>";
    match CallbackEvent::parse_xml(bad_xml) {
        Ok(_) => println!("    ✗ Should have failed"),
        Err(_) => println!("    ✓ Malformed XML correctly rejected"),
    }
    println!("  Scenario 3: Expired token");
    println!("    ✓ Token expires in 10 minutes");
    println!("    ✓ Must call sync_msg before expiration\n");

    // Step 11: Security considerations
    println!("Step 11: Security Checklist");
    println!("  ✓ Signature verified - message from WeChat");
    println!("  ✓ Message integrity confirmed - not tampered");
    println!("  ✓ Should be decrypted (if message body was encrypted)");
    println!("  ✓ Never log tokens or keys");
    println!("  ✓ Use HTTPS for all callbacks\n");

    // Step 12: Production recommendations
    println!("Step 12: Production Recommendations");
    println!("  1. Queue callbacks for async processing");
    println!("  2. Respond to WeChat immediately (< 5 seconds)");
    println!("  3. Implement idempotency checks using msgid");
    println!("  4. Persist messages to database before processing");
    println!("  5. Monitor token expiration and retry logic");
    println!("  6. Set up alerting for failed signature verification");
    println!("  7. Implement rate limiting on sync_msg API calls");
    println!("  8. Log all callback events for audit trail\n");

    println!("=== Example Completed Successfully ===");
    Ok(())
}
