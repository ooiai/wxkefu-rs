//! Example: WeChat Kf callback server
//!
//! This example demonstrates how to set up a callback server that:
//! 1. Verifies incoming callback signatures
//! 2. Decrypts encrypted messages
//! 3. Parses callback events
//! 4. Pulls messages using sync_msg API
//!
//! Prerequisites:
//! - Set up WeChat Kf callback configuration with your token and EncodingAESKey
//! - Ensure your callback URL is publicly accessible
//!
//! Running this example:
//! ```bash
//! CALLBACK_TOKEN=your_callback_token \
//! CALLBACK_AES_KEY=your_43_char_aes_key \
//! cargo run --example callback_server
//! ```
//!
//! The server will listen on http://127.0.0.1:3000
//! - GET  /health - Health check endpoint
//! - POST /callback - WeChat Kf callback endpoint

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};
use wxkefu_rs::callback::{CallbackConfig, CallbackEvent, CallbackValidator};

/// Query parameters from WeChat Kf callback
#[derive(Debug, Deserialize)]
struct CallbackQuery {
    msg_signature: String,
    timestamp: String,
    nonce: String,
    #[serde(default)]
    echostr: Option<String>,
}

/// Request body from WeChat Kf callback (encrypted)
#[derive(Debug, Deserialize)]
struct CallbackBody {
    #[serde(default)]
    encrypt: Option<String>,
}

/// Application state
#[derive(Clone)]
struct AppState {
    validator: Arc<CallbackValidator>,
}

/// Response to WeChat Kf callback
#[derive(Debug, Serialize)]
struct CallbackApiResponse {
    success: bool,
    message: String,
}

/// Handle WeChat Kf callback POST request
async fn handle_callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
    body_str: String,
) -> Result<impl IntoResponse, StatusCode> {
    info!(
        "Received callback: msg_signature={}, timestamp={}, nonce={}",
        query.msg_signature, query.timestamp, query.nonce
    );

    // Step 1: Verify signature
    match state
        .validator
        .verify_signature(&query.msg_signature, &query.timestamp, &query.nonce)
    {
        Ok(false) => {
            error!("Signature verification failed");
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            error!("Signature verification error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        _ => {}
    }

    info!("Signature verified successfully");

    // Step 2: Parse encrypted message from body
    let body: CallbackBody = match serde_json::from_str(&body_str) {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to parse request body: {}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    if let Some(encrypted_msg) = body.encrypt {
        // Step 3: Decrypt message
        let decrypted = match state.validator.decrypt_message(&encrypted_msg) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Failed to decrypt message: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        info!("Message decrypted successfully");

        // Step 4: Parse XML event
        match CallbackEvent::parse_xml(&decrypted) {
            Ok(event) => {
                info!(
                    "Parsed callback event: enterprise_id={}, open_kfid={}, token={}",
                    event.to_user_name, event.open_kfid, event.token
                );

                // Step 5: Process event (in real app, you would:
                // - Validate the token is not expired
                // - Call sync_msg API with the token to fetch actual messages
                // - Store messages in your database
                // - Handle different message types
                info!(
                    "Event details: type={}, event={}, timestamp={}",
                    event.msg_type, event.event, event.create_time
                );

                Ok((StatusCode::OK, "success"))
            }
            Err(e) => {
                error!("Failed to parse callback event: {}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        info!("No encrypted message in callback");
        Ok((StatusCode::OK, "success"))
    }
}

/// Health check endpoint
async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "message": "WeChat Kf callback server is running"
    }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load configuration from environment
    let token = std::env::var("CALLBACK_TOKEN").unwrap_or_else(|_| "mytoken123".to_string());
    let encoding_aes_key = std::env::var("CALLBACK_AES_KEY")
        .unwrap_or_else(|_| "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE".to_string());

    info!("Initializing callback validator with token={}", token);

    // Create callback configuration
    let config = CallbackConfig::new(token, encoding_aes_key)?;

    // Create validator
    let validator = CallbackValidator::new(&config)?;

    let state = AppState {
        validator: Arc::new(validator),
    };

    // Build router
    let app = Router::new()
        .route("/health", axum::routing::get(health))
        .route("/callback", post(handle_callback))
        .with_state(state);

    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    let addr = listener.local_addr()?;
    info!("Server listening on http://{}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}
