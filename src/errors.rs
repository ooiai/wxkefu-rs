#![allow(dead_code)]
//! Global WeCom/WeChat (Kf) error helpers
//!
//! Purpose
//! - Map well-known global errcode values to human-friendly categories and hints
//! - Recommend whether to retry (and how), or refresh the access_token
//! - Detect common JSON format warnings
//!
//! Notes
//! - Always make program logic depend on `errcode` rather than `errmsg`.
//! - `errmsg` may change; treat it only as diagnostic text.
//! - If the request JSON is malformed, WeCom may return errmsg containing
//!   "Warning: wrong json format." — fix your request body and resend.
//!
//! Typical usage
//! - Call `explain(errcode, errmsg)` to quickly get a human-readable guidance.
//! - Or call granular helpers:
//!     - `category_for(code)`
//!     - `should_retry(code)`
//!     - `should_refresh_token(code)`
//!     - `hint_for(code)`
//!     - `contains_wrong_json_format(errmsg)`
//!
//! Coverage
//! - Includes the codes you provided and common token/auth codes seen in practice.
//! - Unknown codes are categorized as `Unknown` with a conservative policy: no retry,
//!   no token refresh recommendation, and a generic hint directing to official docs.

/// High-level classification for an error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Success (errcode = 0)
    Success,
    /// Temporary/system busy or transient condition (retryable)
    TemporarySystem,
    /// Authentication/authorization/credential issues (fix credentials or refresh token)
    Auth,
    /// Invalid parameter, wrong type/size/range, unsupported combinations
    InvalidParam,
    /// Resource not found or not exists
    NotFound,
    /// Business rule or quota/limit exceeded
    Limit,
    /// Feature not supported or not enabled
    Unsupported,
    /// State/Timing constraints (e.g., 48-hour rule, 2-minute recall)
    InvalidState,
    /// Unknown/Uncategorized
    Unknown,
}

/// Recommendation for retry strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryAdvice {
    /// Whether to retry at all
    pub retry: bool,
    /// First backoff in milliseconds (if retry)
    pub initial_backoff_ms: Option<u64>,
    /// Max retries suggested
    pub max_retries: Option<u8>,
    /// Short reason for the advice
    pub reason: &'static str,
}

impl RetryAdvice {
    pub const NO: RetryAdvice = RetryAdvice {
        retry: false,
        initial_backoff_ms: None,
        max_retries: None,
        reason: "do not retry",
    };
    pub const TRANSIENT_3: RetryAdvice = RetryAdvice {
        retry: true,
        initial_backoff_ms: Some(300),
        max_retries: Some(3),
        reason: "transient/system busy; retry with backoff",
    };
}

/// A compact, friendly explanation for an errcode.
#[derive(Debug, Clone)]
pub struct ErrorHelp {
    pub code: i64,
    pub category: ErrorCategory,
    /// Short, stable summary for the code
    pub summary: &'static str,
    /// Actionable hint for mitigation
    pub hint: &'static str,
    /// Retry policy recommendation
    pub retry: RetryAdvice,
    /// Whether you should refresh/reacquire access_token
    pub refresh_token: bool,
}

/// Returns a friendly hint for a known errcode.
pub fn hint_for(code: i64) -> &'static str {
    match code {
        -1 => "System busy; retry with backoff (<=3 attempts).",
        0 => "Success.",
        40001 => {
            "Invalid secret or token; verify Kf Secret on Developer Config and ensure you use the correct credential pair."
        }
        40004 => {
            "Invalid media file type; check 'type' and file content against the media API requirements."
        }
        40005 => {
            "Invalid 'type' parameter; valid values depend on the API (e.g., image/voice/video/file for media upload)."
        }
        40006 => "Invalid file size; ensure the file size matches API limits.",
        40007 => {
            "Invalid media_id; ensure it comes from the temporary media upload API and hasn't expired (valid 3 days)."
        }
        40008 => "Invalid msgtype; ensure msgtype matches API and payload schema.",
        40009 => "Invalid image size; see media size limits.",
        40011 => "Invalid video size; see media size limits.",
        40014 => {
            "Invalid access_token; reacquire token using the correct WeCom Kf Secret, then retry."
        }
        90207 => "Invalid mini program appid; verify it is correct and bound appropriately.",
        95000 => "Invalid open_kfid; verify ID and that it belongs to your enterprise.",
        95001 => {
            "Message count limit exceeded (5 within 48 hours per active session); wait for next user message or the window to reset."
        }
        95002 => {
            "Message time limit exceeded (48-hour window); wait for user to message again or use allowed entry points (e.g., welcome on event)."
        }
        95003 => {
            "Consultation capacity or permission limit; verify enterprise verification/bind Channels as required."
        }
        95004 => {
            "open_kfid does not exist (cross-enterprise or deleted); verify the account is valid in your enterprise."
        }
        95005 => {
            "Kf account count exceeds limit; reduce accounts or upgrade; must have at least one."
        }
        95006 => "Invalid Kf account name; obey length/character constraints.",
        95007 => {
            "Invalid/expired msgtoken; use the latest token from callback event when calling sync_msg."
        }
        95008 => "Menu message items exceed limit; max 10 items.",
        95009 => "Invalid menu item type; ensure type matches spec (click/view/miniprogram/text).",
        95011 => "WeChat Kf already enabled in the enterprise; avoid repeated initialization.",
        95017 => {
            "Enterprise internal API switch is off; enable relevant API switches in admin console."
        }
        95022 => "Invalid location_type; check spec and payload fields.",
        95024 => {
            "No user-initiated message within 48h; cannot send this message (menu-click replies do not qualify)."
        }
        95025 => "At most 1 business card message per 48 hours.",
        95026 => "Low Kf account utilization; improve usage then try creating again.",
        95027 => {
            "Unverified enterprise can only create up to 10 Kf accounts; verify enterprise to increase quota."
        }
        95028 => {
            "Recall msgid not found; ensure the msgid was returned by API send within the same context."
        }
        95029 => {
            "Recall time expired; only messages sent via API within 2 minutes can be recalled."
        }
        _ => "Unknown code; refer to official docs and logs for details.",
    }
}

/// Classify errcode into a category.
pub fn category_for(code: i64) -> ErrorCategory {
    match code {
        0 => ErrorCategory::Success,
        -1 => ErrorCategory::TemporarySystem,
        40001 | 40014 => ErrorCategory::Auth,
        90207 => ErrorCategory::Auth,
        40004 | 40005 | 40006 | 40007 | 40008 | 40009 | 40011 | 95006 | 95022 => {
            ErrorCategory::InvalidParam
        }
        95000 | 95004 | 95028 => ErrorCategory::NotFound,
        95001 | 95003 | 95005 | 95008 | 95025 | 95026 | 95027 => ErrorCategory::Limit,
        95002 | 95007 | 95024 | 95029 => ErrorCategory::InvalidState,
        95009 | 95011 | 95017 => ErrorCategory::Unsupported,
        _ => ErrorCategory::Unknown,
    }
}

/// Whether to retry, and how.
pub fn should_retry(code: i64) -> RetryAdvice {
    match code {
        -1 => RetryAdvice::TRANSIENT_3, // system busy
        // Token/credentials: retrying without fix/refresh is pointless
        40001 | 40014 | 90207 => RetryAdvice {
            retry: false,
            initial_backoff_ms: None,
            max_retries: None,
            reason: "invalid credential or token; fix or refresh before retry",
        },
        // Parameter issues should be fixed then retried
        40004 | 40005 | 40006 | 40007 | 40008 | 40009 | 40011 | 95006 | 95022 => RetryAdvice {
            retry: false,
            initial_backoff_ms: None,
            max_retries: None,
            reason: "invalid parameter; correct request and resend",
        },
        // Business/state constraints: do not retry blindly
        95001 | 95002 | 95003 | 95004 | 95005 | 95008 | 95009 | 95011 | 95017 | 95024 | 95025
        | 95026 | 95027 | 95028 | 95029 => RetryAdvice::NO,
        // Unknown: be conservative (no auto-retry)
        _ => RetryAdvice::NO,
    }
}

/// Whether to refresh/reacquire access_token for this code.
pub fn should_refresh_token(code: i64) -> bool {
    matches!(code, 40001 | 40014)
}

/// Build a structured help object for a given errcode.
pub fn lookup(code: i64) -> ErrorHelp {
    let category = category_for(code);
    let summary = match code {
        -1 => "System busy",
        0 => "Success",
        40001 => "Invalid secret or token",
        40004 => "Invalid media file type",
        40005 => "Invalid 'type' parameter",
        40006 => "Invalid file size",
        40007 => "Invalid media_id parameter",
        40008 => "Invalid msgtype parameter",
        40009 => "Invalid image size",
        40011 => "Invalid video size",
        40014 => "Invalid access_token",
        90207 => "Invalid mini program appid",
        95000 => "Invalid open_kfid",
        95001 => "Message count limit (5 within 48h)",
        95002 => "Message time limit (48h window)",
        95003 => "Consult capacity/permission limit",
        95004 => "open_kfid not exists",
        95005 => "Kf account count exceeds limit",
        95006 => "Invalid Kf account name",
        95007 => "Invalid or expired msgtoken",
        95008 => "Menu items exceed limit (max 10)",
        95009 => "Invalid menu item type",
        95011 => "WeChat Kf already enabled",
        95017 => "API switch off for enterprise",
        95022 => "Invalid location_type",
        95024 => "No user-initiated message within 48h",
        95025 => "Card message limited to 1 per 48h",
        95026 => "Low Kf account utilization",
        95027 => "Unverified enterprise Kf account cap (10)",
        95028 => "Recall msgid not found",
        95029 => "Recall time expired (2 minutes)",
        _ => "Unknown error",
    };
    let hint = hint_for(code);
    let retry = should_retry(code);
    let refresh_token = should_refresh_token(code);

    ErrorHelp {
        code,
        category,
        summary,
        hint,
        retry,
        refresh_token,
    }
}

/// Produce a concise, human-readable explanation string.
/// - Includes code, category, a short summary, retry/refresh advice, and detects JSON format warnings.
pub fn explain(errcode: i64, errmsg: &str) -> String {
    let help = lookup(errcode);
    let mut parts = vec![
        format!("errcode={} ({:?})", help.code, help.category),
        help.summary.to_string(),
        format!("hint: {}", help.hint),
    ];

    if help.retry.retry {
        let mut retry_line = String::from("retry: yes");
        if let Some(ms) = help.retry.initial_backoff_ms {
            retry_line.push_str(&format!(", initial_backoff_ms={}", ms));
        }
        if let Some(n) = help.retry.max_retries {
            retry_line.push_str(&format!(", max_retries={}", n));
        }
        retry_line.push_str(&format!(" ({})", help.retry.reason));
        parts.push(retry_line);
    } else {
        parts.push(format!("retry: no ({})", help.retry.reason));
    }

    if help.refresh_token {
        parts.push("refresh_token: yes".to_string());
    } else {
        parts.push("refresh_token: no".to_string());
    }

    if contains_wrong_json_format(errmsg) {
        parts.push(
            "detected: Warning: wrong json format. Please validate JSON request body.".to_string(),
        );
    }

    parts.join(" | ")
}

/// Detect "Warning: wrong json format." substring in errmsg (case-insensitive).
pub fn contains_wrong_json_format(errmsg: &str) -> bool {
    errmsg
        .to_ascii_lowercase()
        .contains("warning: wrong json format")
}

/// Convenience: quick decision helpers you can use in calling code.

/// Return true if this error looks temporary (safe to retry with backoff).
pub fn is_temporary(code: i64) -> bool {
    matches!(category_for(code), ErrorCategory::TemporarySystem)
}

/// Return true if this is likely due to invalid request parameters.
pub fn is_param_issue(code: i64) -> bool {
    matches!(category_for(code), ErrorCategory::InvalidParam)
}

/// Return true if this is a business/state/limit kind of error (should not blindly retry).
pub fn is_business_or_limit_issue(code: i64) -> bool {
    matches!(
        category_for(code),
        ErrorCategory::Limit | ErrorCategory::InvalidState | ErrorCategory::Unsupported
    )
}

/// Return true if the resource seems not found.
pub fn is_not_found(code: i64) -> bool {
    matches!(category_for(code), ErrorCategory::NotFound)
}

/// Return true if this looks like an auth/token problem.
pub fn is_auth_issue(code: i64) -> bool {
    matches!(category_for(code), ErrorCategory::Auth)
}

/// Return a recommended max retries for transient errors, otherwise None.
pub fn recommended_max_retries(code: i64) -> Option<u8> {
    if should_retry(code).retry {
        should_retry(code).max_retries
    } else {
        None
    }
}

/// Return a recommended initial backoff for transient errors, otherwise None.
pub fn recommended_initial_backoff_ms(code: i64) -> Option<u64> {
    if should_retry(code).retry {
        should_retry(code).initial_backoff_ms
    } else {
        None
    }
}
