/*!
Example: Global error explanation helper usage

Run:
  cargo run --example error_help

What this shows:
- How to use wxkefu_rs::errors helpers to interpret errcode
- How to decide retry vs refresh-token vs fix-params
- How to detect "Warning: wrong json format." in errmsg
*/

use wxkefu_rs::errors::{
    explain, is_auth_issue, is_business_or_limit_issue, is_not_found, is_param_issue, is_temporary,
    lookup, recommended_initial_backoff_ms, recommended_max_retries,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Sample (errcode, errmsg) pairs to demonstrate typical cases
    let samples: Vec<(i64, &str)> = vec![
        (-1, "system busy"),
        (0, "ok"),
        (40001, "invalid secret"),
        (40007, "invalid media id"),
        (40014, "invalid access_token"),
        (95001, "message count limit (5 in 48h)"),
        (95002, "message time limit (48h window)"),
        (95024, "no user message within 48h"),
        (95029, "recall expired (2 minutes)"),
        (95005, "account count exceeds limit"),
        (95027, "unverified enterprise account cap (10)"),
        (123456, "unknown"),
        // Demonstrate wrong json format detection:
        (40007, "Warning: wrong json format."),
    ];

    println!("== Global error explanation demo ==");
    for (code, errmsg) in samples {
        let human = explain(code, errmsg);
        println!("\n- errcode={} errmsg='{}'\n  {}", code, errmsg, human);

        // Structured help
        let help = lookup(code);
        println!(
            "  details: category={:?}, refresh_token={}, retry={{enabled:{}, initial_backoff_ms:{:?}, max_retries:{:?}}}",
            help.category,
            help.refresh_token,
            help.retry.retry,
            help.retry.initial_backoff_ms,
            help.retry.max_retries
        );

        // Quick boolean tags to branch your logic
        println!(
            "  tags: auth={} param={} temporary={} business_or_limit={} not_found={}",
            is_auth_issue(code),
            is_param_issue(code),
            is_temporary(code),
            is_business_or_limit_issue(code),
            is_not_found(code)
        );

        // Optional: use recommended retry parameters
        if let Some(ms) = recommended_initial_backoff_ms(code) {
            println!("  recommended initial backoff (ms): {}", ms);
        }
        if let Some(n) = recommended_max_retries(code) {
            println!("  recommended max retries: {}", n);
        }

        // Example action plan based on the helpers
        advise_action(code, errmsg);
    }

    Ok(())
}

/// A small decision helper that demonstrates how you might branch on error types.
fn advise_action(errcode: i64, errmsg: &str) {
    if errcode == 0 {
        println!("  action: success; proceed.");
        return;
    }

    if is_auth_issue(errcode) {
        println!("  action: refresh/reacquire access_token, verify credentials, then retry once.");
        return;
    }

    if is_temporary(errcode) {
        let backoff = recommended_initial_backoff_ms(errcode).unwrap_or(300);
        let tries = recommended_max_retries(errcode).unwrap_or(3);
        println!(
            "  action: transient/system busy; retry with backoff ({}ms), up to {} attempts.",
            backoff, tries
        );
        return;
    }

    if is_param_issue(errcode) {
        let wrong_json = errmsg
            .to_ascii_lowercase()
            .contains("warning: wrong json format");
        if wrong_json {
            println!("  action: fix JSON request body (malformed). Then resend.");
        } else {
            println!(
                "  action: fix request parameters (type/size/range/msgtype/media_id). Then resend."
            );
        }
        return;
    }

    if is_business_or_limit_issue(errcode) {
        match errcode {
            95001 => println!(
                "  action: hit 5-message limit in 48h; wait for next user message or window reset."
            ),
            95002 | 95024 => println!(
                "  action: outside 48h window; wait for user to message again or use allowed flows (e.g., welcome on event)."
            ),
            95025 => println!("  action: only 1 business card message per 48h; defer."),
            95026 => println!(
                "  action: Kf account utilization too low; improve usage before creating more."
            ),
            95027 => println!("  action: verify enterprise to increase Kf account quota."),
            _ => println!(
                "  action: business/state constraint; adjust flow or data, do not blindly retry."
            ),
        }
        return;
    }

    if is_not_found(errcode) {
        println!(
            "  action: verify resources (open_kfid/msgid) exist and belong to your enterprise."
        );
        return;
    }

    println!(
        "  action: unknown error; check logs and official docs for this code, avoid blind retries."
    );
}
