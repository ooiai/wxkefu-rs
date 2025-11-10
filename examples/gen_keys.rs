use std::env;
use std::process;

use wxkefu_rs::keygen::{generate_encoding_aes_key, generate_token, verify_encoding_aes_key};

/// Simple example to generate WeChat Kf Token and EncodingAESKey, printing .env lines.
///
/// Usage:
///   cargo run --example gen_keys
///   cargo run --example gen_keys -- --len 16
///   cargo run --example gen_keys -- 24
///
/// Output (stdout):
///   WXKF_TOKEN=<alphanumeric up to 32 chars>
///   WXKF_ENCODING_AES_KEY=<43-char alphanumeric, Base64 without '='>
fn main() {
    let (token_len, show_help) = parse_args(env::args().collect());

    if show_help {
        print_help();
        return;
    }

    let token = generate_token(token_len);
    let encoding_aes_key = generate_encoding_aes_key();

    // Defensive verify (should always pass since generator enforces it)
    if !verify_encoding_aes_key(&encoding_aes_key) {
        eprintln!("Fatal: generated EncodingAESKey did not pass verification. Please retry.");
        process::exit(2);
    }

    // Print as .env-compatible lines
    println!("WXKF_TOKEN={}", token);
    println!("WXKF_ENCODING_AES_KEY={}", encoding_aes_key);
}

fn parse_args(args: Vec<String>) -> (usize, bool) {
    // Defaults
    let mut len: usize = 32;
    let mut show_help = false;

    // Allow length via env var as well
    if let Ok(env_len) = env::var("WXKF_TOKEN_LEN") {
        if let Ok(n) = env_len.parse::<usize>() {
            len = clamp_len(n);
        }
    }

    // CLI parsing
    // Accept forms:
    //   --len N
    //   -l N
    //   N (positional)
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                show_help = true;
            }
            "--len" | "-l" => {
                if i + 1 < args.len() {
                    if let Ok(n) = args[i + 1].parse::<usize>() {
                        len = clamp_len(n);
                    } else {
                        eprintln!("Invalid value for --len: {}", args[i + 1]);
                        process::exit(1);
                    }
                    i += 1; // consume the value
                } else {
                    eprintln!("Missing value for --len");
                    process::exit(1);
                }
            }
            // If it's a bare number, treat as positional len
            s if s.chars().all(|c| c.is_ascii_digit()) => {
                if let Ok(n) = s.parse::<usize>() {
                    len = clamp_len(n);
                }
            }
            _ => {
                // ignore unknown arguments
            }
        }
        i += 1;
    }

    (len, show_help)
}

fn clamp_len(n: usize) -> usize {
    if n == 0 || n > 32 { 32 } else { n }
}

fn print_help() {
    eprintln!(
        "\
Generate WeChat Kf Token and EncodingAESKey and print as .env lines.

Usage:
  cargo run --example gen_keys
  cargo run --example gen_keys -- --len 16
  cargo run --example gen_keys -- 24

Environment:
  WXKF_TOKEN_LEN   Optional. Override token length (1..=32). Default: 32.

Output (stdout):
  WXKF_TOKEN=<alphanumeric up to 32 chars>
  WXKF_ENCODING_AES_KEY=<43-char alphanumeric, Base64 without '='>

Notes:
- Token: used for SHA1 signature verification; ASCII alphanumeric, length <= 32.
- EncodingAESKey: 43 chars, only letters/digits. This is Base64 (no '=' padding) for a 32-byte AES-256 key.
- You must set the same Token and EncodingAESKey in the WeChat Kf admin console.
"
    );
}
