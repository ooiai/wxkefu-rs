//! Manual decrypt test - directly decrypt the captured ciphertext

use std::env;

fn main() {
    // Read the encrypt value from file
    let encrypt = std::fs::read_to_string("/tmp/wxkf_encrypt.txt")
        .expect("Failed to read /tmp/wxkf_encrypt.txt");

    println!("=== MANUAL DECRYPT TEST ===\n");
    println!("Encrypt length: {}", encrypt.len());
    println!("Encrypt (first 80): {}", &encrypt[..80.min(encrypt.len())]);
    println!();

    // EncodingAESKey from env
    let key_str = env::var("WXKF_ENCODING_AES_KEY").expect("WXKF_ENCODING_AES_KEY not set");
    let token = env::var("WXKF_TOKEN").expect("WXKF_TOKEN not set");

    println!("EncodingAESKey: {}", key_str);
    println!("Token: {}", token);
    println!();

    // Use the library's decrypt function
    println!("Testing with wxkefu_rs::callback::decrypt_b64_message...");
    match wxkefu_rs::callback::decrypt_b64_message(&key_str, encrypt.trim(), None) {
        Ok(plaintext) => {
            println!("✓ Decryption SUCCESS!");
            println!();
            println!("=== DECRYPTED MESSAGE ===");
            println!("{}", plaintext);
            println!();

            // Try parsing as Kf message
            match wxkefu_rs::callback::parse_kf_plaintext(&plaintext) {
                Ok(msg) => {
                    println!("=== PARSED MESSAGE ===");
                    println!("{:#?}", msg);
                }
                Err(e) => {
                    println!("Could not parse as Kf message: {}", e);
                }
            }
        }
        Err(e) => {
            println!("✗ Decryption FAILED: {:?}", e);
            println!();
            println!("This confirms the EncodingAESKey does NOT match!");
            println!();
            println!("Possible causes:");
            println!("  1. WeChat admin console shows DIFFERENT key than .env");
            println!("  2. WeChat is using a DIFFERENT key for POST vs GET");
            println!("  3. WeChat encrypted with wrong key (their bug)");
            println!();
            println!("Action: Double-check the EncodingAESKey in WeChat console");
            println!("        It MUST exactly match: {}", key_str);
        }
    }
}
