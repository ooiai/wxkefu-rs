/*!
Minimal example: generate and verify Token and EncodingAESKey without extra dependencies.

Run:
  cargo run --example keygen_example
*/

use wxkefu_rs::keygen::{generate_encoding_aes_key, generate_token, verify_encoding_aes_key};

fn main() {
    // Generate an alphanumeric Token (default 32 characters)
    let token = generate_token(32);

    // Generate a 43-character EncodingAESKey (Base64 without '=' padding)
    let encoding_aes_key = generate_encoding_aes_key();

    // Verify that EncodingAESKey decodes to 32 bytes when appending '='
    let ok = verify_encoding_aes_key(&encoding_aes_key);

    println!("TOKEN={}", token);
    println!("ENCODING_AES_KEY={}", encoding_aes_key);
    println!("VERIFY={}", if ok { "OK" } else { "INVALID" });

    // Notes:
    // - Keep TOKEN and ENCODING_AES_KEY secret; do not commit or log them in production.
    // - In your callback server:
    //     * Use TOKEN for SHA1 signature verification.
    //     * Use ENCODING_AES_KEY (append '=' then Base64 decode) to derive the 32-byte AES key
    //       (IV is the first 16 bytes of the decoded key) for decrypting messages.
}
