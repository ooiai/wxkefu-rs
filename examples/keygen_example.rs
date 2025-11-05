/*!
Minimal example: generate and verify Token and EncodingAESKey without extra dependencies.

Run:
  cargo run --example keygen_example
*/

use wxkefu_rs::keygen::{generate_encoding_aes_key, generate_token, verify_encoding_aes_key};

fn main() {
    // 生成 Token（32 字符，字母数字）
    let token = generate_token(32);
    println!("Token: {}", token);

    // 生成 EncodingAESKey（43 字符，字母数字）
    let encoding_aes_key = generate_encoding_aes_key();
    println!("EncodingAESKey: {}", encoding_aes_key);

    // 校验 EncodingAESKey 是否合法（43 长度，补 '=' 后可解码为 32 字节）
    let ok = verify_encoding_aes_key(&encoding_aes_key);
    println!("EncodingAESKey valid? {}", ok);
}
