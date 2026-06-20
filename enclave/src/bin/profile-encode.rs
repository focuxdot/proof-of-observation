// SPDX-License-Identifier: MIT OR Apache-2.0

use attest::tls_profile::{canonical_encode, TlsProfile};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::env;

fn main() {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("用法: profile-encode <spec.json>  → 输出 {{spec_id, canonical_b64}}");
        std::process::exit(2);
    });
    let raw = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("读 spec 失败 {path}: {e}");
        std::process::exit(1);
    });
    let spec: TlsProfile = serde_json::from_slice(&raw).unwrap_or_else(|e| {
        eprintln!("解析 TlsProfile JSON 失败: {e}");
        std::process::exit(1);
    });
    let out = serde_json::json!({
        "spec_id": spec.spec_id,
        "label": spec.label,
        "canonical_b64": B64.encode(canonical_encode(&spec)),
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
