// SPDX-License-Identifier: MIT OR Apache-2.0

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_init, nsm_process_request};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signer, SigningKey};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use vsock::{VsockAddr, VsockListener, VsockStream};

mod egress_boring;
mod egress_openssl;
use attest::tls_profile;

trait ReadWrite: Read + Write {}
impl<T: Read + Write + ?Sized> ReadWrite for T {}

fn decode_profile(head: &ReqHead) -> Option<tls_profile::TlsProfile> {
    tls_profile::decode(&B64.decode(head.tls_spec.as_deref()?).ok()?).ok()
}

const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;
const PARENT_CID: u32 = 3;
const PORT: u32 = 5005;
const DOMAIN_V2: &str = "tee-exchange-v2";

const MAX_HEAD: usize = 64 * 1024;
const MAX_RESP: usize = 64 * 1024 * 1024;
const MAX_REQ_HEAD: usize = 1024 * 1024;
const MAX_REQ_FRAME: usize = 64 * 1024 * 1024;
const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(300);
const UPSTREAM_IO_TIMEOUT: Duration = Duration::from_secs(300);
const ADMIN_TIMEOUT: Duration = Duration::from_secs(2);

const N_WORKERS: usize = 64;
const QUEUE_CAP: usize = 256;
const METRICS_PORT: u32 = 5006;

const REQ_HEAD: u8 = 0x01;
const REQ_BODY: u8 = 0x02;
const RESP_HEAD: u8 = 0x10;
const RESP_CHUNK: u8 = 0x11;
const RESP_TRAILER: u8 = 0x12;
const STATS: u8 = 0x20;
const ERR: u8 = 0x1f;

#[derive(Deserialize)]
struct Upstream {
    host: String,
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    // Ordered, case-preserving outgoing header template. When present it takes
    // precedence over `headers`: headers are emitted verbatim in this exact order
    // and case. `authorization` / `content-length` entries are empty-value
    // sentinels filled in here (token / actual body length). Loosely typed: each
    // item must be exactly [name, value], otherwise it is rejected and the build
    // falls back to the `headers` map path.
    #[serde(default, rename = "headersOrdered")]
    headers_ordered: Option<Vec<Vec<String>>>,
}

#[derive(Deserialize)]
struct ReqHead {
    nonce: String,
    egress_port: u32,
    upstream: Upstream,
    token: Option<String>,
    #[serde(default)]
    tls_seed: Option<String>,
    #[serde(default)]
    tls_spec: Option<String>,
}

fn read_frame<R: Read>(r: &mut R, max: usize) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr)?;
    let t = hdr[0];
    let n = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    if n > max {
        return Err(std::io::Error::new(ErrorKind::InvalidData, "请求帧超过上限"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok((t, buf))
}

fn write_frame<W: Write>(w: &mut W, t: u8, data: &[u8]) -> std::io::Result<()> {
    let mut hdr = [0u8; 5];
    hdr[0] = t;
    hdr[1..].copy_from_slice(&(data.len() as u32).to_be_bytes());
    w.write_all(&hdr)?;
    w.write_all(data)?;
    Ok(())
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

fn no_crlf(s: &str) -> bool {
    !s.bytes().any(|b| b == b'\r' || b == b'\n')
}

fn path_no_query(p: &str) -> &str {
    match p.find('?') {
        Some(i) => &p[..i],
        None => p,
    }
}
#[allow(clippy::too_many_arguments)]
fn build_v2_statement(
    nonce_b64: &str,
    upstream_host: &str,
    upstream_path: &str,
    http_method: &str,
    http_status: u16,
    resp_content_type: &str,
    request_body_sha256_hex: &str,
    response_body_sha256_hex: &str,
) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(DOMAIN_V2);
    out.push('\n');
    out.push_str(&format!("nonce={}\n", nonce_b64));
    out.push_str(&format!("upstream-host={}\n", upstream_host.to_lowercase()));
    out.push_str(&format!("upstream-path={}\n", path_no_query(upstream_path)));
    out.push_str(&format!("http-method={}\n", http_method.to_uppercase()));
    out.push_str(&format!("http-status={}\n", http_status));
    out.push_str(&format!("resp-content-type={}\n", resp_content_type));
    out.push_str(&format!("request-body-sha256={}\n", request_body_sha256_hex));
    out.push_str(&format!("response-body-sha256={}\n", response_body_sha256_hex));
    out.into_bytes()
}

/// Validate the caller-provided ordered header template: each item must be exactly
/// [name, value]; any malformed item yields None (caller falls back to the map path).
fn parse_headers_ordered(v: &Option<Vec<Vec<String>>>) -> Option<Vec<(String, String)>> {
    let arr = v.as_ref()?;
    let mut out = Vec::with_capacity(arr.len());
    for pair in arr {
        if pair.len() != 2 {
            return None;
        }
        out.push((pair[0].clone(), pair[1].clone()));
    }
    Some(out)
}

/// Assemble the HTTP/1.1 request head verbatim from the ordered template
/// (exact order and case, no sorting, no lowercasing). The `authorization` slot is
/// filled from the token (only if present); the `content-length` slot is filled with
/// the actual body length (both are empty-value sentinels). `transfer-encoding` is
/// stripped. Safety net: if the template omits host / content-length they are
/// appended so the request stays well-formed. `connection` is NOT hard-coded here —
/// it is carried by the template when provided.
fn build_request_head_ordered(
    norm_method: &str,
    path: &str,
    host: &str,
    ordered: &[(String, String)],
    token: Option<&str>,
    body_len: usize,
) -> String {
    let mut s = format!("{} {} HTTP/1.1\r\n", norm_method, path);
    let mut host_seen = false;
    let mut clen_seen = false;
    for (k, v) in ordered {
        if k.eq_ignore_ascii_case("authorization") {
            if let Some(t) = token {
                s.push_str(&format!("{}: Bearer {}\r\n", k, t));
            }
        } else if k.eq_ignore_ascii_case("content-length") {
            s.push_str(&format!("{}: {}\r\n", k, body_len));
            clen_seen = true;
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            // strip: a fixed-length body must not carry TE (matches the map path)
        } else {
            if k.eq_ignore_ascii_case("host") {
                host_seen = true;
            }
            s.push_str(&format!("{}: {}\r\n", k, v));
        }
    }
    if !host_seen {
        s.push_str(&format!("host: {}\r\n", host));
    }
    if !clen_seen {
        s.push_str(&format!("content-length: {}\r\n", body_len));
    }
    s.push_str("\r\n");
    s
}

struct Headers {
    status: u16,
    content_type: Option<String>,
    chunked: bool,
    content_length: Option<usize>,
    headers: BTreeMap<String, String>,
}

fn parse_headers(head: &[u8]) -> Result<Headers, String> {
    let s = String::from_utf8_lossy(head);
    let mut lines = s.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("状态行解析失败")?;
    let mut content_type = None;
    let mut chunked = false;
    let mut content_length = None;
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for line in lines {
        if let Some(idx) = line.find(':') {
            let k = line[..idx].trim().to_lowercase();
            let v = line[idx + 1..].trim().to_string();
            match k.as_str() {
                "content-type" => content_type = Some(v.clone()),
                "transfer-encoding" if v.to_lowercase().contains("chunked") => chunked = true,
                "content-length" => content_length = v.parse().ok(),
                _ => {}
            }
            match headers.get_mut(&k) {
                Some(existing) => {
                    existing.push_str(", ");
                    existing.push_str(&v);
                }
                None => {
                    headers.insert(k, v);
                }
            }
        }
    }
    Ok(Headers {
        status,
        content_type,
        chunked,
        content_length,
        headers,
    })
}

fn read_until_headers<R: Read + ?Sized>(tls: &mut R) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            let leftover = buf[pos + 4..].to_vec();
            buf.truncate(pos);
            return Ok((buf, leftover));
        }
        if buf.len() > MAX_HEAD {
            return Err("响应头超过上限".into());
        }
        match tls.read(&mut tmp) {
            Ok(0) => return Err("读响应头时连接关闭".into()),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => return Err("读响应头 EOF".into()),
            Err(e) => return Err(format!("读响应头失败: {}", e)),
        }
    }
}

fn stream_chunked<R: Read + ?Sized, F: FnMut(&[u8]) -> Result<(), String>>(
    mut buf: Vec<u8>,
    tls: &mut R,
    mut sink: F,
) -> Result<(), String> {
    let mut tmp = [0u8; 16384];
    let mut total = 0usize;
    loop {
        let p = loop {
            if let Some(p) = find(&buf, b"\r\n") {
                break p;
            }
            let n = tls.read(&mut tmp).map_err(|e| format!("读 chunk 头失败: {}", e))?;
            if n == 0 {
                return Err("chunked 提前 EOF".into());
            }
            buf.extend_from_slice(&tmp[..n]);
        };
        let size = usize::from_str_radix(
            String::from_utf8_lossy(&buf[..p])
                .trim()
                .split(';')
                .next()
                .unwrap_or("0")
                .trim(),
            16,
        )
        .map_err(|_| "chunk size 解析失败".to_string())?;
        buf.drain(..p + 2);
        if size == 0 {
            break;
        }
        total += size;
        if total > MAX_RESP {
            return Err("响应体超过上限".into());
        }
        while buf.len() < size + 2 {
            let n = tls.read(&mut tmp).map_err(|e| format!("读 chunk 体失败: {}", e))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        let take = size.min(buf.len());
        sink(&buf[..take])?;
        buf.drain(..take);
        if buf.len() >= 2 && &buf[..2] == b"\r\n" {
            buf.drain(..2);
        }
    }
    Ok(())
}

fn stream_plain<R: Read + ?Sized, F: FnMut(&[u8]) -> Result<(), String>>(
    initial: Vec<u8>,
    tls: &mut R,
    content_length: Option<usize>,
    mut sink: F,
) -> Result<(), String> {
    let mut total = 0usize;
    let mut tmp = [0u8; 16384];
    if let Some(cl) = content_length {
        if cl > MAX_RESP {
            return Err("响应体超过上限".into());
        }
        let initial_body = initial.len().min(cl);
        if initial_body > 0 {
            total += initial_body;
            sink(&initial[..initial_body])?;
        }
        while total < cl {
            let remaining = cl - total;
            let limit = remaining.min(tmp.len());
            match tls.read(&mut tmp[..limit]) {
                Ok(0) => {
                    return Err(format!(
                        "content-length 响应提前 EOF: got {} of {}",
                        total, cl
                    ));
                }
                Ok(n) => {
                    total += n;
                    sink(&tmp[..n])?;
                }
                Err(ref e)
                    if e.kind() == ErrorKind::UnexpectedEof
                        || e.kind() == ErrorKind::ConnectionAborted =>
                {
                    return Err(format!(
                        "content-length 响应提前 EOF: got {} of {}",
                        total, cl
                    ));
                }
                Err(e) => return Err(format!("读响应体失败: {}", e)),
            }
        }
        return Ok(());
    }

    if !initial.is_empty() {
        total += initial.len();
        if total > MAX_RESP {
            return Err("响应体超过上限".into());
        }
        sink(&initial)?;
    }
    loop {
        match tls.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total > MAX_RESP {
                    return Err("响应体超过上限".into());
                }
                sink(&tmp[..n])?;
            }
            Err(ref e)
                if e.kind() == ErrorKind::UnexpectedEof
                    || e.kind() == ErrorKind::ConnectionAborted =>
            {
                break
            }
            Err(e) => return Err(format!("读响应体失败: {}", e)),
        }
    }
    Ok(())
}

fn attest(fd: i32, lock: &Mutex<()>, spki: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let _g = lock.lock().unwrap_or_else(|p| p.into_inner());
    match nsm_process_request(
        fd,
        Request::Attestation {
            user_data: None,
            nonce: Some(ByteBuf::from(nonce.to_vec())),
            public_key: Some(ByteBuf::from(spki.to_vec())),
        },
    ) {
        Response::Attestation { document } => Ok(document),
        other => Err(format!("nsm: {:?}", other)),
    }
}

fn handle(
    s: &mut VsockStream,
    sk: &SigningKey,
    spki: &[u8],
    nsm_fd: i32,
    nsm_lock: &Mutex<()>,
    m: &Metrics,
) -> Result<(), String> {
    let (t1, head_buf) = read_frame(s, MAX_REQ_HEAD).map_err(|e| format!("读 HEAD 帧: {}", e))?;
    if t1 != REQ_HEAD {
        return Err(format!("期望 REQ_HEAD，收到 {:#x}", t1));
    }
    let head: ReqHead =
        serde_json::from_slice(&head_buf).map_err(|e| format!("HEAD JSON: {}", e))?;
    drop(head_buf);
    let (t2, body) = read_frame(s, MAX_REQ_FRAME).map_err(|e| format!("读 BODY 帧: {}", e))?;
    if t2 != REQ_BODY {
        return Err(format!("期望 REQ_BODY，收到 {:#x}", t2));
    }
    let req_body_hex = {
        let mut hh = Sha256::new();
        hh.update(&body);
        hex(&hh.finalize())
    };
    let nonce_bytes = B64
        .decode(head.nonce.as_bytes())
        .map_err(|e| format!("nonce base64: {}", e))?;

    if !no_crlf(&head.upstream.host)
        || !no_crlf(&head.upstream.method)
        || !no_crlf(&head.upstream.path)
    {
        return Err("upstream host/method/path 含非法 CR/LF".into());
    }
    for (k, v) in &head.upstream.headers {
        if !no_crlf(k) || !no_crlf(v) {
            return Err("请求头含非法 CR/LF".into());
        }
    }
    if let Some(tok) = &head.token {
        if !no_crlf(tok) {
            return Err("token 含非法 CR/LF".into());
        }
    }

    let profile = decode_profile(&head);
    let seed = head.tls_seed.as_deref().and_then(|s| B64.decode(s).ok());
    let sock = VsockStream::connect(&VsockAddr::new(PARENT_CID, head.egress_port))
        .map_err(|e| format!("连 vsock-proxy 失败: {}", e))?;
    sock.set_read_timeout(Some(UPSTREAM_IO_TIMEOUT)).ok();
    sock.set_write_timeout(Some(UPSTREAM_IO_TIMEOUT)).ok();
    let mut tls: Box<dyn ReadWrite> = match profile.as_ref().map(|p| p.stack) {
        Some(tls_profile::Stack::Boring) => Box::new(
            egress_boring::connect(profile.as_ref().unwrap(), sock, &head.upstream.host, seed.as_deref())
                .map_err(|e| format!("btls 出口: {}", e))?,
        ),
        Some(tls_profile::Stack::OpenSsl) => Box::new(
            egress_openssl::connect(profile.as_ref().unwrap(), sock, &head.upstream.host, seed.as_deref())
                .map_err(|e| format!("openssl 出口: {}", e))?,
        ),
        _ => {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let server_name = ServerName::try_from(head.upstream.host.clone())
                .map_err(|e| format!("SNI 非法: {:?}", e))?;
            let conn = ClientConnection::new(Arc::new(config), server_name)
                .map_err(|e| format!("TLS 初始化失败: {}", e))?;
            Box::new(rustls::StreamOwned::new(conn, sock))
        }
    };

    let norm_method = head.upstream.method.to_uppercase();
    // When an ordered header template is supplied, emit headers verbatim (exact
    // order/case). Otherwise fall back to the map path (sorted + lowercased +
    // connection: close), byte-identical to before.
    let req = match parse_headers_ordered(&head.upstream.headers_ordered) {
        Some(ordered) => build_request_head_ordered(
            &norm_method,
            &head.upstream.path,
            &head.upstream.host,
            &ordered,
            head.token.as_deref(),
            body.len(),
        ),
        None => {
            let mut req = format!("{} {} HTTP/1.1\r\n", norm_method, head.upstream.path);
            req.push_str(&format!("host: {}\r\n", head.upstream.host));
            for (k, v) in &head.upstream.headers {
                let lk = k.to_lowercase();
                if lk == "host" || lk == "authorization" || lk == "content-length" || lk == "connection"
                    || lk == "transfer-encoding" || lk == "te" || lk == "trailer" || lk == "upgrade"
                    || lk == "proxy-connection" || lk == "keep-alive"
                {
                    continue;
                }
                req.push_str(&format!("{}: {}\r\n", k, v));
            }
            if let Some(tok) = &head.token {
                req.push_str(&format!("authorization: Bearer {}\r\n", tok));
            }
            req.push_str(&format!("content-length: {}\r\n", body.len()));
            req.push_str("connection: close\r\n\r\n");
            req
        }
    };

    tls.write_all(req.as_bytes())
        .map_err(|e| format!("TLS 写请求头失败: {}", e))?;
    tls.write_all(&body)
        .map_err(|e| format!("TLS 写请求体失败: {}", e))?;
    tls.flush().ok();

    let (head_bytes, leftover) = read_until_headers(&mut *tls)?;
    let h = parse_headers(&head_bytes)?;

    write_frame(
        s,
        RESP_HEAD,
        json!({ "status": h.status, "headers": h.headers }).to_string().as_bytes(),
    )
    .map_err(|e| format!("写 RESP_HEAD: {}", e))?;

    let mut hasher = Sha256::new();
    let mut streamed = 0usize;
    {
        let mut sink = |bytes: &[u8]| -> Result<(), String> {
            hasher.update(bytes);
            streamed += bytes.len();
            write_frame(s, RESP_CHUNK, bytes).map_err(|e| format!("写 RESP_CHUNK: {}", e))
        };
        if h.chunked {
            stream_chunked(leftover, &mut *tls, &mut sink)?;
        } else {
            stream_plain(leftover, &mut *tls, h.content_length, &mut sink)?;
        }
    }
    let d_body = hasher.finalize();
    m.resp_bytes_total.fetch_add(streamed as u64, Ordering::Relaxed);

    let resp_body_hex = hex(&d_body);
    let content_type = h.content_type.as_deref().unwrap_or("");
    if !no_crlf(content_type) {
        return Err("上游 content-type 含非法 CR/LF".into());
    }
    let norm_host = head.upstream.host.to_lowercase();
    let norm_path = path_no_query(&head.upstream.path).to_string();

    let statement = build_v2_statement(
        &head.nonce,
        &norm_host,
        &norm_path,
        &norm_method,
        h.status,
        content_type,
        &req_body_hex,
        &resp_body_hex,
    );
    let sig = sk.sign(&statement).to_bytes();

    let t_nsm = Instant::now();
    let doc = attest(nsm_fd, nsm_lock, spki, &nonce_bytes)?;
    m.nsm_ns_total
        .fetch_add(t_nsm.elapsed().as_nanos() as u64, Ordering::Relaxed);
    m.nsm_calls.fetch_add(1, Ordering::Relaxed);

    let trailer = json!({
        "v": 2,
        "alg": "ed25519",
        "public_key": B64.encode(spki),
        "nonce": head.nonce,
        "upstream_host": norm_host,
        "upstream_path": norm_path,
        "http_method": norm_method,
        "http_status": h.status,
        "resp_content_type": content_type,
        "request_body_sha256": req_body_hex,
        "response_body_sha256": resp_body_hex,
        "signature": B64.encode(sig),
        "attestation": B64.encode(&doc),
    });
    write_frame(s, RESP_TRAILER, trailer.to_string().as_bytes())
        .map_err(|e| format!("写 RESP_TRAILER: {}", e))?;
    Ok(())
}

#[derive(Default)]
struct Metrics {
    accepted: AtomicU64,
    shed: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    panicked: AtomicU64,
    in_flight: AtomicUsize,
    in_flight_max: AtomicUsize,
    queue_depth: AtomicUsize,
    queue_depth_max: AtomicUsize,
    handle_ns_total: AtomicU64,
    nsm_ns_total: AtomicU64,
    nsm_calls: AtomicU64,
    resp_bytes_total: AtomicU64,
}

impl Metrics {
    fn snapshot(&self) -> String {
        let r = Ordering::Relaxed;
        let done = self.completed.load(r) + self.failed.load(r) + self.panicked.load(r);
        let round2 = |x: f64| (x * 100.0).round() / 100.0;
        let avg_handle_ms = if done > 0 {
            round2(self.handle_ns_total.load(r) as f64 / done as f64 / 1.0e6)
        } else {
            0.0
        };
        let nc = self.nsm_calls.load(r);
        let avg_nsm_ms = if nc > 0 {
            round2(self.nsm_ns_total.load(r) as f64 / nc as f64 / 1.0e6)
        } else {
            0.0
        };
        json!({
            "n_workers": N_WORKERS,
            "queue_cap": QUEUE_CAP,
            "accepted": self.accepted.load(r),
            "shed": self.shed.load(r),
            "completed": self.completed.load(r),
            "failed": self.failed.load(r),
            "panicked": self.panicked.load(r),
            "in_flight": self.in_flight.load(r),
            "in_flight_max": self.in_flight_max.load(r),
            "queue_depth": self.queue_depth.load(r),
            "queue_depth_max": self.queue_depth_max.load(r),
            "avg_handle_ms": avg_handle_ms,
            "avg_nsm_ms": avg_nsm_ms,
            "nsm_calls": nc,
            "resp_bytes_total": self.resp_bytes_total.load(r),
        })
        .to_string()
    }
}

fn bump_max(cur: usize, max: &AtomicUsize) {
    let mut m = max.load(Ordering::Relaxed);
    while cur > m {
        match max.compare_exchange_weak(m, cur, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(x) => m = x,
        }
    }
}

struct Ctx {
    sk: Arc<SigningKey>,
    spki: Arc<Vec<u8>>,
    nsm_fd: i32,
    nsm_lock: Mutex<()>,
    m: Metrics,
}

fn worker(rx: Arc<Mutex<Receiver<VsockStream>>>, ctx: Arc<Ctx>) {
    loop {
        let job = { rx.lock().unwrap().recv() };
        let mut s = match job {
            Ok(s) => s,
            Err(_) => return,
        };
        ctx.m.queue_depth.fetch_sub(1, Ordering::Relaxed);
        let now = ctx.m.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
        bump_max(now, &ctx.m.in_flight_max);
        let start = Instant::now();

        s.set_read_timeout(Some(CONTROL_IO_TIMEOUT)).ok();
        s.set_write_timeout(Some(CONTROL_IO_TIMEOUT)).ok();
        let res = catch_unwind(AssertUnwindSafe(|| {
            handle(&mut s, &ctx.sk, &ctx.spki, ctx.nsm_fd, &ctx.nsm_lock, &ctx.m)
        }));

        ctx.m
            .handle_ns_total
            .fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        ctx.m.in_flight.fetch_sub(1, Ordering::Relaxed);
        match res {
            Ok(Ok(())) => {
                ctx.m.completed.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Err(e)) => {
                ctx.m.failed.fetch_add(1, Ordering::Relaxed);
                eprintln!("handle error: {}", e);
                let _ = write_frame(
                    &mut s,
                    ERR,
                    json!({ "code": "enclave", "message": e }).to_string().as_bytes(),
                );
            }
            Err(_) => {
                ctx.m.panicked.fetch_add(1, Ordering::Relaxed);
                eprintln!("handle panicked (caught)");
            }
        }
    }
}

fn serve_metrics(ctx: Arc<Ctx>) {
    let l = match VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, METRICS_PORT)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("metrics bind 失败: {}", e);
            return;
        }
    };
    for stream in l.incoming() {
        if let Ok(mut s) = stream {
            s.set_write_timeout(Some(ADMIN_TIMEOUT)).ok();
            let _ = write_frame(&mut s, STATS, ctx.m.snapshot().as_bytes());
        }
    }
}

fn main() {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();
    let sk = Arc::new(SigningKey::from_bytes(&seed));
    let vk = sk.verifying_key().to_bytes();
    let mut spki_v = vec![
        0x30u8, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki_v.extend_from_slice(&vk);
    let spki = Arc::new(spki_v);

    let nsm_fd = nsm_init();
    let ctx = Arc::new(Ctx {
        sk,
        spki,
        nsm_fd,
        nsm_lock: Mutex::new(()),
        m: Metrics::default(),
    });

    let (tx, rx) = sync_channel::<VsockStream>(QUEUE_CAP);
    let rx = Arc::new(Mutex::new(rx));
    let mut spawned = 0usize;
    for i in 0..N_WORKERS {
        let rx = Arc::clone(&rx);
        let ctx = Arc::clone(&ctx);
        match thread::Builder::new()
            .name(format!("worker-{}", i))
            .spawn(move || worker(rx, ctx))
        {
            Ok(_) => spawned += 1,
            Err(e) => eprintln!("起 worker {} 失败（非致命）: {}", i, e),
        }
    }

    {
        let ctx = Arc::clone(&ctx);
        if let Err(e) = thread::Builder::new()
            .name("metrics".into())
            .spawn(move || serve_metrics(ctx))
        {
            eprintln!("起 metrics 线程失败（非致命）: {}", e);
        }
    }

    let listener =
        VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, PORT)).expect("bind vsock");
    eprintln!(
        "listening on vsock :{} (workers={}/{}, queue={}), metrics :{}",
        PORT, spawned, N_WORKERS, QUEUE_CAP, METRICS_PORT
    );

    for stream in listener.incoming() {
        let s = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let q = ctx.m.queue_depth.fetch_add(1, Ordering::Relaxed) + 1;
        bump_max(q, &ctx.m.queue_depth_max);
        match tx.try_send(s) {
            Ok(()) => {
                ctx.m.accepted.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(mut s)) => {
                ctx.m.queue_depth.fetch_sub(1, Ordering::Relaxed);
                ctx.m.shed.fetch_add(1, Ordering::Relaxed);
                s.set_write_timeout(Some(ADMIN_TIMEOUT)).ok();
                let _ = write_frame(
                    &mut s,
                    ERR,
                    json!({ "code": "busy", "message": "enclave at capacity, retry" })
                        .to_string()
                        .as_bytes(),
                );
            }
            Err(TrySendError::Disconnected(_)) => {
                ctx.m.queue_depth.fetch_sub(1, Ordering::Relaxed);
                break;
            }
        }
    }
}

#[cfg(test)]
mod response_stream_tests {
    use super::stream_plain;
    use std::io::{Cursor, Error, ErrorKind, Read, Result as IoResult};

    #[test]
    fn content_length_short_read_is_rejected() {
        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut out = Vec::new();
        let err = stream_plain(b"abc".to_vec(), &mut reader, Some(5), |bytes| {
            out.extend_from_slice(bytes);
            Ok(())
        })
        .expect_err("short content-length body must fail");

        assert!(err.contains("content-length 响应提前 EOF"));
        assert_eq!(out, b"abc");
    }

    #[test]
    fn content_length_unexpected_eof_is_rejected() {
        struct OneThenUnexpectedEof {
            sent: bool,
        }

        impl Read for OneThenUnexpectedEof {
            fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
                if !self.sent {
                    self.sent = true;
                    buf[0] = b'a';
                    return Ok(1);
                }
                Err(Error::new(ErrorKind::UnexpectedEof, "truncated"))
            }
        }

        let mut reader = OneThenUnexpectedEof { sent: false };
        let mut out = Vec::new();
        let err = stream_plain(Vec::new(), &mut reader, Some(2), |bytes| {
            out.extend_from_slice(bytes);
            Ok(())
        })
        .expect_err("unexpected EOF before content-length must fail");

        assert!(err.contains("content-length 响应提前 EOF"));
        assert_eq!(out, b"a");
    }

    #[test]
    fn content_length_only_forwards_declared_initial_bytes() {
        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut out = Vec::new();
        stream_plain(b"abcdef".to_vec(), &mut reader, Some(3), |bytes| {
            out.extend_from_slice(bytes);
            Ok(())
        })
        .expect("declared content-length bytes are complete");

        assert_eq!(out, b"abc");
    }

    #[test]
    fn close_delimited_response_still_reads_to_eof() {
        let mut reader = Cursor::new(b"def".to_vec());
        let mut out = Vec::new();
        stream_plain(b"abc".to_vec(), &mut reader, None, |bytes| {
            out.extend_from_slice(bytes);
            Ok(())
        })
        .expect("close-delimited body can end at EOF");

        assert_eq!(out, b"abcdef");
    }
}

#[cfg(test)]
mod golden {
    use super::{build_v2_statement, hex};
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use serde::Deserialize;
    use sha2::{Digest, Sha256};

    #[derive(Deserialize)]
    struct ExpectedV2 {
        statement: String,
        statement_hex: String,
        request_body_sha256: String,
        response_body_sha256: String,
    }
    #[derive(Deserialize)]
    struct CaseV2 {
        name: String,
        nonce_b64: String,
        upstream_host: String,
        upstream_path: String,
        http_method: String,
        http_status: u16,
        resp_content_type: String,
        request_body_b64: String,
        response_body_b64: String,
        expected: ExpectedV2,
    }
    #[derive(Deserialize)]
    struct Fixture {
        cases_v2: Vec<CaseV2>,
    }

    #[test]
    fn rust_v2_statement_matches_frozen_vectors() {
        let fx: Fixture =
            serde_json::from_str(include_str!("../signing-vectors.json")).expect("parse fixture");
        assert!(!fx.cases_v2.is_empty(), "cases_v2 为空");
        for c in &fx.cases_v2 {
            let req_body = B64.decode(c.request_body_b64.as_bytes()).expect("req b64");
            let resp_body = B64.decode(c.response_body_b64.as_bytes()).expect("resp b64");
            let req_hex = hex(&Sha256::digest(&req_body));
            let resp_hex = hex(&Sha256::digest(&resp_body));
            assert_eq!(req_hex, c.expected.request_body_sha256, "req hash [{}]", c.name);
            assert_eq!(resp_hex, c.expected.response_body_sha256, "resp hash [{}]", c.name);

            let stmt = build_v2_statement(
                &c.nonce_b64,
                &c.upstream_host,
                &c.upstream_path,
                &c.http_method,
                c.http_status,
                &c.resp_content_type,
                &req_hex,
                &resp_hex,
            );
            assert_eq!(
                String::from_utf8(stmt.clone()).unwrap(),
                c.expected.statement,
                "v2 statement [{}]",
                c.name
            );
            assert_eq!(hex(&stmt), c.expected.statement_hex, "v2 statement hex [{}]", c.name);
        }
    }
}

// Ordered outgoing headers: emitted verbatim in the given order and case.
#[cfg(test)]
mod ordered_headers {
    use super::{build_request_head_ordered, parse_headers_ordered};

    fn s(x: &str) -> String {
        x.to_string()
    }

    #[test]
    fn ordered_emit_preserves_order_case_and_fills_sentinels() {
        let ordered = vec![
            (s("Accept"), s("application/json")),
            (s("Authorization"), s("")), // empty sentinel -> filled from token
            (s("User-Agent"), s("example-client/1.0")),
            (s("Connection"), s("keep-alive")),
            (s("Host"), s("api.example.com")),
            (s("Content-Length"), s("")), // empty sentinel -> filled with body_len
        ];
        let text = build_request_head_ordered("POST", "/v1/messages?beta=true", "fallback", &ordered, Some("tok123"), 2);
        let head = text.split("\r\n\r\n").next().unwrap();
        let lines: Vec<&str> = head.split("\r\n").collect();
        assert_eq!(lines[0], "POST /v1/messages?beta=true HTTP/1.1");
        assert_eq!(
            lines[1..].to_vec(),
            vec![
                "Accept: application/json",
                "Authorization: Bearer tok123",
                "User-Agent: example-client/1.0",
                "Connection: keep-alive", // not connection: close
                "Host: api.example.com",
                "Content-Length: 2",
            ]
        );
        assert!(text.ends_with("\r\n\r\n")); // head only; body written by caller
        assert_eq!(text.matches("Content-Length").count(), 1);
    }

    #[test]
    fn ordered_emit_strips_te_and_backfills_missing_host_and_clen() {
        let ordered = vec![
            (s("Accept"), s("application/json")),
            (s("transfer-encoding"), s("chunked")), // stripped
        ];
        let text = build_request_head_ordered("POST", "/x", "host.example", &ordered, None, 3);
        assert!(!text.to_lowercase().contains("transfer-encoding"));
        assert!(text.contains("host: host.example\r\n")); // backfilled
        assert!(text.contains("content-length: 3\r\n")); // backfilled
        assert!(!text.to_lowercase().contains("authorization")); // no token -> omitted
    }

    #[test]
    fn parse_headers_ordered_preserves_order() {
        let v = Some(vec![
            vec![s("B-Header"), s("1")],
            vec![s("a-header"), s("2")],
        ]);
        assert_eq!(
            parse_headers_ordered(&v).unwrap(),
            vec![(s("B-Header"), s("1")), (s("a-header"), s("2"))]
        );
    }

    #[test]
    fn parse_headers_ordered_rejects_malformed_and_missing() {
        assert!(parse_headers_ordered(&None).is_none());
        assert!(parse_headers_ordered(&Some(vec![vec![s("only-one")]])).is_none());
        assert!(parse_headers_ordered(&Some(vec![vec![s("a"), s("b"), s("c")]])).is_none());
    }
}
