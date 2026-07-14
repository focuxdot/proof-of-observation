// Synchronous bridge around h2 0.4.15. The blocking TLS stream runs in the h2
// connection driver thread; short socket read timeouts surface as Pending so
// stream completion can shut the driver down without leaking a thread.
use attest::tls_profile::H2Settings;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, Uri};
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct H2ResponseSummary {
    pub status: u16,
    pub body_bytes: usize,
}

pub trait H2ResponseSink {
    fn on_head(&mut self, status: u16, headers: &[(String, String)]) -> Result<(), String>;
    fn on_chunk(&mut self, chunk: &[u8]) -> Result<(), String>;
}

struct BlockingIo<S>(S);

impl<S: Read + Unpin> AsyncRead for BlockingIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.0.read(buf.initialize_unfilled()) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl<S: Write + Unpin> AsyncWrite for BlockingIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.0.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.0.flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[allow(clippy::too_many_arguments)]
pub fn execute<S: Read + Write + Send + Unpin + 'static, T: H2ResponseSink>(
    io: S,
    fingerprint: &H2Settings,
    host: &str,
    method: &str,
    path: &str,
    ordered_headers: &[(String, String)],
    token: Option<&str>,
    body: &[u8],
    max_response_bytes: usize,
    sink: &mut T,
) -> Result<H2ResponseSummary, String> {
    if fingerprint.pseudo_header_order != [":method", ":scheme", ":authority", ":path"] {
        return Err("Grok h2 pseudo-header order must be :method,:scheme,:authority,:path".into());
    }

    let mut builder = h2::client::Builder::new();
    for &(id, value) in &fingerprint.settings {
        match id {
            2 => {
                builder.enable_push(value != 0);
            }
            4 => {
                builder.initial_window_size(value);
            }
            5 => {
                builder.max_frame_size(value);
            }
            6 => {
                builder.max_header_list_size(value);
            }
            _ => return Err(format!("unsupported Grok h2 setting id {id}")),
        }
    }
    let connection_window = 65_535u32
        .checked_add(fingerprint.window_update)
        .ok_or_else(|| "Grok h2 connection window overflow".to_string())?;
    builder.initial_connection_window_size(connection_window);

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| format!("h2 runtime: {e}"))?;
    let (mut sender, connection) = rt
        .block_on(builder.handshake(BlockingIo(io)))
        .map_err(|e| format!("h2 handshake: {e}"))?;

    let uri: Uri = format!("https://{host}{path}")
        .parse()
        .map_err(|e| format!("h2 URI: {e}"))?;
    let method: Method = method.parse().map_err(|e| format!("h2 method: {e}"))?;
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(())
        .map_err(|e| format!("h2 request: {e}"))?;
    let mut auth_seen = false;
    let mut content_length_seen = false;
    for (name, original_value) in ordered_headers {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "host"
                | "connection"
                | "transfer-encoding"
                | "te"
                | "trailer"
                | "upgrade"
                | "proxy-connection"
                | "keep-alive"
        ) {
            continue;
        }
        let value = if lower == "authorization" {
            auth_seen = true;
            match token {
                Some(token) => format!("Bearer {token}"),
                None => continue,
            }
        } else if lower == "content-length" {
            content_length_seen = true;
            body.len().to_string()
        } else {
            original_value.clone()
        };
        let header_name = HeaderName::from_bytes(lower.as_bytes())
            .map_err(|e| format!("h2 header name {lower}: {e}"))?;
        let mut header_value =
            HeaderValue::from_str(&value).map_err(|e| format!("h2 header {lower}: {e}"))?;
        if lower == "authorization" {
            header_value.set_sensitive(true);
        }
        request.headers_mut().append(header_name, header_value);
    }
    if !auth_seen {
        if let Some(token) = token {
            let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|e| format!("h2 authorization: {e}"))?;
            value.set_sensitive(true);
            request
                .headers_mut()
                .append(http::header::AUTHORIZATION, value);
        }
    }
    if !content_length_seen {
        request.headers_mut().append(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string())
                .map_err(|e| format!("h2 content-length: {e}"))?,
        );
    }

    let (response_future, mut send_stream) = sender
        .send_request(request, body.is_empty())
        .map_err(|e| format!("h2 send headers: {e}"))?;
    drop(sender);

    let driver = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(|e| format!("h2 driver runtime: {e}"))?;
        rt.block_on(connection)
            .map_err(|e| format!("h2 connection: {e}"))
    });

    let result = (|| {
        let mut offset = 0usize;
        while offset < body.len() {
            let wanted = (body.len() - offset).min(16_384);
            send_stream.reserve_capacity(wanted);
            let capacity = rt
                .block_on(poll_fn(|cx| send_stream.poll_capacity(cx)))
                .ok_or_else(|| "h2 request stream closed before body".to_string())?
                .map_err(|e| format!("h2 request capacity: {e}"))?;
            if capacity == 0 {
                continue;
            }
            let n = wanted.min(capacity);
            let end = offset + n == body.len();
            send_stream
                .send_data(Bytes::copy_from_slice(&body[offset..offset + n]), end)
                .map_err(|e| format!("h2 send body: {e}"))?;
            offset += n;
        }
        drop(send_stream);

        let response = rt
            .block_on(response_future)
            .map_err(|e| format!("h2 response: {e}"))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect::<Vec<_>>();
        sink.on_head(status, &headers)?;
        let mut recv = response.into_body();
        let mut total = 0usize;
        while let Some(chunk) = rt.block_on(recv.data()) {
            let chunk = chunk.map_err(|e| format!("h2 response body: {e}"))?;
            total = total
                .checked_add(chunk.len())
                .ok_or_else(|| "h2 response size overflow".to_string())?;
            if total > max_response_bytes {
                return Err("h2 response body exceeds limit".into());
            }
            // Apply downstream backpressure before giving the peer more receive capacity.
            sink.on_chunk(&chunk)?;
            recv.flow_control()
                .release_capacity(chunk.len())
                .map_err(|e| format!("h2 release response capacity: {e}"))?;
        }
        Ok(H2ResponseSummary {
            status,
            body_bytes: total,
        })
    })();

    drop(rt);
    match driver.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) if result.is_ok() => return Err(e),
        Err(_) if result.is_ok() => return Err("h2 connection driver panicked".into()),
        _ => {}
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::Duration;

    struct RecordingSink {
        events: Vec<String>,
        first_chunk_tx: mpsc::Sender<()>,
    }

    impl H2ResponseSink for RecordingSink {
        fn on_head(&mut self, status: u16, _headers: &[(String, String)]) -> Result<(), String> {
            self.events.push(format!("head:{status}"));
            Ok(())
        }

        fn on_chunk(&mut self, chunk: &[u8]) -> Result<(), String> {
            self.events.push(String::from_utf8(chunk.to_vec()).unwrap());
            if chunk == b"first" {
                self.first_chunk_tx.send(()).unwrap();
            }
            Ok(())
        }
    }

    fn read_frame(stream: &mut UnixStream) -> (u8, u8, Vec<u8>) {
        let mut head = [0u8; 9];
        stream.read_exact(&mut head).unwrap();
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).unwrap();
        (head[3], head[4], payload)
    }

    fn write_frame(stream: &mut UnixStream, kind: u8, flags: u8, stream_id: u32, payload: &[u8]) {
        let len = payload.len() as u32;
        let head = [
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
            kind,
            flags,
            (stream_id >> 24) as u8,
            (stream_id >> 16) as u8,
            (stream_id >> 8) as u8,
            stream_id as u8,
        ];
        stream.write_all(&head).unwrap();
        stream.write_all(payload).unwrap();
        stream.flush().unwrap();
    }

    #[test]
    fn streams_h2_data_before_end_stream() {
        let (client, mut server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (first_chunk_tx, first_chunk_rx) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let mut preface = [0u8; 24];
            server.read_exact(&mut preface).unwrap();
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            let _settings = read_frame(&mut server);
            let _window_update = read_frame(&mut server);
            write_frame(&mut server, 4, 0, 0, &[]);
            write_frame(&mut server, 4, 1, 0, &[]);
            loop {
                let (kind, flags, _) = read_frame(&mut server);
                if (kind == 1 || kind == 0) && flags & 1 != 0 {
                    break;
                }
            }
            // :status 200, END_HEADERS; DATA is deliberately split around the
            // callback acknowledgement to prove the first chunk is forwarded
            // before the upstream stream reaches END_STREAM.
            write_frame(&mut server, 1, 4, 1, &[0x88]);
            write_frame(&mut server, 0, 0, 1, b"first");
            first_chunk_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            write_frame(&mut server, 0, 1, 1, b"second");
            while server.read(&mut [0u8; 1024]).unwrap_or(0) != 0 {}
        });

        let fingerprint = H2Settings {
            settings: vec![(2, 0), (4, 2_097_152), (5, 16_384), (6, 16_384)],
            window_update: 5_177_345,
            pseudo_header_order: vec![
                ":method".into(),
                ":scheme".into(),
                ":authority".into(),
                ":path".into(),
            ],
        };
        let mut sink = RecordingSink {
            events: Vec::new(),
            first_chunk_tx,
        };
        let response = execute(
            client,
            &fingerprint,
            "api.x.ai",
            "POST",
            "/v1/responses",
            &[("content-type".into(), "application/json".into())],
            Some("test-token"),
            b"{}",
            1024,
            &mut sink,
        )
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body_bytes, 11);
        assert_eq!(sink.events, ["head:200", "first", "second"]);
        peer.join().unwrap();
    }
}
