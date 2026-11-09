//! Shared hand-rolled HTTP/1.1 plumbing for the std-`TcpListener` reverse proxies (the
//! `kriya-llm-proxy` local-inference lane and the `kriya-gateway egress --llm-listen` governed
//! LLM lane). One parser, one forwarder: no async runtime, no HTTP-server crate — the inbound side
//! is std only, the outbound side is the same synchronous `ureq` client the crate already uses.
//!
//! Scope is deliberately small: one request per connection (`Connection: close`), a
//! `Content-Length` or `chunked` request body under a bounded cap, and response writers for either
//! a chunked relay or a fully-buffered `Content-Length` body.

use std::io::{BufRead, Write};

/// A generous but bounded request/response body cap (prompts, embedding batches, buffered model
/// replies — never a model weight file).
pub(crate) const MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Hop-by-hop / framing headers never forwarded verbatim in either direction: the proxy re-frames
/// every body itself.
const HOP_HEADERS: &[&str] = &["host", "content-length", "transfer-encoding", "connection"];

pub(crate) struct ParsedRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

/// Read one HTTP/1.1 request from `reader`. `Ok(None)` means the client closed the connection
/// before sending anything (a normal end-of-connection, not an error — these proxies are one-
/// request-per-connection, so every keep-alive-less client hits this on its next reconnect).
pub(crate) fn read_request(reader: &mut impl BufRead) -> std::io::Result<Option<ParsedRequest>> {
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(None);
    }
    let trimmed = request_line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.splitn(3, ' ');
    let (Some(method), Some(path), Some(_version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Ok(None);
    };
    let method = method.to_string();
    let path = path.to_string();

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok());
    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });

    let body = if chunked {
        read_chunked_body(reader)?
    } else if let Some(len) = content_length {
        if len > MAX_BODY_BYTES {
            return Err(too_large_error());
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        buf
    } else {
        Vec::new()
    };

    Ok(Some(ParsedRequest {
        method,
        path,
        headers,
        body,
    }))
}

pub(crate) fn too_large_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "request body exceeds the size cap",
    )
}

pub(crate) fn read_chunked_body(reader: &mut impl BufRead) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut size_line = String::new();
        if reader.read_line(&mut size_line)? == 0 {
            break;
        }
        let size_str = size_line.trim().split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed chunk size")
        })?;
        if size == 0 {
            // Consume trailing header lines up to the final blank line.
            loop {
                let mut trailer = String::new();
                if reader.read_line(&mut trailer)? == 0 || trailer.trim().is_empty() {
                    break;
                }
            }
            break;
        }
        if out.len() + size > MAX_BODY_BYTES {
            return Err(too_large_error());
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk)?;
        out.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?; // the chunk's trailing CRLF
    }
    Ok(out)
}

/// Forward `method url` upstream with the client's headers (minus hop-by-hop framing headers and
/// any header named in `extra_skip`, compared case-insensitively) and `body`.
///
/// `ureq::Error::Status` carries a full `Response` (callers relay the real upstream response
/// instead of masking it as a generic 502) — same intentional-large-Err shape
/// `audit::Signer::record_persisted` already accepts for the same reason.
#[allow(clippy::result_large_err)]
pub(crate) fn forward(
    agent: &ureq::Agent,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    extra_skip: &[&str],
) -> Result<ureq::Response, ureq::Error> {
    let mut r = agent.request(method, url);
    for (k, v) in headers {
        let kl = k.to_ascii_lowercase();
        if HOP_HEADERS.contains(&kl.as_str()) || extra_skip.contains(&kl.as_str()) {
            continue;
        }
        r = r.set(k, v);
    }
    if body.is_empty() {
        r.call()
    } else {
        r.send_bytes(body)
    }
}

/// The upstream response's headers minus the framing ones this proxy re-writes itself.
pub(crate) fn collect_headers(resp: &ureq::Response) -> Vec<(String, String)> {
    resp.headers_names()
        .into_iter()
        .filter(|n| {
            let nl = n.to_ascii_lowercase();
            !matches!(
                nl.as_str(),
                "content-length" | "transfer-encoding" | "connection"
            )
        })
        .filter_map(|n| resp.header(&n).map(|v| (n.clone(), v.to_string())))
        .collect()
}

/// Write a response head for a body that follows as HTTP chunked framing.
#[cfg_attr(not(feature = "llm-proxy"), allow(dead_code))]
pub(crate) fn write_response_head(
    writer: &mut impl Write,
    status: u16,
    headers: &[(String, String)],
) -> std::io::Result<()> {
    write!(writer, "HTTP/1.1 {status} {}\r\n", status_text(status))?;
    for (k, v) in headers {
        write!(writer, "{k}: {v}\r\n")?;
    }
    write!(writer, "Transfer-Encoding: chunked\r\n")?;
    write!(writer, "Connection: close\r\n")?;
    write!(writer, "\r\n")?;
    Ok(())
}

/// Write a complete response with a fully-buffered body and a correct `Content-Length`. Any
/// `content-length` / `transfer-encoding` / `connection` entry in `headers` is dropped (the body
/// here is authoritative).
#[cfg_attr(not(all(feature = "contain", feature = "mcp-http")), allow(dead_code))]
pub(crate) fn write_full_response(
    writer: &mut impl Write,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> std::io::Result<()> {
    write!(writer, "HTTP/1.1 {status} {}\r\n", status_text(status))?;
    for (k, v) in headers {
        let kl = k.to_ascii_lowercase();
        if matches!(
            kl.as_str(),
            "content-length" | "transfer-encoding" | "connection"
        ) {
            continue;
        }
        write!(writer, "{k}: {v}\r\n")?;
    }
    write!(writer, "Content-Length: {}\r\n", body.len())?;
    write!(writer, "Connection: close\r\n\r\n")?;
    writer.write_all(body)?;
    writer.flush()
}

pub(crate) fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}
