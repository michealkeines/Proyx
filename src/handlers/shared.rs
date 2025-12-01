use std::io::{Error, ErrorKind};

use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};

use crate::connection::Connection;

pub async unsafe fn read_client_data(conn: &mut Connection, buf: &mut [u8]) -> std::io::Result<usize> {
    debug_assert!(
        conn.client_mitm_tls.is_some() || conn.client_tls.is_some() || conn.client_tcp.is_some(),
        "read_client_data: expected at least one client transport"
    );
    if let Some(ptr) = conn.client_mitm_tls {
        (*ptr).read(buf).await
    } else if let Some(ptr) = conn.client_tls {
        (*ptr).read(buf).await
    } else if let Some(ptr) = conn.client_tcp {
        (*ptr).read(buf).await
    } else {
        Err(Error::new(ErrorKind::NotConnected, "client stream missing"))
    }
}

pub async unsafe fn write_client_data(conn: &mut Connection, data: &[u8]) -> std::io::Result<()> {
    debug_assert!(
        conn.client_mitm_tls.is_some() || conn.client_tls.is_some() || conn.client_tcp.is_some(),
        "write_client_data: expected at least one client transport"
    );
    if let Some(ptr) = conn.client_mitm_tls {
        (*ptr).write_all(data).await
    } else if let Some(ptr) = conn.client_tls {
        (*ptr).write_all(data).await
    } else if let Some(ptr) = conn.client_tcp {
        (*ptr).write_all(data).await
    } else {
        Err(Error::new(ErrorKind::NotConnected, "client stream missing"))
    }
}

pub async unsafe fn read_upstream_data(
    conn: &mut Connection,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    debug_assert!(
        conn.upstream_tls.is_some() || conn.upstream_tcp.is_some(),
        "read_upstream_data: expected upstream transport"
    );
    if let Some(ptr) = conn.upstream_tls {
        (*ptr).read(buf).await
    } else if let Some(ptr) = conn.upstream_tcp {
        (*ptr).read(buf).await
    } else {
        Err(Error::new(
            ErrorKind::NotConnected,
            "upstream stream missing",
        ))
    }
}

pub async unsafe fn write_upstream_data(conn: &mut Connection, data: &[u8]) -> std::io::Result<()> {
    debug_assert!(
        conn.upstream_tls.is_some() || conn.upstream_tcp.is_some(),
        "write_upstream_data: expected upstream transport"
    );
    if let Some(ptr) = conn.upstream_tls {
        (*ptr).write_all(data).await
    } else if let Some(ptr) = conn.upstream_tcp {
        (*ptr).write_all(data).await
    } else {
        Err(Error::new(
            ErrorKind::NotConnected,
            "upstream stream missing",
        ))
    }
}

pub async unsafe fn tunnel_copy(conn: &mut Connection) -> std::io::Result<()> {
    match (
        conn.client_tls.as_mut(),
        conn.client_tcp.as_mut(),
        conn.upstream_tls.as_mut(),
        conn.upstream_tcp.as_mut(),
    ) {
        (Some(c_tls), _, Some(u_tls), _) => copy_bidirectional(&mut **c_tls, &mut **u_tls).await.map(|_| ()),
        (Some(c_tls), _, _, Some(u_tcp)) => copy_bidirectional(&mut **c_tls, &mut **u_tcp).await.map(|_| ()),
        (_, Some(c_tcp), Some(u_tls), _) => copy_bidirectional(&mut **c_tcp, &mut **u_tls).await.map(|_| ()),
        (_, Some(c_tcp), _, Some(u_tcp)) => copy_bidirectional(&mut **c_tcp, &mut **u_tcp).await.map(|_| ()),
        _ => Err(Error::new(
            ErrorKind::NotConnected,
            "missing streams for CONNECT tunnel",
        )),
    }
}

pub fn parse_connect_target(buf: &[u8], default_port: u16) -> Option<(String, u16)> {
    let line_end = twoway::find_bytes(buf, b"\r\n").unwrap_or(buf.len());
    let line = std::str::from_utf8(&buf[..line_end]).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let authority = parts.next()?;
    Some(split_host_port(authority, default_port))
}

pub fn looks_like_http1(buf: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"TRACE ",
        b"PATCH ",
        b"CONNECT ",
    ];
    METHODS.iter().any(|m| buf.starts_with(*m))
}

pub fn parse_request_line(buf: &[u8]) -> Option<(String, String)> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    if let Ok(httparse::Status::Complete(_)) = req.parse(buf) {
        if let (Some(method), Some(path)) = (req.method, req.path) {
            return Some((method.to_string(), path.to_string()));
        }
    }
    None
}

pub fn parse_host_header(buf: &[u8], default_port: u16) -> Option<(String, u16)> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    if let Ok(httparse::Status::Complete(_)) = req.parse(buf) {
        for header in req.headers {
            if header.name.eq_ignore_ascii_case("host") {
                if let Ok(value) = std::str::from_utf8(header.value) {
                    let trimmed = value.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    return Some(split_host_port(trimmed, default_port));
                }
            }
        }
    }

    None
}

pub fn split_host_port(host: &str, default_port: u16) -> (String, u16) {
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            let addr = host[1..end].to_string();
            if let Some(rest) = host.get(end + 1..) {
                if rest.starts_with(':') {
                    if let Ok(port) = rest[1..].parse() {
                        return (addr, port);
                    }
                }
            }
            return (addr, default_port);
        }
    } else if host.matches(':').count() == 1 {
        if let Some(pos) = host.rfind(':') {
            if let Ok(port) = host[pos + 1..].parse() {
                return (host[..pos].to_string(), port);
            }
        }
    }

    (host.to_string(), default_port)
}
