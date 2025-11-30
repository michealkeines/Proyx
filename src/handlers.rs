use std::io::{Error, ErrorKind};
use std::sync::Arc;

use httparse::{Request, Response, Status};
use rustls_pki_types::ServerName;
use hpack::Decoder;

use crate::{
    connection::{Connection, ReadEnum, WriteEnum},
    fsm::NextStep,
    states::*,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::TcpStream,
};

use crate::CA::helpers::build_fake_cert_for_domain;
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    client::TlsStream,
    rustls::{
        ClientConfig, RootCertStore, ServerConfig, client,
        pki_types::{CertificateDer, PrivateKeyDer, TrustAnchor, pem::PemObject},
        server,
    },
};

const H2_DEFAULT_MAX_FRAME_SIZE: usize = 16_384;

pub async unsafe fn transport_handler(conn: &mut Connection, s: TransportState) -> NextStep {
    println!("[TRANSPORT] {:?}", s);

    match s {
        TransportState::Conn(state) => match state {
            TransportConnState::AcceptClientConnection => {
                debug_assert!(
                    conn.client_tcp.is_some(),
                    "Transport handler expected client TCP socket"
                );

                println!(
                    "[TRANSPORT] AcceptClientConnection, readable={:?}",
                    conn.readable
                );

                if conn.client_tcp.is_some() {
                    conn.readable = Some(ReadEnum::Tcp(conn.client_tcp.unwrap()));
                    println!(" → Waiting for first client read");
                    return NextStep::WaitRead(ProxyState::Detect(DetectState::Bootstrap(
                        DetectBootstrapState::DetectProtocolBegin,
                    )));
                }

                return NextStep::Continue(ProxyState::Detect(DetectState::Bootstrap(
                    DetectBootstrapState::DetectProtocolBegin,
                )));
            }

            TransportConnState::ClientTcpHandshake => {
                println!("[TRANSPORT] Skipping TCP handshake");
                return NextStep::Continue(ProxyState::Transport(TransportState::Conn(
                    TransportConnState::ClientTcpEstablished,
                )));
            }

            TransportConnState::ClientTcpEstablished => {
                println!("[TRANSPORT] Client established –> Detect");
                return NextStep::Continue(ProxyState::Detect(DetectState::Bootstrap(
                    DetectBootstrapState::DetectProtocolBegin,
                )));
            }
        },

        _ => {
            println!("[TRANSPORT] Unhandled state");
            return NextStep::Close;
        }
    }
}

// ===============================================================
// 2. DETECT HANDLER (TLS / HTTP / CONNECT)
// ===============================================================

pub async unsafe fn detect_handler(conn: &mut Connection, s: DetectState) -> NextStep {
    println!("[DETECT] {:?}", s);

    match s {
        DetectState::Bootstrap(_) => {
            debug_assert!(
                conn.client_tcp.is_some(),
                "Detect handler requires client TCP stream to peek"
            );
            let tcp = conn.client_tcp.unwrap();

            let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);
            let n = match (*tcp).peek(buf).await {
                Ok(n) if n > 0 => {
                    conn.in_len = n;
                    println!("[DETECT] Peeked {} bytes", n);
                    n
                }
                _ => return NextStep::Close,
            };

            let slice = &buf[..n];

            // CONNECT tunneling → HTTPS proxy mode
            if slice.starts_with(b"CONNECT ") {
                println!("[DETECT] CONNECT request detected");

                return NextStep::Continue(ProxyState::H1(H1State::Connect(
                    H1ConnectState::ConnectTunnelEstablished,
                )));
            }

            // TLS ClientHello detection
            if slice.len() > 5 && slice[0] == 0x16 && slice[1] == 0x03 {
                println!("[DETECT] TLS ClientHello detected");

                return NextStep::Continue(ProxyState::Tls(TlsState::Handshake(
                    TlsHandshakeState::HandshakeBegin,
                )));
            }

            // HTTP/1 (plain)
            if looks_like_http1(slice) {
                println!("[DETECT] HTTP/1.x detected");
                return NextStep::Continue(ProxyState::H1(H1State::Request(
                    H1RequestParseState::RecvHeaders,
                )));
            }

            println!("[DETECT] Unknown protocol – closing");
            NextStep::Close
        }

        _ => NextStep::Close,
    }
}

// ===============================================================
// 3. TLS HANDLER – MITM TLS
// ===============================================================

pub async unsafe fn tls_handler(conn: &mut Connection, s: TlsState) -> NextStep {
    println!("[TLS] {:?}", s);

    match s {
        // -----------------------------------------------------------
        // Step 1: Start handshake – build fake cert from SNI
        // -----------------------------------------------------------
        TlsState::Handshake(TlsHandshakeState::HandshakeBegin) => {
            println!("[TLS] HandshakeBegin → MITM certificate generation");

            // Drop any bytes that were only peeked during detection.
            conn.in_len = 0;

            debug_assert!(
                conn.client_tcp.is_some(),
                "TLS handshake begin requires client TCP stream"
            );

            // --- Extract SNI from ClientHello ---
            let client_hello = conn.in_buf.as_mut();
            let sni = "localhost".to_string();

            println!("[TLS] Extracted SNI = {}", sni);

            // --- Generate fake cert signed by CA ---
            let (leaf_cert, leaf_key) = build_fake_cert_for_domain(&sni);

            // --- Install into rustls server config ---
            let mut server_cfg = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![leaf_cert], leaf_key)
                .unwrap();
            server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let mut acceptor = Box::into_raw(Box::new(TlsAcceptor::from(Arc::new(server_cfg))));
            conn.scratch = acceptor as u64;

            return NextStep::Continue(ProxyState::Tls(TlsState::Handshake(
                TlsHandshakeState::HandshakeRead,
            )));
        }

        // -----------------------------------------------------------
        // Step 2: Accept TLS from client
        // -----------------------------------------------------------
        TlsState::Handshake(TlsHandshakeState::HandshakeRead) => {
            println!("[TLS] Accepting TLS handshake");

            debug_assert!(
                conn.client_tcp.is_some(),
                "TLS handshake read requires client TCP stream"
            );

            println!("[TLS] Accepting TLS handshake");

            // 1. Recover ownership of TcpStream from raw pointer
            let tcp_box: Box<TcpStream> = Box::from_raw(conn.client_tcp.unwrap() as *mut TcpStream);

            // 2. Get acceptor reference
            let mut acceptor: &mut TlsAcceptor = &mut *(conn.scratch as *mut TlsAcceptor);

            // 3. Move TcpStream into accept()  (NO &mut allowed)
            match acceptor.accept(*tcp_box).await {
                Ok(tls_stream) => {
                    // 4. tls_stream is TlsStream<TcpStream>
                    conn.client_tls = Some(Box::into_raw(Box::new(tls_stream)));
                    conn.client_tcp = None; // no longer valid
                }
                Err(e) => {
                    println!("[TLS] Handshake error: {}", e);
                    return NextStep::Close;
                }
            }

            return NextStep::Continue(ProxyState::Tls(TlsState::Handshake(
                TlsHandshakeState::HandshakeComplete,
            )));
        }

        // -----------------------------------------------------------
        // Step 3: Client TLS handshake completed
        // -----------------------------------------------------------
        TlsState::Handshake(TlsHandshakeState::HandshakeComplete) => {
            println!("[TLS] Client TLS Handshake Complete");
            conn.in_len = 0;

            if let Some(ptr) = conn.client_tls {
                let tls_stream = &*ptr;
                let (_, server_conn) = tls_stream.get_ref();
                if let Some(proto) = server_conn.alpn_protocol() {
                    conn.negotiated_alpn = Some(String::from_utf8_lossy(proto).to_string());
                }
                conn.readable = Some(ReadEnum::SeverTls(ptr));
                conn.writable = Some(WriteEnum::SeverTls(ptr));
            }

            unsafe {
                // Only prime target from SNI for non-H2 sessions; H2 will derive target from pseudo-headers.
                if conn.negotiated_alpn.as_deref() != Some("h2") {
                    conn.fill_target_from_tls_sni(443);
                } else {
                    conn.target_addr = None;
                }
            }

            if let Some(alpn) = &conn.negotiated_alpn {
                if alpn == "h2" {
                    return NextStep::Continue(ProxyState::H2(H2State::Bootstrap(
                        H2ConnBootstrapState::ClientPreface,
                    )));
                }
            }

            return NextStep::Continue(ProxyState::H1(H1State::Request(
                H1RequestParseState::RecvHeaders,
            )));
        }

        _ => {
            println!("[TLS] Unhandled state");
            return NextStep::Close;
        }
    }
}

// pub async unsafe fn tls_handler(conn: &mut Connection, s: TlsState) -> NextStep {
//     println!("[TLS] {:?}", s);

//     match s {

//         // -----------------------------------------------------------
//         // Step 1: Start handshake – build fake cert
//         // -----------------------------------------------------------
//         TlsState::Handshake(TlsHandshakeState::HandshakeBegin) => {
//             println!("[TLS] HandshakeBegin: generating fake certificate");

//             let mut roots = RootCertStore::empty();
//             let der_bytes = std::fs::read("CA/root.der").unwrap();
//             roots.add(CertificateDer::from(der_bytes)).unwrap();
//             let cert = generate_simple_self_signed(vec!["example.com".into()]).unwrap();
//             let cert_der = cert.cert.der();
//             let key_der = cert.cert.pem();

//             let server_config = ServerConfig::builder()
//                 .with_no_client_auth()
//                 .with_single_cert(
//                     vec![cert_der.clone()],
//                     PrivateKeyDer::from_pem_slice(key_der[..].as_bytes()).unwrap()
//                 ).unwrap();
//             // store acceptor in conn.scratch (via pointer)
//             let mut acceptor =
//                 Box::into_raw(Box::new(TlsAcceptor::from(Arc::new(server_config))));
//             conn.scratch = acceptor as u64;

//             return NextStep::Continue(ProxyState::Tls(
//                 TlsState::Handshake(TlsHandshakeState::HandshakeRead)
//             ));
//         }

//         // -----------------------------------------------------------
//         // Step 2: Accept TLS from client
//         // -----------------------------------------------------------
//         TlsState::Handshake(TlsHandshakeState::HandshakeRead) => {
//             println!("[TLS] Accepting TLS handshake");

//             let tcp = tcp_mut(conn.client_tcp).unwrap();
//             let mut acceptor: &TlsAcceptor = &*(conn.scratch as *mut TlsAcceptor);

//             match acceptor.accept(tcp).await {
//                 Ok(tls) => {
//                     conn.client_tcp = Some(
//                         Box::into_raw(Box::new(tls)) as *mut _
//                     );
//                 }
//                 Err(e) => {
//                     println!("[TLS] Handshake error: {}", e);
//                     return NextStep::Close;
//                 }
//             }

//             return NextStep::Continue(ProxyState::Tls(
//                 TlsState::Handshake(TlsHandshakeState::HandshakeComplete)
//             ));
//         }

//         // -----------------------------------------------------------
//         // Step 3: Handshake completed
//         // -----------------------------------------------------------

// ===============================================================
// 4. H1 HANDLER – HTTP/1.1 and CONNECT
// ===============================================================

pub async unsafe fn h1_handler(conn: &mut Connection, s: H1State) -> NextStep {
    println!("[H1] {:?}", s);

    match s {
        // -----------------------------------------------------------
        // CONNECT tunnel establishment
        // -----------------------------------------------------------
        H1State::Connect(H1ConnectState::ConnectTunnelEstablished) => {
            println!("[H1] CONNECT: parsing target and dialing upstream");

            let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);
            let n = match read_client_data(conn, buf).await {
                Ok(n) if n > 0 => {
                    conn.in_len = n;
                    n
                }
                _ => return NextStep::Close,
            };

            let target = match parse_connect_target(&buf[..n], 443) {
                Some(t) => t,
                None => {
                    println!("[H1] Invalid CONNECT request line");
                    return NextStep::Close;
                }
            };

            conn.set_target(target.0, target.1);
            conn.upstream_tls_required = false;
            conn.connect_response_sent = false;
            conn.next_state_after_upstream = Some(ProxyState::H1(H1State::Connect(
                H1ConnectState::ConnectTunnelTransfer,
            )));

            if try_reuse_upstream(conn) {
                if let Some(next) = conn.next_state_after_upstream.take() {
                    println!("[H1] CONNECT reusing pooled upstream connection");
                    return NextStep::Continue(next);
                }
            }

            return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                UpstreamDnsState::ResolveStart,
            )));
        }

        H1State::Connect(H1ConnectState::ConnectTunnelTransfer) => {
            println!(
                "[H1] CONNECT transfer start: upstream_tcp={} upstream_tls={} connect_resp_sent={}",
                conn.upstream_tcp.is_some(),
                conn.upstream_tls.is_some(),
                conn.connect_response_sent
            );
            if conn.upstream_tcp.is_none() && conn.upstream_tls.is_none() {
                println!("[H1] CONNECT tunnel waiting for upstream socket");
                return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                    UpstreamDnsState::ResolveStart,
                )));
            }

            if !conn.connect_response_sent {
                println!("[H1] CONNECT sending 200 response to client");
                let _ = write_client_data(
                    conn,
                    b"HTTP/1.1 200 Connection Established\r\n\r\n",
                )
                .await;
                conn.connect_response_sent = true;
            }

            println!("[H1] CONNECT entering bidirectional tunnel");
            let tunnel_res = tunnel_copy(conn).await;
            if let Err(e) = tunnel_res {
                println!("[H1] CONNECT tunnel error: {}", e);
            } else {
                println!("[H1] CONNECT tunnel completed cleanly");
            }
            return NextStep::Close;
        }

        // -----------------------------------------------------------
        // Begin reading request headers (TLS or plaintext)
        // -----------------------------------------------------------
        H1State::Request(H1RequestParseState::RecvHeaders) => {
            println!("[H1] RecvHeaders");

            let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);

            loop {
                if let Some(pos) = twoway::find_bytes(&buf[..conn.in_len], b"\r\n\r\n") {
                    let header_len = pos + 4;
                    println!("[H1] Headers complete at {}", header_len);

                    match prepare_h1_request(conn, &buf[..header_len]) {
                        Ok(()) => {}
                        Err(e) => {
                            println!("[H1] Request parse error: {}", e);
                            return NextStep::Close;
                        }
                    }

                    // Move any buffered body bytes to the front of the buffer.
                    if conn.in_len > header_len {
                        let body_bytes = conn.in_len - header_len;
                        buf.copy_within(header_len..header_len + body_bytes, 0);
                        conn.in_len = body_bytes;
                    } else {
                        conn.in_len = 0;
                    }

                    // Expect/continue handling
                    if conn.client_h1_state.expect_continue {
                        return NextStep::Continue(ProxyState::H1(H1State::Continue(
                            H1ContinueState::SendContinue,
                        )));
                    }

                    if try_reuse_upstream(conn) {
                        if let Some(next) = conn.next_state_after_upstream.take() {
                            println!("[H1] Reusing pooled upstream connection");
                            return NextStep::Continue(next);
                        }
                    }

                    return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                        UpstreamDnsState::ResolveStart,
                    )));
                }

                if conn.in_len >= conn.in_cap {
                    println!("[H1] Request headers exceeded buffer");
                    return NextStep::Close;
                }

                match read_client_data(conn, &mut buf[conn.in_len..]).await {
                    Ok(n) if n > 0 => conn.in_len += n,
                    _ => return NextStep::Close,
                }

                println!("[H1] RecvHeaders read more, total={}", conn.in_len);
            }
        }

        // -----------------------------------------------------------
        // 100-continue helper
        // -----------------------------------------------------------
        H1State::Continue(H1ContinueState::SendContinue) => {
            println!("[H1] Sending 100-continue");
            conn.client_h1_state.expect_continue = false;
            if let Err(e) = write_client_data(conn, b"HTTP/1.1 100 Continue\r\n\r\n").await {
                println!("[H1] Failed to send 100-continue: {}", e);
                return NextStep::Close;
            }
            if try_reuse_upstream(conn) {
                if let Some(next) = conn.next_state_after_upstream.take() {
                    println!("[H1] Reusing pooled upstream connection after 100-continue");
                    return NextStep::Continue(next);
                }
            }
            return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                UpstreamDnsState::ResolveStart,
            )));
        }

        //--------------------------------------------------------------
        // FORWARD REQUEST HEADERS (client → upstream)
        //--------------------------------------------------------------
        H1State::Forward(H1ForwardState::ForwardRequestHeaders) => {
            println!("[H1] ForwardRequestHeaders");
            let buf = std::slice::from_raw_parts_mut(conn.out_buf.as_ptr(), conn.out_cap);
            let n = conn.out_len;
            println!(
                "[H1] Req headers ready {:?} bytes, target={:?}, tls_required={}",
                n,
                conn.target(),
                conn.upstream_tls_required
            );

            debug_assert!(
                conn.upstream_tcp.is_some() || conn.upstream_tls.is_some(),
                "[H1] ForwardRequestHeaders needs upstream transport before forwarding"
            );

            if let Some(ptr) = conn.upstream_tls {
                let mut a = conn.upstream_tls.unwrap();
                println!("[H1] Forward req, writing to upstream");
                if let Err(e) = (*a).write_all(&buf[..n]).await {
                    println!("[H1] Forward req headers error: {}", e);
                    return NextStep::Close;
                }
            } else {
                let mut a = (conn.upstream_tcp.unwrap());
                println!("[H1] Forward req, writing to tcp upstream");
                if let Err(e) = (*a).write_all(&buf[..n]).await {
                    println!("[H1] Forward req headers error: {}", e);
                    return NextStep::Close;
                }
            };

            // Decide next state based on framing
            let sess = &conn.client_h1_state;
            if sess.is_chunked {
                println!("[H1] Request uses chunked transfer");
                conn.scratch = 0; // client → upstream chunked direction flag
                return NextStep::Continue(ProxyState::H1(H1State::Chunked(
                    H1ChunkedState::ChunkedSize,
                )));
            }

            if let Some(len) = sess.body_len {
                if len > 0 {
                    println!("[H1] Request body_len remaining={}", len);
                    return NextStep::Continue(ProxyState::H1(H1State::Forward(
                        H1ForwardState::ForwardRequestBody,
                    )));
                }
            }

            println!("[H1] No request body, proceed to upstream response");
            return NextStep::Continue(ProxyState::H1(H1State::Forward(
                H1ForwardState::UpstreamRecvHeaders,
            )));
        }

        //--------------------------------------------------------------
        // FORWARD REQUEST BODY (client → upstream)
        //--------------------------------------------------------------
        H1State::Forward(H1ForwardState::ForwardRequestBody) => {
            println!("[H1] ForwardRequestBody");

            let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);
            let mut remaining = conn.client_h1_state.body_len.unwrap_or(0);

            if remaining == 0 {
                return NextStep::Continue(ProxyState::H1(H1State::Forward(
                    H1ForwardState::UpstreamRecvHeaders,
                )));
            }

            // Flush any buffered body bytes first.
            if conn.in_len > 0 {
                let to_send = std::cmp::min(conn.in_len as u64, remaining) as usize;
                if let Err(e) = write_upstream_data(conn, &buf[..to_send]).await {
                    println!("[H1] Req body buffered write error: {}", e);
                    return NextStep::Close;
                }
                remaining -= to_send as u64;

                if conn.in_len > to_send {
                    // Drop extra buffered bytes (pipelined data not supported yet)
                    let extra = conn.in_len - to_send;
                    buf.copy_within(to_send..to_send + extra, 0);
                    conn.in_len = extra;
                } else {
                    conn.in_len = 0;
                }

                conn.client_h1_state.body_len = Some(remaining);

                if remaining == 0 {
                    return NextStep::Continue(ProxyState::H1(H1State::Forward(
                        H1ForwardState::UpstreamRecvHeaders,
                    )));
                }
            }

            let max_read = std::cmp::min(conn.in_cap as u64, remaining) as usize;
            match read_client_data(conn, &mut buf[..max_read]).await {
                Ok(0) => {
                    println!("[H1] Req body EOF before expected length");
                    return NextStep::Close;
                }
                Ok(n) => {
                    if let Err(e) = write_upstream_data(conn, &buf[..n]).await {
                        println!("[H1] Req body write error: {}", e);
                        return NextStep::Close;
                    }
                    remaining = remaining.saturating_sub(n as u64);
                    conn.client_h1_state.body_len = Some(remaining);
                }
                Err(e) => {
                    println!("[H1] Req body read error: {}", e);
                    return NextStep::Close;
                }
            }

            if remaining == 0 {
                return NextStep::Continue(ProxyState::H1(H1State::Forward(
                    H1ForwardState::UpstreamRecvHeaders,
                )));
            }

            NextStep::Continue(ProxyState::H1(H1State::Forward(
                H1ForwardState::ForwardRequestBody,
            )))
        }

        //--------------------------------------------------------------
        // CHUNKED TRANSFER (shared for request/response)
        //--------------------------------------------------------------
        H1State::Chunked(H1ChunkedState::ChunkedSize) => {
            let from_upstream = conn.scratch == 1;
            let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);

            if conn.in_len == 0 {
                let read_res = if from_upstream {
                    read_upstream_data(conn, buf).await
                } else {
                    read_client_data(conn, buf).await
                };
                match read_res {
                    Ok(n) if n > 0 => conn.in_len = n,
                    _ => return NextStep::Close,
                }
            }

            if let Some(pos) = twoway::find_bytes(&buf[..conn.in_len], b"\r\n") {
                let size_line = &buf[..pos];
                let size_str = match std::str::from_utf8(size_line) {
                    Ok(s) => s.trim(),
                    Err(_) => {
                        println!("[H1] Invalid chunk size line");
                        return NextStep::Close;
                    }
                };

                let chunk_size = match u64::from_str_radix(size_str, 16) {
                    Ok(v) => v,
                    Err(_) => {
                        println!("[H1] Failed to parse chunk size '{}'", size_str);
                        return NextStep::Close;
                    }
                };

                // forward the size line + CRLF as-is
                let line_end = pos + 2;
                if let Err(e) = if from_upstream {
                    write_client_data(conn, &buf[..line_end]).await
                } else {
                    write_upstream_data(conn, &buf[..line_end]).await
                } {
                    println!("[H1] Failed forwarding chunk size: {}", e);
                    return NextStep::Close;
                }

                if conn.in_len > line_end {
                    let remain = conn.in_len - line_end;
                    buf.copy_within(line_end..line_end + remain, 0);
                    conn.in_len = remain;
                } else {
                    conn.in_len = 0;
                }

                if from_upstream {
                    conn.upstream_h1_state.chunk_remaining = chunk_size;
                } else {
                    conn.client_h1_state.chunk_remaining = chunk_size;
                }
                if chunk_size == 0 {
                    return NextStep::Continue(ProxyState::H1(H1State::Chunked(
                        H1ChunkedState::ChunkedTrailer,
                    )));
                }

                return NextStep::Continue(ProxyState::H1(H1State::Chunked(
                    H1ChunkedState::ChunkedData,
                )));
            }

            if conn.in_len >= conn.in_cap {
                println!("[H1] Chunk size line too large for buffer");
                return NextStep::Close;
            }

            return NextStep::WaitRead(ProxyState::H1(H1State::Chunked(
                H1ChunkedState::ChunkedSize,
            )));
        }

        H1State::Chunked(H1ChunkedState::ChunkedData) => {
            let from_upstream = conn.scratch == 1;
            let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);
            let mut chunk_remaining = if from_upstream {
                conn.upstream_h1_state.chunk_remaining
            } else {
                conn.client_h1_state.chunk_remaining
            };

            if chunk_remaining == 0 {
                return NextStep::Continue(ProxyState::H1(H1State::Chunked(
                    H1ChunkedState::ChunkedSize,
                )));
            }

            if conn.in_len == 0 {
                let max_read = std::cmp::min(chunk_remaining as usize, conn.in_cap);
                let read_res = if from_upstream {
                    read_upstream_data(conn, &mut buf[..max_read]).await
                } else {
                    read_client_data(conn, &mut buf[..max_read]).await
                };
                match read_res {
                    Ok(n) if n > 0 => conn.in_len = n,
                    _ => return NextStep::Close,
                }
            }

            let to_send = std::cmp::min(conn.in_len as u64, chunk_remaining) as usize;
            if to_send > 0 {
                if let Err(e) = if from_upstream {
                    write_client_data(conn, &buf[..to_send]).await
                } else {
                    write_upstream_data(conn, &buf[..to_send]).await
                } {
                    println!("[H1] Chunk data forward error: {}", e);
                    return NextStep::Close;
                }

                chunk_remaining = chunk_remaining.saturating_sub(to_send as u64);

                if conn.in_len > to_send {
                    let remain = conn.in_len - to_send;
                    buf.copy_within(to_send..to_send + remain, 0);
                    conn.in_len = remain;
                } else {
                    conn.in_len = 0;
                }
            }

            if chunk_remaining > 0 {
                if from_upstream {
                    conn.upstream_h1_state.chunk_remaining = chunk_remaining;
                } else {
                    conn.client_h1_state.chunk_remaining = chunk_remaining;
                }
                return NextStep::Continue(ProxyState::H1(H1State::Chunked(
                    H1ChunkedState::ChunkedData,
                )));
            }

            // need trailing CRLF
            while conn.in_len < 2 {
                let read_res = if from_upstream {
                    read_upstream_data(conn, &mut buf[conn.in_len..2]).await
                } else {
                    read_client_data(conn, &mut buf[conn.in_len..2]).await
                };
                match read_res {
                    Ok(n) if n > 0 => conn.in_len += n,
                    _ => return NextStep::Close,
                }
            }

            if let Err(e) = if from_upstream {
                write_client_data(conn, &buf[..2]).await
            } else {
                write_upstream_data(conn, &buf[..2]).await
            } {
                println!("[H1] Chunk CRLF forward error: {}", e);
                return NextStep::Close;
            }

            if conn.in_len > 2 {
                let remain = conn.in_len - 2;
                buf.copy_within(2..2 + remain, 0);
                conn.in_len = remain;
            } else {
                conn.in_len = 0;
            }

            if from_upstream {
                conn.upstream_h1_state.chunk_remaining = 0;
            } else {
                conn.client_h1_state.chunk_remaining = 0;
            }

            return NextStep::Continue(ProxyState::H1(H1State::Chunked(
                H1ChunkedState::ChunkedSize,
            )));
        }

        H1State::Chunked(H1ChunkedState::ChunkedTrailer) => {
            let from_upstream = conn.scratch == 1;
            let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);

            loop {
                if let Some(pos) = twoway::find_bytes(&buf[..conn.in_len], b"\r\n\r\n") {
                    let trailer_len = pos + 4;
                    if let Err(e) = if from_upstream {
                        write_client_data(conn, &buf[..trailer_len]).await
                    } else {
                        write_upstream_data(conn, &buf[..trailer_len]).await
                    } {
                        println!("[H1] Trailer forward error: {}", e);
                        return NextStep::Close;
                    }

                    if conn.in_len > trailer_len {
                        let remain = conn.in_len - trailer_len;
                        buf.copy_within(trailer_len..trailer_len + remain, 0);
                        conn.in_len = remain;
                    } else {
                        conn.in_len = 0;
                    }

                if from_upstream {
                    return NextStep::Continue(ProxyState::H1(H1State::Lifecycle(
                        H1ConnLifecycleState::CheckKeepAlive,
                    )));
                }

                    return NextStep::Continue(ProxyState::H1(H1State::Forward(
                        H1ForwardState::UpstreamRecvHeaders,
                    )));
                }

                if conn.in_len >= conn.in_cap {
                    println!("[H1] Chunked trailers exceeded buffer");
                    return NextStep::Close;
                }

                let read_res = if from_upstream {
                    read_upstream_data(conn, &mut buf[conn.in_len..]).await
                } else {
                    read_client_data(conn, &mut buf[conn.in_len..]).await
                };
                match read_res {
                    Ok(n) if n > 0 => conn.in_len += n,
                    _ => return NextStep::Close,
                }
            }
        }

        //--------------------------------------------------------------
        // UPSTREAM RECV RESPONSE HEADERS
        //--------------------------------------------------------------
        H1State::Forward(H1ForwardState::UpstreamRecvHeaders) => {
            println!("[H1] UpstreamRecvHeaders");
            let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);

            loop {
                if let Some(pos) = twoway::find_bytes(&buf[..conn.in_len], b"\r\n\r\n") {
                    let header_len = pos + 4;

                    match prepare_h1_response(conn, &buf[..header_len]) {
                        Ok(()) => {}
                        Err(e) => {
                            println!("[H1] Response parse error: {}", e);
                            return NextStep::Close;
                        }
                    }

                    if conn.in_len > header_len {
                        let body_bytes = conn.in_len - header_len;
                        buf.copy_within(header_len..header_len + body_bytes, 0);
                        conn.in_len = body_bytes;
                    } else {
                        conn.in_len = 0;
                    }

                    return NextStep::Continue(ProxyState::H1(H1State::Forward(
                        H1ForwardState::SendResponseHeadersToClient,
                    )));
                }

                if conn.in_len >= conn.in_cap {
                    println!("[H1] Upstream headers exceeded buffer");
                    return NextStep::Close;
                }

                let start = conn.in_len;
                match read_upstream_data(conn, &mut buf[start..]).await {
                    Ok(n) if n > 0 => conn.in_len += n,
                    _ => return NextStep::Close,
                }
            }
        }

        //--------------------------------------------------------------
        // SEND RESPONSE HEADERS TO CLIENT
        //--------------------------------------------------------------
        H1State::Forward(H1ForwardState::SendResponseHeadersToClient) => {
            println!("[H1] SendResponseHeadersToClient");
            let buf = std::slice::from_raw_parts_mut(conn.out_buf.as_ptr(), conn.out_cap);
            let n = conn.out_len;

            debug_assert!(
                conn.client_tls.is_some() || conn.client_tcp.is_some(),
                "[H1] SendResponseHeadersToClient needs a client stream"
            );

            if let Err(e) = write_client_data(conn, &buf[..n]).await {
                println!("[H1] Response header write error: {}", e);
                return NextStep::Close;
            }

            let resp = &mut conn.upstream_h1_state;
            if resp.is_chunked {
                conn.scratch = 1; // upstream → client chunked
                return NextStep::Continue(ProxyState::H1(H1State::Chunked(
                    H1ChunkedState::ChunkedSize,
                )));
            }

            if let Some(len) = resp.body_len {
                if len > 0 {
                    return NextStep::Continue(ProxyState::H1(H1State::Forward(
                        H1ForwardState::UpstreamRecvBody,
                    )));
                }
            }

            return NextStep::Continue(ProxyState::H1(H1State::Lifecycle(
                H1ConnLifecycleState::CheckKeepAlive,
            )));
        }

        //--------------------------------------------------------------
        // READ RESPONSE BODY FROM UPSTREAM
        //--------------------------------------------------------------
        H1State::Forward(H1ForwardState::UpstreamRecvBody) => {
            println!("[H1] UpstreamRecvBody");
            let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);
            let mut remaining = conn.upstream_h1_state.body_len.unwrap_or(0);

            if remaining == 0 {
                return NextStep::Continue(ProxyState::H1(H1State::Lifecycle(
                    H1ConnLifecycleState::CheckKeepAlive,
                )));
            }

            if conn.in_len == 0 {
                let max_read = std::cmp::min(conn.in_cap as u64, remaining) as usize;
                match read_upstream_data(conn, &mut buf[..max_read]).await {
                    Ok(0) => {
                        println!(
                            "[H1] Upstream body EOF before expected length (remaining={})",
                            remaining
                        );
                        return NextStep::Close;
                    }
                    Ok(n) => {
                        conn.in_len = n;
                        println!(
                            "[H1] Upstream body read {} bytes (remaining before decrement={})",
                            n, remaining
                        );
                    }
                    Err(e) => {
                        println!("[H1] Resp body read error: {}", e);
                        return NextStep::Close;
                    }
                }
            }

            conn.upstream_h1_state.body_len = Some(remaining);
            return NextStep::Continue(ProxyState::H1(H1State::Forward(
                H1ForwardState::SendResponseBodyToClient,
            )));
        }

        //--------------------------------------------------------------
        // SEND RESPONSE BODY TO CLIENT
        //--------------------------------------------------------------
        H1State::Forward(H1ForwardState::SendResponseBodyToClient) => {
            println!("[H1] SendResponseBodyToClient");
            let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);
            let mut remaining = conn.upstream_h1_state.body_len.unwrap_or(0);

            if conn.in_len == 0 {
                return NextStep::Continue(ProxyState::H1(H1State::Forward(
                    H1ForwardState::UpstreamRecvBody,
                )));
            }

            let to_send = std::cmp::min(conn.in_len as u64, remaining) as usize;
            if let Err(e) = write_client_data(conn, &buf[..to_send]).await {
                println!("[H1] Resp body write error: {}", e);
                return NextStep::Close;
            }

            remaining = remaining.saturating_sub(to_send as u64);
            conn.upstream_h1_state.body_len = Some(remaining);

            if conn.in_len > to_send {
                let extra = conn.in_len - to_send;
                buf.copy_within(to_send..to_send + extra, 0);
                conn.in_len = extra;
            } else {
                conn.in_len = 0;
            }

            if remaining == 0 {
                return NextStep::Continue(ProxyState::H1(H1State::Lifecycle(
                    H1ConnLifecycleState::CloseConnection,
                )));
            }

            // Continue reading remaining bytes
            return NextStep::Continue(ProxyState::H1(H1State::Forward(
                H1ForwardState::UpstreamRecvBody,
            )));
        }

        //--------------------------------------------------------------
        // CONNECTION LIFECYCLE
        //--------------------------------------------------------------
        H1State::Lifecycle(H1ConnLifecycleState::CloseConnection) => {
            println!("[H1] CloseConnection");
            return NextStep::Close;
        }

        H1State::Lifecycle(H1ConnLifecycleState::CheckKeepAlive) => {
            let req_keep = conn.client_h1_state.keep_alive;
            let resp_keep = conn.upstream_h1_state.keep_alive;

            if !req_keep || !resp_keep {
                println!(
                    "[H1] keep-alive not allowed (req_keep={} resp_keep={}), closing",
                    req_keep, resp_keep
                );
                return NextStep::Continue(ProxyState::H1(H1State::Lifecycle(
                    H1ConnLifecycleState::CloseConnection,
                )));
            }

            println!("[H1] keep-alive allowed, preparing next request");
            conn.store_current_upstream_in_pool();

            return NextStep::Continue(ProxyState::H1(H1State::Lifecycle(
                H1ConnLifecycleState::PrepareNextRequest,
            )));
        }

        H1State::Lifecycle(H1ConnLifecycleState::PrepareNextRequest) => {
            println!("[H1] Resetting state for next request on keep-alive");
            reset_h1_session(&mut conn.client_h1_state);
            reset_h1_session(&mut conn.upstream_h1_state);
            conn.in_len = 0;
            conn.out_len = 0;
            conn.next_state_after_upstream = None;
            conn.target_addr = None;
            conn.upstream_tls_required = true;
            conn.connect_response_sent = false;
            conn.h2_connect_stream_id = None;
            conn.scratch = 0;

            return NextStep::WaitRead(ProxyState::H1(H1State::Request(
                H1RequestParseState::RecvHeaders,
            )));
        }

        _ => {
            println!("[H1] Unhandled state");
            NextStep::Close
        }
    }
}

// ===============================================================
// 5. UPSTREAM HANDLER – TCP + TLS handshake
// ===============================================================

pub async unsafe fn upstream_handler(conn: &mut Connection, s: UpstreamState) -> NextStep {
    println!("[UPSTREAM] {:?}", s);

    match s {
        // ----------------------------------------------------------
        UpstreamState::Dns(UpstreamDnsState::ResolveStart) => {
            if conn.upstream_tcp.is_some() || conn.upstream_tls.is_some() {
                println!("[UPSTREAM] Reusing existing upstream transport from pool");
                if let Some(next) = conn.next_state_after_upstream.take() {
                    return NextStep::Continue(next);
                }
                return NextStep::Close;
            }

            println!("[UPSTREAM] Dummy DNS resolution");
            conn.scratch = 443;
            return NextStep::Continue(ProxyState::Upstream(UpstreamState::Tcp(
                UpstreamTcpState::TcpConnectBegin,
            )));
        }

        // ----------------------------------------------------------
        UpstreamState::Tcp(UpstreamTcpState::TcpConnectBegin) => {
            debug_assert!(
                conn.target().is_some(),
                "[UPSTREAM] target address must be set before TCP connect"
            );
            let addr = conn.target().unwrap().socket_addr();

            println!("[UPSTREAM] Connecting TCP {}", addr);

            match TcpStream::connect(addr.as_str()).await {
                Ok(s) => {
                    conn.upstream_tcp = Some(Box::into_raw(Box::new(s)) as *mut _);
                    println!("[UPSTREAM] TCP connect established {}", addr);
                    if !conn.upstream_tls_required {
                        if let Some(next) = conn.next_state_after_upstream.take() {
                            return NextStep::Continue(next);
                        }
                        return NextStep::Close;
                    }
                    return NextStep::Continue(ProxyState::Upstream(UpstreamState::Tls(
                        UpstreamTlsState::TlsHandshakeBegin,
                    )));
                }
                Err(e) => {
                    println!("[UPSTREAM] TCP connect failed {}: {}", addr, e);
                    return NextStep::Close;
                }
            }
        }

        // ----------------------------------------------------------
        UpstreamState::Tls(UpstreamTlsState::TlsHandshakeBegin) => {
            debug_assert!(
                conn.upstream_tcp.is_some(),
                "[UPSTREAM] TLS handshake needs upstream TCP socket"
            );
            let host = match conn.target() {
                Some(target) => target.host.clone(),
                None => {
                    println!("[UPSTREAM] Missing target address");
                    return NextStep::Close;
                }
            };

            println!("[UPSTREAM] Upstream TLS handshake for {}", host);

            let tcp = Box::from_raw(conn.upstream_tcp.unwrap());

            use tokio_rustls::rustls::RootCertStore;
            use webpki_roots::TLS_SERVER_ROOTS;

            // Create empty store

            let mut roots = RootCertStore::empty();
            let der_bytes = std::fs::read("/Users/michealkeines/Proyx/src/CA/root.der").unwrap();
            roots.add(CertificateDer::from(der_bytes)).unwrap();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let cfg = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();

            let connector = TlsConnector::from(Arc::new(cfg));

            let domain = match ServerName::try_from(host.clone()) {
                Ok(name) => name,
                Err(_) => {
                    println!("[UPSTREAM] Invalid hostname for TLS handshake: {}", host);
                unsafe { drop(tcp); }
                    return NextStep::Close;
                }
            };

            match connector.connect(domain, *tcp).await {
                Ok(tls) => {
                    conn.upstream_tls = Some(Box::into_raw(Box::new(tls)));
                    println!("TLS upstream done");
                    conn.upstream_tcp = None;

                    debug_assert!(
                        conn.next_state_after_upstream.is_some(),
                        "[UPSTREAM] TLS handshake complete should resume pending state"
                    );

                    if let Some(next_state) = conn.next_state_after_upstream.take() {
                        return NextStep::Continue(next_state);
                    }

                    return NextStep::Continue(ProxyState::H1(H1State::Forward(
                        H1ForwardState::ForwardRequestHeaders,
                    )));
                }
                Err(err) => {
                    println!("error: {:?}", err);
                    return NextStep::Close;
                }
            }
        }

        _ => {
            println!("[UPSTREAM] Unhandled state");
            NextStep::Close
        }
    }
}

// ===============================================================
// STREAM HANDLER (not used yet)
// ===============================================================

pub async unsafe fn stream_handler(_: &mut Connection, _: StreamState) -> NextStep {
    NextStep::Close
}

// ===============================================================
// SHUTDOWN HANDLER
// ===============================================================

pub async unsafe fn shutdown_handler(_: &mut Connection, _: ShutdownState) -> NextStep {
    println!("[SHUTDOWN]");
    NextStep::Close
}

// ===============================================================
// UNUSED (but required):
// TLS / QUIC / H2 / H3 / Intercept
// ===============================================================

pub async unsafe fn quic_handler(_: &mut Connection, _: QuicState) -> NextStep {
    println!("[QUIC] Not implemented");
    NextStep::Close
}

pub async unsafe fn h2_handler(conn: &mut Connection, s: H2State) -> NextStep {
    println!("[H2] {:?}", s);

    let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);

    match s {
        H2State::Bootstrap(H2ConnBootstrapState::ClientPreface) => {
            const CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            let preface_len = CLIENT_PREFACE.len();

            while conn.in_len < preface_len {
                match read_client_data(conn, &mut buf[conn.in_len..preface_len]).await {
                    Ok(n) if n > 0 => {
                        conn.in_len += n;
                        if conn.in_len < preface_len {
                            println!(
                                "[H2] Partial client preface ({} / {} bytes), waiting",
                                conn.in_len, preface_len
                            );
                            return NextStep::WaitRead(ProxyState::H2(H2State::Bootstrap(
                                H2ConnBootstrapState::ClientPreface,
                            )));
                        }
                    }
                    Ok(_) => {
                        println!("[H2] Client closed before preface complete");
                        conn.in_len = 0;
                        return NextStep::Close;
                    }
                    Err(e) => {
                        println!("[H2] Error reading client preface: {}", e);
                        conn.in_len = 0;
                        return NextStep::Close;
                    }
                }
            }

            if &buf[..preface_len] != CLIENT_PREFACE {
                conn.in_len = 0;
                return h2_connection_error(conn, 0x1, "invalid client preface").await;
            }

            println!("[H2] Client preface complete");

            // Server preface: immediately send our SETTINGS frame (empty payload = defaults)
            let server_settings = build_h2_frame_header(0, 0x4, 0x0, 0);
            if let Err(e) = write_client_data(conn, &server_settings).await {
                println!("[H2] Failed to send server SETTINGS: {}", e);
                return NextStep::Close;
            }
            println!("[H2] Sent server SETTINGS");

            conn.in_len = 0;
            return NextStep::Continue(ProxyState::H2(H2State::Bootstrap(
                H2ConnBootstrapState::RecvClientSettings,
            )));
        }

        H2State::Bootstrap(H2ConnBootstrapState::RecvClientSettings) => {
            // Ensure we have a full SETTINGS frame (9-byte header + payload)
            if conn.in_len < 9 {
                match read_client_data(conn, buf).await {
                    Ok(n) if n > 0 => conn.in_len = n,
                    _ => return NextStep::Close,
                }
            }

            if conn.in_len < 9 {
                return NextStep::WaitRead(ProxyState::H2(H2State::Bootstrap(
                    H2ConnBootstrapState::RecvClientSettings,
                )));
            }

            let header = parse_h2_frame_header(&buf[..9]);
            let settings_len = header.length;
            let total = 9 + settings_len;

            if header.kind != 0x4 {
                return h2_connection_error(conn, 0x1, "first frame was not SETTINGS").await;
            }

            if header.flags & 0x1 != 0 {
                if settings_len != 0 {
                    return h2_connection_error(
                        conn,
                        0x6,
                        "SETTINGS ack had non-zero length",
                    )
                    .await;
                }
                return h2_connection_error(conn, 0x1, "SETTINGS preface was ACK").await;
            }

            if settings_len % 6 != 0 {
                return h2_connection_error(conn, 0x6, "SETTINGS length not multiple of 6").await;
            }

            if settings_len > H2_DEFAULT_MAX_FRAME_SIZE {
                return h2_connection_error(
                    conn,
                    0x6,
                    "SETTINGS frame exceeds max frame size",
                )
                .await;
            }

            if total > conn.in_cap {
                return h2_connection_error(conn, 0x6, "SETTINGS frame larger than buffer").await;
            }

            while conn.in_len < total {
                match read_client_data(conn, &mut buf[conn.in_len..total]).await {
                    Ok(n) if n > 0 => conn.in_len += n,
                    Ok(_) => {
                        return h2_connection_error(
                            conn,
                            0x1,
                            "client closed during SETTINGS read",
                        )
                        .await;
                    }
                    Err(e) => {
                        println!(
                            "[H2] Error reading SETTINGS (have {} want {}): {}",
                            conn.in_len, total, e
                        );
                        return h2_connection_error(conn, 0x1, "error reading SETTINGS").await;
                    }
                }
            }

            println!("[H2] Client settings frame len {}", settings_len);

            // ACK client SETTINGS
            let settings_ack = build_h2_frame_header(0, 0x4, 0x1, 0);
            if let Err(e) = write_client_data(conn, &settings_ack).await {
                println!("[H2] Failed to send SETTINGS ACK: {}", e);
                return NextStep::Close;
            }
            println!("[H2] Sent SETTINGS ACK to client");

            // Slide any extra bytes (next frame) to start of buffer
            if conn.in_len > total {
                let remaining = conn.in_len - total;
                buf.copy_within(total..total + remaining, 0);
                conn.in_len = remaining;
            } else {
                conn.in_len = 0;
            }

            // Send our own SETTINGS and ACK theirs
            return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                H2FrameParseState::RecvFrameHeader,
            )));
        }

        H2State::FrameParse(H2FrameParseState::RecvFrameHeader) => {
            let mut n = conn.in_len;
            if n < 9 {
                match read_client_data(conn, buf).await {
                    Ok(read) if read > 0 => n = read,
                    _ => return NextStep::Close,
                }
            }

            if n < 9 {
                conn.in_len = n;
                return NextStep::WaitRead(ProxyState::H2(H2State::FrameParse(
                    H2FrameParseState::RecvFrameHeader,
                )));
            }

            conn.in_len = n;

            let frame = parse_h2_frame_header(&buf[..9]);
            println!(
                "[H2] Frame parsed len={} type={} flags=0x{:02x} stream={}",
                frame.length, frame.kind, frame.flags, frame.stream_id
            );

            conn.scratch = ((frame.stream_id as u64) << 32) | frame.length as u64;

            return NextStep::Continue(ProxyState::H2(H2State::FlowControl(
                H2FlowControlState::FlowControlWaitWindowUpdate,
            )));
        }

        H2State::FlowControl(H2FlowControlState::FlowControlWaitWindowUpdate) => {
            let payload_len = (conn.scratch & 0xffff_ffff) as usize;
            let stream_id = (conn.scratch >> 32) as u32;
            let frame = parse_h2_frame_header(&buf[..9]);

            if payload_len > H2_DEFAULT_MAX_FRAME_SIZE {
                return h2_connection_error(
                    conn,
                    0x6,
                    "frame payload exceeds max frame size",
                )
                .await;
            }

            if frame.kind == 0x4 && (payload_len % 6 != 0) && (frame.flags & 0x1 == 0) {
                return h2_connection_error(
                    conn,
                    0x6,
                    "SETTINGS length not multiple of 6",
                )
                .await;
            }

            if frame.kind == 0x4 && frame.flags & 0x1 != 0 && payload_len != 0 {
                return h2_connection_error(
                    conn,
                    0x6,
                    "SETTINGS ACK had non-zero length",
                )
                .await;
            }

            if payload_len + 9 > conn.in_len {
                println!(
                    "[H2] Frame payload truncated (expected {} + 9, got {}), reading more",
                    payload_len, conn.in_len
                );
                let need = payload_len + 9 - conn.in_len;
                let start = conn.in_len;
                if start + need > conn.in_cap {
                    return h2_connection_error(conn, 0x6, "frame larger than buffer").await;
                }
                match read_client_data(conn, &mut buf[start..start + need]).await {
                    Ok(got) if got == need => {
                        conn.in_len += got;
                    }
                    Ok(_) => {
                        return NextStep::WaitRead(ProxyState::H2(H2State::FlowControl(
                            H2FlowControlState::FlowControlWaitWindowUpdate,
                        )));
                    }
                    Err(e) => {
                        println!("[H2] Failed reading frame payload: {}", e);
                        return NextStep::Close;
                    }
                }
            }

            let frame = parse_h2_frame_header(&buf[..9]);

            if let Some(connect_stream) = conn.h2_connect_stream_id {
                if frame.stream_id == connect_stream && frame.kind == 0x0 {
                    println!(
                        "[H2] CONNECT deferring DATA frame (len={} flags=0x{:02x}) to tunnel handler",
                        frame.length, frame.flags
                    );
                    return NextStep::Continue(ProxyState::H2(H2State::Proxy(
                        H2ProxyState::ProxyFramesClientToUpstream,
                    )));
                }
            }

            // SETTINGS ack (len=0, type=0x4, ACK flag) → just loop
            if frame.kind == 0x4 && frame.flags & 0x1 != 0 {
                conn.in_len = 0;
                println!("[H2] Received SETTINGS ACK from client");
                return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                    H2FrameParseState::RecvFrameHeader,
                )));
            }

            // HEADERS (stream > 0): parse pseudo headers and establish target. Supports PADDED,
            // PRIORITY, and CONTINUATION per RFC 9113.
            if frame.kind == 0x1 && frame.stream_id != 0 {
                let mut consumed_total = 9 + payload_len;
                let mut frag = Vec::new();

                let mut offset = 9;
                let mut remaining = payload_len;
                let mut pad_len = 0usize;

                if frame.flags & 0x8 != 0 {
                    if remaining == 0 {
                        return h2_connection_error(conn, 0x1, "PADDED with zero length").await;
                    }
                    pad_len = buf[offset] as usize;
                    offset += 1;
                    remaining = remaining.saturating_sub(1);
                }

                if frame.flags & 0x20 != 0 {
                    if remaining < 5 {
                        return h2_connection_error(conn, 0x1, "PRIORITY flag missing payload").await;
                    }
                    offset += 5;
                    remaining -= 5;
                }

                if remaining < pad_len {
                    return h2_connection_error(conn, 0x1, "pad length exceeds payload").await;
                }

                let fragment_len = remaining - pad_len;
                frag.extend_from_slice(&buf[offset..offset + fragment_len]);

                let mut end_headers = frame.flags & 0x4 != 0;

                while !end_headers {
                    // Ensure next frame header is available
                    if conn.in_len < consumed_total + 9 {
                        let need = consumed_total + 9 - conn.in_len;
                        match read_client_data(conn, &mut buf[conn.in_len..conn.in_len + need]).await {
                            Ok(n) if n > 0 => conn.in_len += n,
                            _ => return h2_connection_error(conn, 0x1, "incomplete CONTINUATION header").await,
                        }
                    }

                    let next_header = parse_h2_frame_header(&buf[consumed_total..consumed_total + 9]);
                    if next_header.kind != 0x9 || next_header.stream_id != frame.stream_id {
                        return h2_connection_error(conn, 0x1, "expected CONTINUATION").await;
                    }

                    let next_total = consumed_total + 9 + next_header.length;
                    if next_total > conn.in_len {
                        let need = next_total - conn.in_len;
                        if next_total > conn.in_cap {
                            return h2_connection_error(conn, 0x6, "CONTINUATION too large for buffer").await;
                        }
                        match read_client_data(conn, &mut buf[conn.in_len..next_total]).await {
                            Ok(n) if n > 0 => conn.in_len += n,
                            _ => return h2_connection_error(conn, 0x1, "incomplete CONTINUATION payload").await,
                        }
                    }

                    frag.extend_from_slice(&buf[consumed_total + 9..consumed_total + 9 + next_header.length]);
                    consumed_total = next_total;
                    end_headers = next_header.flags & 0x4 != 0;
                }

                // Consume processed bytes
                if conn.in_len > consumed_total {
                    let remaining = conn.in_len - consumed_total;
                    buf.copy_within(consumed_total..consumed_total + remaining, 0);
                    conn.in_len = remaining;
                } else {
                    conn.in_len = 0;
                }

                if let Some((method, host, port)) = parse_h2_pseudo_headers(&frag, 443) {
                    if method.eq_ignore_ascii_case("CONNECT") {
                        println!("[H2] CONNECT detected on stream {}", frame.stream_id);
                        conn.set_target(host, port);
                        conn.upstream_tls_required = false;
                        conn.connect_response_sent = false;
                        conn.h2_connect_stream_id = Some(frame.stream_id);
                        conn.next_state_after_upstream =
                            Some(ProxyState::H2(H2State::Proxy(
                                H2ProxyState::ProxyFramesClientToUpstream,
                            )));
                        return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                            UpstreamDnsState::ResolveStart,
                        )));
                    } else {
                        if conn.target().is_none() {
                            conn.set_target(host, port);
                        }
                        conn.next_state_after_upstream =
                            Some(ProxyState::H2(H2State::Proxy(
                                H2ProxyState::ProxyFramesClientToUpstream,
                            )));
                        return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                            UpstreamDnsState::ResolveStart,
                        )));
                    }
                } else {
                    return h2_connection_error(conn, 0x1, "failed to parse HEADERS pseudo-headers").await;
                }
            }

            // If we still don't have a target and this isn't a HEADERS frame, just consume it.
            if frame.kind != 0x1 && conn.target().is_none() {
                let consumed = 9 + payload_len;
                if conn.in_len > consumed {
                    let remaining = conn.in_len - consumed;
                    buf.copy_within(consumed..consumed + remaining, 0);
                    conn.in_len = remaining;
                } else {
                    conn.in_len = 0;
                }
                return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                    H2FrameParseState::RecvFrameHeader,
                )));
            }

            if conn.upstream_tcp.is_none() && conn.upstream_tls.is_none() {
                println!("[H2] No upstream yet, queuing upstream connect before proxying");
                if conn.target().is_none() {
                    conn.in_len = 0;
                    return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                        H2FrameParseState::RecvFrameHeader,
                    )));
                }
                if conn.next_state_after_upstream.is_none() {
                    conn.next_state_after_upstream = Some(ProxyState::H2(H2State::Proxy(
                        H2ProxyState::ProxyFramesClientToUpstream,
                    )));
                }
                conn.in_len = 0;
                return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                    UpstreamDnsState::ResolveStart,
                )));
            }

            if frame.kind == 0x1 {
                if let Some((method, host, port)) =
                    parse_h2_pseudo_headers(&buf[9..9 + payload_len], 443)
                {
                    if method.eq_ignore_ascii_case("CONNECT") {
                        println!("[H2] CONNECT detected on stream {}", stream_id);
                        conn.set_target(host, port);
                        conn.upstream_tls_required = false;
                        conn.connect_response_sent = false;
                        conn.h2_connect_stream_id = Some(stream_id);
                        conn.next_state_after_upstream =
                            Some(ProxyState::H2(H2State::Proxy(
                                H2ProxyState::ProxyFramesClientToUpstream,
                            )));
                        let consumed = 9 + payload_len;
                        if conn.in_len > consumed {
                            let remaining = conn.in_len - consumed;
                            buf.copy_within(consumed..consumed + remaining, 0);
                            conn.in_len = remaining;
                        } else {
                            conn.in_len = 0;
                        }
                        return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                            UpstreamDnsState::ResolveStart,
                        )));
                    } else {
                        if conn.target().is_none() {
                            conn.set_target(host, port);
                        }
                        conn.next_state_after_upstream =
                            Some(ProxyState::H2(H2State::Proxy(
                                H2ProxyState::ProxyFramesClientToUpstream,
                            )));
                        let consumed = 9 + payload_len;
                        if conn.in_len > consumed {
                            let remaining = conn.in_len - consumed;
                            buf.copy_within(consumed..consumed + remaining, 0);
                            conn.in_len = remaining;
                        } else {
                            conn.in_len = 0;
                        }
                        return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                            UpstreamDnsState::ResolveStart,
                        )));
                    }
                }
            }

            let consumed = 9 + payload_len;
            if conn.in_len > consumed {
                let remaining = conn.in_len - consumed;
                buf.copy_within(consumed..consumed + remaining, 0);
                conn.in_len = remaining;
            } else {
                conn.in_len = 0;
            }

            if conn.next_state_after_upstream.is_none() {
                conn.next_state_after_upstream = Some(ProxyState::H2(H2State::Proxy(
                    H2ProxyState::ProxyFramesClientToUpstream,
                )));
            }

            return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                H2FrameParseState::RecvFrameHeader,
            )));
        }

        H2State::Proxy(H2ProxyState::ProxyFramesClientToUpstream) => {
            let mut n = conn.in_len;
            println!(
                "[H2] CONNECT tunnel entry: in_len={} upstream_tcp={} upstream_tls={}",
                n,
                conn.upstream_tcp.is_some(),
                conn.upstream_tls.is_some()
            );

            if let Some(stream_id) = conn.h2_connect_stream_id {
                // If no buffered client data, choose the side that becomes readable first.
                if n == 0 {
                    println!(
                        "[H2] CONNECT tunnel idle; pending client_buf_len=0 upstream_ready={}",
                        conn.upstream_tcp.is_some() || conn.upstream_tls.is_some()
                    );
                    let client_ready = wait_client_transport_readable(conn);
                    let upstream_ready = wait_upstream_transport_readable(conn);

                    println!("[H2] CONNECT tunnel idle; waiting on client or upstream readability");
                    tokio::select! {
                        r = client_ready => {
                            if let Err(e) = r {
                                println!("[H2] CONNECT client readable wait error: {}", e);
                                return NextStep::Close;
                            }
                            println!("[H2] CONNECT tunnel: client became readable");
                        }
                        r = upstream_ready => {
                            if let Err(e) = r {
                                println!("[H2] CONNECT upstream readable wait error: {}", e);
                                return NextStep::Close;
                            }
                            println!("[H2] CONNECT tunnel: upstream became readable");
                            return h2_connect_forward_upstream(conn, stream_id, buf).await;
                        }
                    }
                }
            }

            if n == 0 {
                match read_client_data(conn, buf).await {
                    Ok(read) if read > 0 => {
                        conn.in_len = read;
                        n = read;
                        println!("[H2] Read {} bytes from client for upstream", n);
                    }
                    _ => return NextStep::Close,
                }
            }

            if conn.upstream_tcp.is_none() && conn.upstream_tls.is_none() {
                // We need an upstream before proxying; if we don't even know the target yet, keep parsing frames.
                if conn.target().is_none() {
                    conn.in_len = 0;
                    return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                        H2FrameParseState::RecvFrameHeader,
                    )));
                }

                if conn.next_state_after_upstream.is_none() {
                    conn.next_state_after_upstream = Some(ProxyState::H2(H2State::Proxy(
                        H2ProxyState::ProxyFramesClientToUpstream,
                    )));
                }

                return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                    UpstreamDnsState::ResolveStart,
                )));
            }

            if let Some(stream_id) = conn.h2_connect_stream_id {
                // Always ensure CONNECT response is sent before tunneling.
                if !conn.connect_response_sent {
                    if let Err(e) = send_h2_connect_response(conn, stream_id).await {
                        println!("[H2] Failed to send CONNECT response: {}", e);
                        return NextStep::Close;
                    }
                    conn.connect_response_sent = true;
                }

                // For CONNECT, allow upstream to drive the tunnel even if the client is idle.
                if conn.in_len == 0 {
                    println!(
                        "[H2] CONNECT tunnel idle; pending client_buf_len=0 upstream_ready={}",
                        conn.upstream_tcp.is_some() || conn.upstream_tls.is_some()
                    );
                    let client_ready = wait_client_transport_readable(conn);
                    let upstream_ready = wait_upstream_transport_readable(conn);

                    println!("[H2] CONNECT tunnel idle; waiting on client or upstream readability");
                    tokio::select! {
                        r = client_ready => {
                            if let Err(e) = r {
                                println!("[H2] CONNECT client readable wait error: {}", e);
                                return NextStep::Close;
                            }
                            println!("[H2] CONNECT tunnel: client became readable");
                        }
                        r = upstream_ready => {
                            if let Err(e) = r {
                                println!("[H2] CONNECT upstream readable wait error: {}", e);
                                return NextStep::Close;
                            }
                            println!("[H2] CONNECT tunnel: upstream became readable");
                            return h2_connect_forward_upstream(conn, stream_id, buf).await;
                        }
                    }
                }

                if !conn.connect_response_sent {
                    if let Err(e) = send_h2_connect_response(conn, stream_id).await {
                        println!("[H2] Failed to send CONNECT response: {}", e);
                        return NextStep::Close;
                    }
                    conn.connect_response_sent = true;
                }

                // Ensure full frame header
                if n < 9 {
                    match read_client_data(conn, &mut buf[n..9]).await {
                        Ok(more) if more > 0 => {
                            conn.in_len += more;
                            n += more;
                        }
                        _ => return NextStep::Close,
                    }
                }

                if conn.in_len < 9 {
                    return NextStep::WaitRead(ProxyState::H2(H2State::Proxy(
                        H2ProxyState::ProxyFramesClientToUpstream,
                    )));
                }

                let frame = parse_h2_frame_header(&buf[..9]);
                let total = 9 + frame.length;
                if total > conn.in_cap {
                    println!("[H2] CONNECT frame too large for buffer: {}", total);
                    return NextStep::Close;
                }

                while conn.in_len < total {
                    match read_client_data(conn, &mut buf[conn.in_len..total]).await {
                        Ok(more) if more > 0 => conn.in_len += more,
                        _ => return NextStep::WaitRead(ProxyState::H2(H2State::Proxy(
                            H2ProxyState::ProxyFramesClientToUpstream,
                        ))),
                    }
                }

                if frame.stream_id == 0 {
                    match frame.kind {
                        0x4 => {
                            println!(
                                "[H2] CONNECT received connection-level SETTINGS (flags=0x{:02x}, len={}), ignoring",
                                frame.flags, frame.length
                            );
                            consume_h2_frame(conn, buf, total);
                            return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                                H2FrameParseState::RecvFrameHeader,
                            )));
                        }
                        0x6 => {
                            if frame.length != 8 {
                                println!(
                                    "[H2] CONNECT received invalid PING length {}, dropping",
                                    frame.length
                                );
                                consume_h2_frame(conn, buf, total);
                                return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                                    H2FrameParseState::RecvFrameHeader,
                                )));
                            }

                            if frame.flags & 0x1 == 0 {
                                let mut ack = Vec::with_capacity(17);
                                ack.extend_from_slice(&build_h2_frame_header(8, 0x6, 0x1, 0));
                                ack.extend_from_slice(&buf[9..17]);
                                if let Err(e) = write_client_data(conn, &ack).await {
                                    println!("[H2] Failed to send PING ACK: {}", e);
                                    return NextStep::Close;
                                }
                                println!("[H2] CONNECT replied to PING");
                            }

                            consume_h2_frame(conn, buf, total);
                            return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                                H2FrameParseState::RecvFrameHeader,
                            )));
                        }
                        0x8 => {
                            println!(
                                "[H2] CONNECT received WINDOW_UPDATE (len={} stream={}), ignoring",
                                frame.length, frame.stream_id
                            );
                            consume_h2_frame(conn, buf, total);
                            return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                                H2FrameParseState::RecvFrameHeader,
                            )));
                        }
                        _ => {
                            println!(
                                "[H2] CONNECT ignoring connection-level frame kind={} len={}",
                                frame.kind, frame.length
                            );
                            consume_h2_frame(conn, buf, total);
                            return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                                H2FrameParseState::RecvFrameHeader,
                            )));
                        }
                    }
                }

                if frame.stream_id != stream_id {
                    println!(
                        "[H2] CONNECT ignoring frame on stream {} (kind={}) while tunneling stream {}",
                        frame.stream_id, frame.kind, stream_id
                    );
                    consume_h2_frame(conn, buf, total);
                    return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                        H2FrameParseState::RecvFrameHeader,
                    )));
                }

                if frame.kind != 0x0 {
                    println!(
                        "[H2] CONNECT expected DATA on stream {}, got kind={} (flags=0x{:02x})",
                        stream_id, frame.kind, frame.flags
                    );
                    consume_h2_frame(conn, buf, total);
                    return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                        H2FrameParseState::RecvFrameHeader,
                    )));
                }

                let mut offset = 9;
                let mut remaining = frame.length;
                let mut pad_len = 0usize;
                if frame.flags & 0x8 != 0 {
                    if remaining == 0 {
                        println!("[H2] CONNECT DATA PADDED but no pad length byte");
                        conn.in_len = 0;
                        return NextStep::Close;
                    }
                    pad_len = buf[offset] as usize;
                    offset += 1;
                    remaining = remaining.saturating_sub(1);
                }

                if remaining < pad_len {
                    println!("[H2] CONNECT DATA pad length {} exceeds payload {}", pad_len, remaining);
                    conn.in_len = 0;
                    return NextStep::Close;
                }

                let data_len = remaining - pad_len;
                println!(
                    "[H2] CONNECT DATA frame stream={} len={} data={} pad={} end_stream={}",
                    frame.stream_id,
                    frame.length,
                    data_len,
                    pad_len,
                    frame.flags & 0x1 != 0
                );

                if data_len > 0 {
                    let end = offset + data_len;
                    println!(
                        "[H2] CONNECT writing {} bytes to upstream (tcp={} tls={})",
                        data_len,
                        conn.upstream_tcp.is_some(),
                        conn.upstream_tls.is_some()
                    );
                    if let Err(e) = write_upstream_data(conn, &buf[offset..end]).await {
                        println!("[H2] CONNECT payload write failed: {}", e);
                        return NextStep::Close;
                    } else {
                        println!("[H2] CONNECT wrote {} bytes to upstream", data_len);
                    }
                }

                // Slide remaining buffered bytes (if any) down
                if conn.in_len > total {
                    let remaining_bytes = conn.in_len - total;
                    buf.copy_within(total..total + remaining_bytes, 0);
                    conn.in_len = remaining_bytes;
                } else {
                    conn.in_len = 0;
                }

                return NextStep::Continue(ProxyState::H2(H2State::Proxy(
                    H2ProxyState::ProxyFramesClientToUpstream,
                )));
            }

            if let Err(e) = write_upstream_data(conn, &buf[..n]).await {
                println!("[H2] Client->upstream write failed: {}", e);
                return NextStep::Close;
            }
            println!("[H2] Forwarded {} bytes from client to upstream (raw)", n);

            if conn.h2_connect_stream_id.is_some() {
                return NextStep::Continue(ProxyState::H2(H2State::Proxy(
                    H2ProxyState::ProxyFramesClientToUpstream,
                )));
            }

            return NextStep::Continue(ProxyState::H2(H2State::Proxy(
                H2ProxyState::ProxyFramesUpstreamToClient,
            )));
        }

        H2State::Proxy(H2ProxyState::ProxyFramesUpstreamToClient) => {
            if let Some(stream_id) = conn.h2_connect_stream_id {
                return h2_connect_forward_upstream(conn, stream_id, buf).await;
            }

            let n = match read_upstream_data(conn, buf).await {
                Ok(n) if n > 0 => n,
                Ok(_) => {
                    println!("[H2] Upstream closed connection");
                    return NextStep::Close;
                }
                Err(e) => {
                    println!("[H2] Upstream read error: {}", e);
                    return NextStep::Close;
                }
            };

            conn.in_len = n;

            if let Err(e) = write_client_data(conn, &buf[..n]).await {
                println!("[H2] Upstream->client write failed: {}", e);
                return NextStep::Close;
            }
            println!("[H2] Forwarded {} bytes upstream->client (raw)", n);

            return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                H2FrameParseState::RecvFrameHeader,
            )));
        }

        _ => {
            println!("[H2] Unhandled state");
            NextStep::Close
        }
    }
}

pub async unsafe fn h3_handler(conn: &mut Connection, s: H3State) -> NextStep {
    println!("[H3] {:?}", s);

    let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);

    match s {
        H3State::Control(H3ControlState::ControlStreamSetup) => {
            match read_client_data(conn, buf).await {
                Ok(n) if n > 0 => {
                    conn.in_len = n;
                    println!("[H3] Control stream {} bytes", n);
                    conn.next_state_after_upstream = Some(ProxyState::H3(H3State::RequestParse(
                        H3RequestParseState::RecvHeaders,
                    )));
                    return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                        UpstreamDnsState::ResolveStart,
                    )));
                }
                _ => return NextStep::Close,
            }
        }

        H3State::RequestParse(H3RequestParseState::RecvHeaders) => {
            let n = match read_client_data(conn, buf).await {
                Ok(n) if n > 0 => n,
                Ok(_) => {
                    println!("[H3] Client closed while reading headers");
                    return NextStep::Close;
                }
                Err(e) => {
                    println!("[H3] Headers read error: {}", e);
                    return NextStep::Close;
                }
            };

            conn.in_len = n;
            if let Some((host, port)) = parse_connect_target(&buf[..n], 443) {
                println!("[H3] CONNECT detected");
                conn.set_target(host, port);
                conn.upstream_tls_required = false;
                conn.connect_response_sent = false;
                conn.next_state_after_upstream = Some(ProxyState::H3(H3State::Session(
                    H3SessionState::FinalizeConnection,
                )));
                return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                    UpstreamDnsState::ResolveStart,
                )));
            }
            println!("[H3] Parsed headers {} bytes", n);
            return NextStep::Continue(ProxyState::H3(H3State::Qpack(
                H3QpackState::QpackDecodeHeaders,
            )));
        }

        H3State::Qpack(H3QpackState::QpackDecodeHeaders) => {
            println!("[H3] QPACK decode stub ({} bytes)", conn.in_len);
            return NextStep::Continue(ProxyState::H3(H3State::Forward(
                H3ForwardState::ForwardHeaders,
            )));
        }

        H3State::Forward(H3ForwardState::ForwardHeaders) => {
            let n = conn.in_len;
            if n == 0 {
                println!("[H3] No headers buffered to forward");
                return NextStep::Close;
            }

            if let Err(e) = write_upstream_data(conn, &buf[..n]).await {
                println!("[H3] Write to upstream failed: {}", e);
                return NextStep::Close;
            }

            return NextStep::Continue(ProxyState::H3(H3State::Forward(
                H3ForwardState::ForwardBody,
            )));
        }

        H3State::Forward(H3ForwardState::ForwardBody) => {
            let n = match read_upstream_data(conn, buf).await {
                Ok(n) if n > 0 => n,
                Ok(_) => {
                    println!("[H3] Upstream closed during body");
                    return NextStep::Close;
                }
                Err(e) => {
                    println!("[H3] Upstream read error: {}", e);
                    return NextStep::Close;
                }
            };

            conn.in_len = n;
            if let Err(e) = write_client_data(conn, &buf[..n]).await {
                println!("[H3] Write to client failed: {}", e);
                return NextStep::Close;
            }

            return NextStep::Continue(ProxyState::H3(H3State::RequestParse(
                H3RequestParseState::RecvHeaders,
            )));
        }

        H3State::Session(H3SessionState::FinalizeConnection) => {
            if conn.upstream_tcp.is_none() && conn.upstream_tls.is_none() {
                return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                    UpstreamDnsState::ResolveStart,
                )));
            }

            if !conn.connect_response_sent {
                let _ = write_client_data(
                    conn,
                    b"HTTP/1.1 200 Connection Established\r\n\r\n",
                )
                .await;
                conn.connect_response_sent = true;
            }

            let _ = tunnel_copy(conn).await;
            return NextStep::Close;
        }

        _ => {
            println!("[H3] Unhandled state");
            NextStep::Close
        }
    }
}

async unsafe fn read_client_data(conn: &mut Connection, buf: &mut [u8]) -> std::io::Result<usize> {
    debug_assert!(
        conn.client_tls.is_some() || conn.client_tcp.is_some(),
        "read_client_data: expected at least one client transport"
    );
    if let Some(ptr) = conn.client_tls {
        (*ptr).read(buf).await
    } else if let Some(ptr) = conn.client_tcp {
        (*ptr).read(buf).await
    } else {
        Err(Error::new(ErrorKind::NotConnected, "client stream missing"))
    }
}

async unsafe fn write_client_data(conn: &mut Connection, data: &[u8]) -> std::io::Result<()> {
    debug_assert!(
        conn.client_tls.is_some() || conn.client_tcp.is_some(),
        "write_client_data: expected at least one client transport"
    );
    if let Some(ptr) = conn.client_tls {
        (*ptr).write_all(data).await
    } else if let Some(ptr) = conn.client_tcp {
        (*ptr).write_all(data).await
    } else {
        Err(Error::new(ErrorKind::NotConnected, "client stream missing"))
    }
}

async unsafe fn read_upstream_data(
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

async unsafe fn write_upstream_data(conn: &mut Connection, data: &[u8]) -> std::io::Result<()> {
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

async unsafe fn tunnel_copy(conn: &mut Connection) -> std::io::Result<()> {
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

fn parse_connect_target(buf: &[u8], default_port: u16) -> Option<(String, u16)> {
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

fn looks_like_http1(buf: &[u8]) -> bool {
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

fn parse_request_line(buf: &[u8]) -> Option<(String, String)> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = Request::new(&mut headers);
    if let Ok(Status::Complete(_)) = req.parse(buf) {
        if let (Some(method), Some(path)) = (req.method, req.path) {
            return Some((method.to_string(), path.to_string()));
        }
    }
    None
}

fn parse_h2_pseudo_headers(
    payload: &[u8],
    default_port: u16,
) -> Option<(String, String, u16)> {
    let mut decoder = Decoder::new();
    let headers = decoder.decode(payload).ok()?;

    let mut method: Option<String> = None;
    let mut authority: Option<String> = None;

    for (name, value) in headers {
        if let (Ok(n), Ok(v)) = (std::str::from_utf8(&name), std::str::from_utf8(&value)) {
            if n.eq_ignore_ascii_case(":method") {
                method = Some(v.to_string());
            } else if n.eq_ignore_ascii_case(":authority") {
                authority = Some(v.to_string());
            }
        }
    }

    let method = method?;
    let authority = authority?;
    let (host, port) = split_host_port(&authority, default_port);
    Some((method, host, port))
}

fn parse_host_header(buf: &[u8], default_port: u16) -> Option<(String, u16)> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = Request::new(&mut headers);

    if let Ok(Status::Complete(_)) = req.parse(buf) {
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

fn split_host_port(host: &str, default_port: u16) -> (String, u16) {
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

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "te"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn prepare_h1_request(conn: &mut Connection, header_bytes: &[u8]) -> Result<(), String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = Request::new(&mut headers);
    let status = req.parse(header_bytes).map_err(|e| format!("parse error: {}", e))?;
    if !matches!(status, Status::Complete(_)) {
        return Err("incomplete request headers".into());
    }

    let method = req.method.ok_or("missing method")?.to_string();
    let path = req.path.ok_or("missing path")?.to_string();
    let version = req.version.unwrap_or(1);
    let is_1_0 = version == 0;

    let mut keep_alive = !is_1_0;
    let mut is_chunked = false;
    let mut content_len: Option<u64> = None;
    let mut expect_continue = false;
    let mut host_header: Option<String> = None;

    for h in req.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        let value = std::str::from_utf8(h.value).unwrap_or("").trim();

        match name.as_str() {
            "host" => host_header = Some(value.to_string()),
            "connection" => {
                let lower = value.to_ascii_lowercase();
                if lower.contains("close") {
                    keep_alive = false;
                }
                if lower.contains("keep-alive") && is_1_0 {
                    keep_alive = true;
                }
            }
            "proxy-connection" => keep_alive = false,
            "expect" => {
                if value.eq_ignore_ascii_case("100-continue") {
                    expect_continue = true;
                }
            }
            "transfer-encoding" => {
                if value.to_ascii_lowercase().contains("chunked") {
                    is_chunked = true;
                }
            }
            "content-length" => {
                if let Ok(v) = value.parse::<u64>() {
                    content_len = Some(v);
                }
            }
            _ => {}
        }
    }

    if is_chunked {
        content_len = None;
    }

    let method_upper = method.to_ascii_uppercase();
    let is_connect = method_upper == "CONNECT";
    let is_head = method_upper == "HEAD";

    let mut target_host = String::new();
    let mut target_port: u16 = 80;
    let mut upstream_path = path.clone();
    let mut default_port = 80;

    if is_connect {
        let (h, p) = split_host_port(&path, 443);
        target_host = h;
        target_port = p;
        default_port = 443;
        conn.upstream_tls_required = false;
        conn.connect_response_sent = false;
        conn.next_state_after_upstream = Some(ProxyState::H1(H1State::Connect(
            H1ConnectState::ConnectTunnelTransfer,
        )));
    } else if path.starts_with("http://") || path.starts_with("https://") {
        let (scheme, rest) = path
            .split_once("://")
            .ok_or("invalid absolute-form request-target")?;
        default_port = if scheme.eq_ignore_ascii_case("https") {
            443
        } else {
            80
        };
        let slash = rest.find('/').unwrap_or(rest.len());
        let authority = &rest[..slash];
        let parsed_path = if slash < rest.len() {
            &rest[slash..]
        } else {
            "/"
        };
        let (h, p) = split_host_port(authority, default_port);
        target_host = h;
        target_port = p;
        upstream_path = parsed_path.to_string();
        conn.upstream_tls_required = default_port == 443;
    } else {
        let (h, p) = match host_header {
            Some(ref host) => split_host_port(host, 80),
            None => {
                if !is_1_0 {
                    return Err("missing Host header for HTTP/1.1 request".into());
                }
                match conn.target() {
                    Some(t) => (t.host.clone(), t.port),
                    None => return Err("missing Host header and no cached target".into()),
                }
            }
        };
        target_host = h;
        target_port = p;
        default_port = if target_port == 443 { 443 } else { 80 };
        conn.upstream_tls_required = target_port == 443;
    }

    if target_host.is_empty() {
        return Err("unable to determine target host".into());
    }

    conn.set_target(target_host.clone(), target_port);
    if is_connect {
        conn.next_state_after_upstream = Some(ProxyState::H1(H1State::Connect(
            H1ConnectState::ConnectTunnelTransfer,
        )));
    } else {
        conn.next_state_after_upstream = Some(ProxyState::H1(H1State::Forward(
            H1ForwardState::ForwardRequestHeaders,
        )));
    }

    let mut rewritten = Vec::with_capacity(header_bytes.len() + 32);
    let version_str = if is_1_0 { "HTTP/1.0" } else { "HTTP/1.1" };
    rewritten.extend_from_slice(method.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(upstream_path.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(version_str.as_bytes());
    rewritten.extend_from_slice(b"\r\n");

    for h in req.headers.iter() {
        let name = h.name;
        let lower = name.to_ascii_lowercase();
        if is_hop_by_hop(&lower) {
            continue;
        }
        if lower == "host"
            || lower == "content-length"
            || lower == "transfer-encoding"
            || lower == "expect"
        {
            continue;
        }
        rewritten.extend_from_slice(name.as_bytes());
        rewritten.extend_from_slice(b": ");
        rewritten.extend_from_slice(h.value);
        rewritten.extend_from_slice(b"\r\n");
    }

    // Host header
    if !is_connect {
        let include_port = target_port != default_port;
        rewritten.extend_from_slice(b"Host: ");
        rewritten.extend_from_slice(target_host.as_bytes());
        if include_port {
            rewritten.extend_from_slice(format!(":{}", target_port).as_bytes());
        }
        rewritten.extend_from_slice(b"\r\n");
    }

    // Connection header
    let conn_header = if keep_alive { "keep-alive" } else { "close" };
    rewritten.extend_from_slice(b"Connection: ");
    rewritten.extend_from_slice(conn_header.as_bytes());
    rewritten.extend_from_slice(b"\r\n");

    if expect_continue {
        rewritten.extend_from_slice(b"Expect: 100-continue\r\n");
    }

    if is_chunked {
        rewritten.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    } else if let Some(len) = content_len {
        rewritten.extend_from_slice(format!("Content-Length: {}\r\n", len).as_bytes());
    }

    rewritten.extend_from_slice(b"\r\n");

    if rewritten.len() > conn.out_cap {
        return Err("request headers exceed buffer".into());
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            rewritten.as_ptr(),
            conn.out_buf.as_ptr(),
            rewritten.len(),
        );
    }
    conn.out_len = rewritten.len();

    conn.client_h1_state.parsed_headers = true;
    conn.client_h1_state.parsed_body = false;
    conn.client_h1_state.content_len = content_len;
    conn.client_h1_state.body_len = if is_chunked { Some(0) } else { content_len };
    conn.client_h1_state.is_chunked = is_chunked;
    conn.client_h1_state.keep_alive = keep_alive;
    conn.client_h1_state.expect_continue = expect_continue;
    conn.client_h1_state.is_head = is_head;
    conn.client_h1_state.is_connect = is_connect;
    conn.client_h1_state.version_1_0 = is_1_0;

    Ok(())
}

fn prepare_h1_response(conn: &mut Connection, header_bytes: &[u8]) -> Result<(), String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    let status = resp.parse(header_bytes).map_err(|e| format!("parse error: {}", e))?;
    if !matches!(status, Status::Complete(_)) {
        return Err("incomplete response headers".into());
    }

    let version = resp.version.unwrap_or(1);
    let status_code = resp.code.ok_or("missing status code")?;
    let reason = resp.reason.unwrap_or("OK");
    let mut keep_alive = !matches!(version, 0);
    let mut is_chunked = false;
    let mut content_len: Option<u64> = None;

    for h in resp.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        let value = std::str::from_utf8(h.value).unwrap_or("").trim();

        match name.as_str() {
            "connection" => {
                let lower = value.to_ascii_lowercase();
                if lower.contains("close") {
                    keep_alive = false;
                }
                if lower.contains("keep-alive") && version == 0 {
                    keep_alive = true;
                }
            }
            "proxy-connection" => keep_alive = false,
            "transfer-encoding" => {
                if value.to_ascii_lowercase().contains("chunked") {
                    is_chunked = true;
                }
            }
            "content-length" => {
                if let Ok(v) = value.parse::<u64>() {
                    content_len = Some(v);
                }
            }
            _ => {}
        }
    }

    if is_chunked {
        content_len = None;
    }

    let mut has_body = true;
    if (100..200).contains(&status_code) && status_code != 101 {
        has_body = false;
    }
    if status_code == 204 || status_code == 304 {
        has_body = false;
    }
    if conn.client_h1_state.is_head || conn.client_h1_state.is_connect {
        has_body = false;
    }

    if !has_body {
        content_len = Some(0);
        is_chunked = false;
    }

    let mut rewritten = Vec::with_capacity(header_bytes.len() + 32);
    let version_str = if version == 0 { "HTTP/1.0" } else { "HTTP/1.1" };
    rewritten.extend_from_slice(version_str.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(status_code.to_string().as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(reason.as_bytes());
    rewritten.extend_from_slice(b"\r\n");

    for h in resp.headers.iter() {
        let name = h.name;
        let lower = name.to_ascii_lowercase();
        if is_hop_by_hop(&lower) {
            continue;
        }
        if lower == "content-length" || lower == "transfer-encoding" {
            continue;
        }

        rewritten.extend_from_slice(name.as_bytes());
        rewritten.extend_from_slice(b": ");
        rewritten.extend_from_slice(h.value);
        rewritten.extend_from_slice(b"\r\n");
    }

    let conn_header = if keep_alive { "keep-alive" } else { "close" };
    rewritten.extend_from_slice(b"Connection: ");
    rewritten.extend_from_slice(conn_header.as_bytes());
    rewritten.extend_from_slice(b"\r\n");

    if has_body {
        if is_chunked {
            rewritten.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        } else if let Some(len) = content_len {
            rewritten.extend_from_slice(format!("Content-Length: {}\r\n", len).as_bytes());
        }
    }

    rewritten.extend_from_slice(b"\r\n");

    if rewritten.len() > conn.out_cap {
        return Err("response headers exceed buffer".into());
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            rewritten.as_ptr(),
            conn.out_buf.as_ptr(),
            rewritten.len(),
        );
    }
    conn.out_len = rewritten.len();

    conn.upstream_h1_state.parsed_headers = true;
    conn.upstream_h1_state.parsed_body = false;
    conn.upstream_h1_state.keep_alive = keep_alive;
    conn.upstream_h1_state.is_chunked = is_chunked;
    conn.upstream_h1_state.content_len = content_len;
    conn.upstream_h1_state.body_len = if is_chunked { Some(0) } else { content_len };
    conn.upstream_h1_state.version_1_0 = version == 0;

    Ok(())
}

struct H2Frame {
    length: usize,
    kind: u8,
    flags: u8,
    stream_id: u32,
}

fn parse_h2_frame_header(buf: &[u8]) -> H2Frame {
    let len = ((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | buf[2] as usize;
    let kind = buf[3];
    let flags = buf[4];
    let stream_id = ((buf[5] as u32 & 0x7F) << 24)
        | ((buf[6] as u32) << 16)
        | ((buf[7] as u32) << 8)
        | (buf[8] as u32);

    H2Frame {
        length: len,
        kind,
        flags,
        stream_id,
    }
}

fn build_h2_frame_header(len: usize, kind: u8, flags: u8, stream_id: u32) -> [u8; 9] {
    let length = len.min(0x00FF_FFFF);
    [
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
        kind,
        flags,
        ((stream_id >> 24) & 0x7F) as u8,
        ((stream_id >> 16) & 0xff) as u8,
        ((stream_id >> 8) & 0xff) as u8,
        (stream_id & 0xff) as u8,
    ]
}

fn consume_h2_frame(conn: &mut Connection, buf: &mut [u8], total: usize) {
    if conn.in_len > total {
        let remaining = conn.in_len - total;
        buf.copy_within(total..total + remaining, 0);
        conn.in_len = remaining;
    } else {
        conn.in_len = 0;
    }
}

async unsafe fn send_h2_goaway(
    conn: &mut Connection,
    last_stream_id: u32,
    error_code: u32,
    debug: &[u8],
) -> std::io::Result<()> {
    let mut payload = Vec::with_capacity(8 + debug.len());
    payload.extend_from_slice(&(last_stream_id & 0x7fff_ffff).to_be_bytes());
    payload.extend_from_slice(&error_code.to_be_bytes());
    payload.extend_from_slice(debug);

    let header = build_h2_frame_header(payload.len(), 0x7, 0, 0);
    let mut frame = Vec::with_capacity(header.len() + payload.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&payload);

    write_client_data(conn, &frame).await
}

async unsafe fn h2_connection_error(
    conn: &mut Connection,
    error_code: u32,
    reason: &str,
) -> NextStep {
    println!("[H2] Connection error {}: {}", error_code, reason);
    if let Err(e) = send_h2_goaway(conn, 0, error_code, reason.as_bytes()).await {
        println!("[H2] Failed to send GOAWAY: {}", e);
    }
    NextStep::Close
}

async unsafe fn send_h2_connect_response(
    conn: &mut Connection,
    stream_id: u32,
) -> std::io::Result<()> {
    // HEADERS frame with indexed static table entry :status 200 (0x88)
    let mut frame = Vec::with_capacity(10);
    frame.extend_from_slice(&build_h2_frame_header(1, 0x1, 0x4, stream_id));
    frame.push(0x88);
    write_client_data(conn, &frame).await
}

fn build_h2_data_frame(stream_id: u32, payload: &[u8], end_stream: bool) -> Vec<u8> {
    let len = payload.len().min(0x00FF_FFFF);
    let mut frame = Vec::with_capacity(9 + len);
    let flags = if end_stream { 0x1 } else { 0x0 };
    frame.extend_from_slice(&build_h2_frame_header(len, 0x0, flags, stream_id));
    frame.extend_from_slice(&payload[..len]);
    frame
}

async unsafe fn wait_client_transport_readable(conn: &Connection) -> std::io::Result<()> {
    if let Some(ptr) = conn.client_tls {
        (*ptr).get_ref().0.readable().await
    } else if let Some(ptr) = conn.client_tcp {
        (*ptr).readable().await
    } else {
        Err(Error::new(ErrorKind::NotConnected, "client transport missing"))
    }
}

async unsafe fn wait_upstream_transport_readable(conn: &Connection) -> std::io::Result<()> {
    if let Some(ptr) = conn.upstream_tls {
        (*ptr).get_ref().0.readable().await
    } else if let Some(ptr) = conn.upstream_tcp {
        (*ptr).readable().await
    } else {
        Err(Error::new(
            ErrorKind::NotConnected,
            "upstream transport missing",
        ))
    }
}

async unsafe fn h2_connect_forward_upstream(
    conn: &mut Connection,
    stream_id: u32,
    buf: &mut [u8],
) -> NextStep {
    if !conn.connect_response_sent {
        if let Err(e) = send_h2_connect_response(conn, stream_id).await {
            println!("[H2] Failed to send CONNECT response before upstream data: {}", e);
            return NextStep::Close;
        }
        conn.connect_response_sent = true;
    }

    let n = match read_upstream_data(conn, buf).await {
        Ok(n) => n,
        Err(e) => {
            println!("[H2] Upstream read error: {}", e);
            return NextStep::Close;
        }
    };
    conn.in_len = 0;
    println!("[H2] CONNECT upstream read {} bytes", n);

    if n == 0 {
        let end_frame = build_h2_data_frame(stream_id, &[], true);
        let _ = write_client_data(conn, &end_frame).await;
        println!("[H2] Upstream closed; sent END_STREAM for CONNECT");
        return NextStep::Close;
    }

    let mut offset = 0;
    while offset < n {
        let chunk = std::cmp::min(H2_DEFAULT_MAX_FRAME_SIZE, n - offset);
        let frame = build_h2_data_frame(stream_id, &buf[offset..offset + chunk], false);
        if let Err(e) = write_client_data(conn, &frame).await {
            println!("[H2] Upstream->client write failed: {}", e);
            return NextStep::Close;
        }
        println!(
            "[H2] Forwarded {} bytes upstream->client on CONNECT stream {}",
            chunk, stream_id
        );
        offset += chunk;
    }

    NextStep::Continue(ProxyState::H2(H2State::Proxy(
        H2ProxyState::ProxyFramesClientToUpstream,
    )))
}

fn reset_h1_session(sess: &mut H1Session) {
    sess.headers_count = None;
    sess.body_len = None;
    sess.parsed_headers = false;
    sess.parsed_body = false;
    sess.content_len = None;
    sess.is_chunked = false;
    sess.keep_alive = false;
    sess.chunk_remaining = 0;
    sess.expect_continue = false;
    sess.is_head = false;
    sess.is_connect = false;
    sess.version_1_0 = false;
}

fn try_reuse_upstream(conn: &mut Connection) -> bool {
    let target = conn.target().cloned();
    let needed_tls = conn.upstream_tls_required;
    target
        .map(|t| conn.take_pooled_upstream(&t, needed_tls))
        .unwrap_or(false)
}

pub async unsafe fn intercept_handler(_: &mut Connection, _: InterceptState) -> NextStep {
    println!("[INTERCEPT] Not implemented");
    NextStep::Close
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::Connection;
    use crate::fsm::NextStep;
    use crate::states::{
        H2ConnBootstrapState, H2FlowControlState, H2FrameParseState, H2ProxyState, H2State,
        H3ControlState, H3ForwardState, H3QpackState, H3RequestParseState, H3State, ProxyState,
        UpstreamDnsState, UpstreamState,
    };
    use std::error::Error;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    async fn tcp_pair() -> Result<(TcpStream, TcpStream), Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let client = TcpStream::connect(addr).await?;
        let (server, _) = listener.accept().await?;
        Ok((client, server))
    }

    fn build_h2_frame(payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut frame = vec![
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
            0x0,
            0x1,
            0x00,
            0x00,
            0x00,
            0x01,
        ];
        frame.extend_from_slice(payload);
        frame
    }

    #[tokio::test]
    async fn h2_handler_flows() -> Result<(), Box<dyn Error>> {
        let (tx, rx) = mpsc::unbounded_channel();

        let (client_stream, mut client_peer) = tcp_pair().await?;
        let (upstream_stream, mut upstream_peer) = tcp_pair().await?;

        let client_ptr = Box::into_raw(Box::new(client_stream));
        let mut conn = Connection::new_tcp_raw(client_ptr, tx, rx);
        let upstream_ptr = Box::into_raw(Box::new(upstream_stream));
        conn.upstream_tcp = Some(upstream_ptr);

        let preface = b"PRI * HTTP/2.0

SM

";
        client_peer.write_all(preface).await?;
        let step = unsafe {
            h2_handler(
                &mut conn,
                H2State::Bootstrap(H2ConnBootstrapState::ClientPreface),
            )
            .await
        };
        assert!(matches!(
            step,
            NextStep::Continue(ProxyState::H2(H2State::Bootstrap(
                H2ConnBootstrapState::RecvClientSettings
            )))
        ));

        let settings = b"       ";
        client_peer.write_all(settings).await?;
        let step = unsafe {
            h2_handler(
                &mut conn,
                H2State::Bootstrap(H2ConnBootstrapState::RecvClientSettings),
            )
            .await
        };
        assert!(matches!(
            step,
            NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                H2FrameParseState::RecvFrameHeader
            )))
        ));

        let payload = b"client->upstream";
        let frame = build_h2_frame(payload);
        client_peer.write_all(&frame).await?;

        let step = unsafe {
            h2_handler(
                &mut conn,
                H2State::FrameParse(H2FrameParseState::RecvFrameHeader),
            )
            .await
        };
        assert!(matches!(
            step,
            NextStep::Continue(ProxyState::H2(H2State::FlowControl(
                H2FlowControlState::FlowControlWaitWindowUpdate
            )))
        ));

        let step = unsafe {
            h2_handler(
                &mut conn,
                H2State::FlowControl(H2FlowControlState::FlowControlWaitWindowUpdate),
            )
            .await
        };
        assert!(matches!(
            step,
            NextStep::Continue(ProxyState::H2(H2State::Proxy(
                H2ProxyState::ProxyFramesClientToUpstream
            )))
        ));
        assert_eq!(
            conn.next_state_after_upstream,
            Some(ProxyState::H2(H2State::Proxy(
                H2ProxyState::ProxyFramesClientToUpstream
            )))
        );

        let step = unsafe {
            h2_handler(
                &mut conn,
                H2State::Proxy(H2ProxyState::ProxyFramesClientToUpstream),
            )
            .await
        };
        assert!(matches!(
            step,
            NextStep::Continue(ProxyState::H2(H2State::Proxy(
                H2ProxyState::ProxyFramesUpstreamToClient
            )))
        ));

        let mut forwarded = vec![0u8; frame.len()];
        upstream_peer.read_exact(&mut forwarded).await?;
        assert_eq!(forwarded, frame);

        let upstream_payload = b"upstream->client";
        upstream_peer.write_all(upstream_payload).await?;
        let step = unsafe {
            h2_handler(
                &mut conn,
                H2State::Proxy(H2ProxyState::ProxyFramesUpstreamToClient),
            )
            .await
        };
        assert!(matches!(
            step,
            NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                H2FrameParseState::RecvFrameHeader
            )))
        ));

        let mut received = vec![0u8; upstream_payload.len()];
        client_peer.read_exact(&mut received).await?;
        assert_eq!(received, upstream_payload);

        unsafe {
            if let Some(ptr) = conn.client_tcp.take() {
                drop(Box::from_raw(ptr));
            }
            if let Some(ptr) = conn.upstream_tcp.take() {
                drop(Box::from_raw(ptr));
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn h2_connect_allows_control_frames() -> Result<(), Box<dyn Error>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let (client_stream, mut client_peer) = tcp_pair().await?;
        let client_ptr = Box::into_raw(Box::new(client_stream));
        let mut conn = Connection::new_tcp_raw(client_ptr, tx, rx);
        conn.h2_connect_stream_id = Some(1);
        conn.connect_response_sent = true;

        let settings_ack = build_h2_frame_header(0, 0x4, 0x1, 0);
        client_peer.write_all(&settings_ack).await?;

        let step = unsafe {
            h2_handler(
                &mut conn,
                H2State::Proxy(H2ProxyState::ProxyFramesClientToUpstream),
            )
            .await
        };

        assert!(matches!(
            step,
            NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                H2FrameParseState::RecvFrameHeader
            )))
        ));
        assert_eq!(conn.in_len, 0);

        unsafe {
            if let Some(ptr) = conn.client_tcp.take() {
                drop(Box::from_raw(ptr));
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn h2_connect_replies_to_ping() -> Result<(), Box<dyn Error>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let (client_stream, mut client_peer) = tcp_pair().await?;
        let client_ptr = Box::into_raw(Box::new(client_stream));
        let mut conn = Connection::new_tcp_raw(client_ptr, tx, rx);
        conn.h2_connect_stream_id = Some(1);
        conn.connect_response_sent = true;

        let mut ping = Vec::new();
        let ping_payload = [1u8, 2, 3, 4, 5, 6, 7, 8];
        ping.extend_from_slice(&build_h2_frame_header(8, 0x6, 0x0, 0));
        ping.extend_from_slice(&ping_payload);
        client_peer.write_all(&ping).await?;

        let step = unsafe {
            h2_handler(
                &mut conn,
                H2State::Proxy(H2ProxyState::ProxyFramesClientToUpstream),
            )
            .await
        };

        assert!(matches!(
            step,
            NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                H2FrameParseState::RecvFrameHeader
            )))
        ));

        let mut ack = vec![0u8; 17];
        client_peer.read_exact(&mut ack).await?;
        let mut expected = Vec::new();
        expected.extend_from_slice(&build_h2_frame_header(8, 0x6, 0x1, 0));
        expected.extend_from_slice(&ping_payload);
        assert_eq!(ack, expected);
        assert_eq!(conn.in_len, 0);

        unsafe {
            if let Some(ptr) = conn.client_tcp.take() {
                drop(Box::from_raw(ptr));
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn h3_handler_flows() -> Result<(), Box<dyn Error>> {
        let (tx, rx) = mpsc::unbounded_channel();

        let (client_stream, mut client_peer) = tcp_pair().await?;
        let (upstream_stream, mut upstream_peer) = tcp_pair().await?;

        let client_ptr = Box::into_raw(Box::new(client_stream));
        let mut conn = Connection::new_tcp_raw(client_ptr, tx, rx);
        let upstream_ptr = Box::into_raw(Box::new(upstream_stream));
        conn.upstream_tcp = Some(upstream_ptr);

        let control_payload = b"h3-control";
        client_peer.write_all(control_payload).await?;
        let step = unsafe {
            h3_handler(
                &mut conn,
                H3State::Control(H3ControlState::ControlStreamSetup),
            )
            .await
        };
        assert!(matches!(
            step,
            NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                UpstreamDnsState::ResolveStart
            )))
        ));
        assert_eq!(
            conn.next_state_after_upstream,
            Some(ProxyState::H3(H3State::RequestParse(
                H3RequestParseState::RecvHeaders
            )))
        );

        let h3_headers = b"h3-headers";
        client_peer.write_all(h3_headers).await?;
        let step = unsafe {
            h3_handler(
                &mut conn,
                H3State::RequestParse(H3RequestParseState::RecvHeaders),
            )
            .await
        };
        assert!(matches!(
            step,
            NextStep::Continue(ProxyState::H3(H3State::Qpack(
                H3QpackState::QpackDecodeHeaders
            )))
        ));

        let step = unsafe {
            h3_handler(&mut conn, H3State::Qpack(H3QpackState::QpackDecodeHeaders)).await
        };
        assert!(matches!(
            step,
            NextStep::Continue(ProxyState::H3(H3State::Forward(
                H3ForwardState::ForwardHeaders
            )))
        ));

        let mut forwarded = vec![0u8; h3_headers.len()];
        upstream_peer.read_exact(&mut forwarded).await?;
        assert_eq!(forwarded, h3_headers);

        let h3_body = b"h3-body";
        upstream_peer.write_all(h3_body).await?;
        let step =
            unsafe { h3_handler(&mut conn, H3State::Forward(H3ForwardState::ForwardBody)).await };
        assert!(matches!(
            step,
            NextStep::Continue(ProxyState::H3(H3State::RequestParse(
                H3RequestParseState::RecvHeaders
            )))
        ));

        let mut received = vec![0u8; h3_body.len()];
        client_peer.read_exact(&mut received).await?;
        assert_eq!(received, h3_body);

        unsafe {
            if let Some(ptr) = conn.client_tcp.take() {
                drop(Box::from_raw(ptr));
            }
            if let Some(ptr) = conn.upstream_tcp.take() {
                drop(Box::from_raw(ptr));
            }
        }

        Ok(())
    }
}
