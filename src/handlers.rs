use std::io::{Error, ErrorKind};
use std::sync::Arc;

use httparse::{Request, Status};
use rustls_pki_types::ServerName;

use crate::{
    connection::{Connection, ReadEnum, WriteEnum},
    fsm::NextStep,
    states::*,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
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

            // HTTP/1
            if slice.starts_with(b"GET ")
                || slice.starts_with(b"POST ")
                || slice.starts_with(b"HEAD ")
            {
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
            let server_cfg = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![leaf_cert], leaf_key)
                .unwrap();

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

            unsafe {
                conn.fill_target_from_tls_sni(443);
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
            println!("[H1] CONNECT: returning 200");

            let tcp = conn.client_tcp.unwrap();
            let _ = (*tcp)
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await;

            return NextStep::Continue(ProxyState::Tls(TlsState::Handshake(
                TlsHandshakeState::HandshakeBegin,
            )));
        }

        // -----------------------------------------------------------
        // Begin reading request headers (TLS or plaintext)
        // -----------------------------------------------------------
        H1State::Request(H1RequestParseState::RecvHeaders) => {
            println!("[H1] RecvHeaders");

            debug_assert!(
                conn.client_tls.is_some(),
                "[H1] Request RecvHeaders expects TLS stream"
            );

            // Decide which reader to use
            let mut_reader = conn.client_tls.unwrap();
            println!("[H1] RecvHeaders1");
            let mut buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);

            println!("[H1] RecvHeaders2");
            let n = match (*mut_reader).read(buf).await {
                Ok(n) if n > 0 => {
                    conn.in_len = n;
                    println!("[H1] Read {} bytes", n);
                    n
                }
                _ => return NextStep::Close,
            };

            if twoway::find_bytes(&buf[..n], b"\r\n\r\n").is_some() {
                println!("[H1] Headers complete");

                debug_assert!(
                    conn.next_state_after_upstream.is_none(),
                    "[H1] next_state_after_upstream should not be set before headers complete"
                );
                if let Some((host, port)) = parse_host_header(&buf[..n], 443) {
                    conn.set_target(host, port);
                }
                conn.next_state_after_upstream = Some(ProxyState::H1(H1State::Forward(
                    H1ForwardState::ForwardRequestHeaders,
                )));
                return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                    UpstreamDnsState::ResolveStart,
                )));
            }

            return NextStep::WaitRead(ProxyState::H1(H1State::Request(
                H1RequestParseState::RecvHeaders,
            )));
        }

        //--------------------------------------------------------------
        // FORWARD REQUEST HEADERS (client → upstream)
        //--------------------------------------------------------------
        H1State::Forward(H1ForwardState::ForwardRequestHeaders) => {
            println!("[H1] ForwardRequestHeaders");

            let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);

            let n = conn.in_len;
            println!("[H1] Req headers read {:?} bytes", n);

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

            // End of request headers?
            if twoway::find_bytes(&buf[..n], b"\r\n\r\n").is_some() {
                println!("[H1] Request headers complete");
                return NextStep::Continue(ProxyState::H1(H1State::Forward(
                    H1ForwardState::ForwardRequestBody,
                )));
            }

            // continue collecting headers
            NextStep::Continue(ProxyState::H1(H1State::Forward(
                H1ForwardState::ForwardRequestHeaders,
            )))
        }

        //--------------------------------------------------------------
        // FORWARD REQUEST BODY (client → upstream)
        //--------------------------------------------------------------
        H1State::Forward(H1ForwardState::ForwardRequestBody) => {
            println!("[H1] ForwardRequestBody");

            let mut n: usize = conn.in_len;
            let mut buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);

            debug_assert!(
                conn.upstream_tcp.is_some() || conn.upstream_tls.is_some(),
                "[H1] ForwardRequestBody needs upstream transport ready"
            );

            // if let Some(ptr) = conn.client_tls {
            //     n = match (*(conn.client_tls.unwrap())).read(buf).await {
            //         Ok(0) => {
            //             println!("[H1] Req body EOF");
            //             return NextStep::Continue(ProxyState::H1(H1State::Forward(
            //                 H1ForwardState::UpstreamRecvHeaders,
            //             )));
            //         }
            //         Ok(n) => n,
            //         Err(e) => {
            //             println!("[H1] Req body read error: {}", e);
            //             return NextStep::Close;
            //         }
            //     };
            // } else {
            //     n = match (*(conn.client_tcp.unwrap())).read(buf).await {
            //         Ok(0) => {
            //             println!("[H1] Req body EOF");
            //             return NextStep::Continue(ProxyState::H1(H1State::Forward(
            //                 H1ForwardState::UpstreamRecvHeaders,
            //             )));
            //         }
            //         Ok(n) => n,
            //         Err(e) => {
            //             println!("[H1] Req body read error: {}", e);
            //             return NextStep::Close;
            //         }
            //     };
            // };

            if let Some(ptr) = conn.upstream_tls {
                let mut a = (conn.upstream_tls.unwrap());
                if let Err(e) = (*a).write_all(&buf[n..]).await {
                    println!("[H1]  Req body write error: {}", e);
                    return NextStep::Close;
                }
            } else {
                let mut a = (conn.upstream_tcp.unwrap());
                if let Err(e) = (*a).write_all(&buf[n..]).await {
                    println!("[H1]  Req body write error: {}", e);
                    return NextStep::Close;
                }
            };

            NextStep::Continue(ProxyState::H1(H1State::Forward(
                H1ForwardState::UpstreamRecvHeaders,
            )))
        }

        //--------------------------------------------------------------
        // UPSTREAM RECV RESPONSE HEADERS
        //--------------------------------------------------------------
        H1State::Forward(H1ForwardState::UpstreamRecvHeaders) => {
            println!("[H1] UpstreamRecvHeaders");

            debug_assert!(
                conn.upstream_tcp.is_some() || conn.upstream_tls.is_some(),
                "[H1] UpstreamRecvHeaders requires upstream connection"
            );

            let reader: &mut (dyn AsyncRead + Unpin) = if let Some(ptr) = conn.upstream_tls {
                &mut *(ptr as *mut TlsStream<TcpStream>)
            } else {
                &mut *(conn.upstream_tcp.unwrap() as *mut TcpStream)
            };

            let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);

            let n = match reader.read(buf).await {
                Ok(n) if n > 0 => n,
                _ => return NextStep::Close,
            };

            println!("[H1] Upstream response headers {} bytes", n);
            conn.in_len = n;
            if twoway::find_bytes(buf, b"\r\n\r\n").is_some() {
                return NextStep::Continue(ProxyState::H1(H1State::Forward(
                    H1ForwardState::SendResponseHeadersToClient,
                )));
            }

            return NextStep::Continue(ProxyState::H1(H1State::Forward(
                H1ForwardState::UpstreamRecvHeaders,
            )));
        }

        //--------------------------------------------------------------
        // SEND RESPONSE HEADERS TO CLIENT
        //--------------------------------------------------------------
        H1State::Forward(H1ForwardState::SendResponseHeadersToClient) => {
            println!("[H1] SendResponseHeadersToClient");

            let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);

            let n = conn.in_len;
            debug_assert!(
                conn.client_tls.is_some() || conn.client_tcp.is_some(),
                "[H1] SendResponseHeadersToClient needs a client stream"
            );
            if let Some(ptr) = conn.client_tls {
                let mut a = (conn.client_tls.unwrap());
                if let Err(e) = (*a).write_all(&buf[..n]).await {
                    println!("[H1]  Req body write error: {}", e);
                    return NextStep::Close;
                }
            } else {
                let mut a = (conn.client_tcp.unwrap());
                if let Err(e) = (*a).write_all(&buf[..n]).await {
                    println!("[H1]  Req body write error: {}", e);
                    return NextStep::Close;
                }
            };

            // Check if headers ended
            if twoway::find_bytes(buf, b"\r\n\r\n").is_some() {
                return NextStep::Continue(ProxyState::H1(H1State::Forward(
                    H1ForwardState::UpstreamRecvBody,
                )));
            }

            NextStep::Close
        }

        //--------------------------------------------------------------
        // READ RESPONSE BODY FROM UPSTREAM
        //--------------------------------------------------------------
        H1State::Forward(H1ForwardState::UpstreamRecvBody) => {
            println!("[H1] UpstreamRecvBody");
            let mut buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);
            let mut v = 0;

            if let Some(ptr) = conn.upstream_tls {
                v = match (*(conn.upstream_tls.unwrap()))
                    .read(&mut buf[conn.in_len..])
                    .await
                {
                    Ok(0) => {
                        println!("[H1] Upstream body EOF");
                        return NextStep::Close;
                    }
                    Ok(n) => {
                        conn.in_len += n;
                        n
                    }
                    Err(e) => {
                        let err_str = e.to_string();

                        if err_str
                            .contains("peer closed connection without sending TLS close_notify")
                            || err_str.contains("UnexpectedEof")
                        {
                            // Treat as normal EOF
                            println!("[H1] Upstream body EOF (TLS no close_notify)");
                            return NextStep::Close;
                        }

                        println!("[H1] Resp body1 read error: {}", e);
                        return NextStep::Close;
                    }
                };
            } else {
                match (*(conn.upstream_tcp.unwrap())).read(buf).await {
                    Ok(0) => {
                        println!("[H1] Upstream body EOF");
                        return NextStep::Close;
                    }
                    Ok(n) => {
                        conn.out_len = n;
                        n
                    }
                    Err(e) => {
                        println!("[H1] Resp body read error: {}", e);
                        return NextStep::Close;
                    }
                };
            }

            println!(
                "[H1] BUffer written: {}/{}\n{:?}",
                conn.in_len,
                buf.len(),
                String::from_utf8(buf[..conn.in_len].to_vec()).unwrap()
            );

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
            println!(
                "[H1] BUffer read: {}/{}\n{:?}",
                conn.in_len,
                buf.len(),
                String::from_utf8(buf[..conn.in_len].to_vec()).unwrap()
            );

            let n = conn.in_len;
            debug_assert!(
                conn.client_tls.is_some() || conn.client_tcp.is_some(),
                "[H1] SendResponseBodyToClient needs a client stream"
            );
            if let Some(ptr) = conn.client_tls {
                let mut a = (conn.client_tls.unwrap());
                if let Err(e) = (*a).write_all(&buf[..n]).await {
                    println!("[H1]  Res body1 write error: {}", e);
                    return NextStep::Close;
                }
            } else {
                let mut a = (conn.client_tcp.unwrap());
                if let Err(e) = (*a).write_all(&buf[..n]).await {
                    println!("[H1]  Res body write error: {}", e);
                    return NextStep::Close;
                }
            };

            // Continue body pump
            return NextStep::Continue(ProxyState::H1(H1State::Forward(
                H1ForwardState::UpstreamRecvBody,
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
                    return NextStep::Continue(ProxyState::Upstream(UpstreamState::Tls(
                        UpstreamTlsState::TlsHandshakeBegin,
                    )));
                }
                Err(_) => return NextStep::Close,
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
            match read_client_data(conn, buf).await {
                Ok(n) if n > 0 => {
                    conn.in_len = n;
                    println!("[H2] Client preface {} bytes", n);
                    return NextStep::Continue(ProxyState::H2(H2State::Bootstrap(
                        H2ConnBootstrapState::RecvClientSettings,
                    )));
                }
                _ => return NextStep::Close,
            }
        }

        H2State::Bootstrap(H2ConnBootstrapState::RecvClientSettings) => {
            match read_client_data(conn, buf).await {
                Ok(n) if n > 0 => {
                    conn.in_len = n;
                    println!("[H2] Client settings {} bytes", n);
                    conn.next_state_after_upstream = Some(ProxyState::H2(H2State::FrameParse(
                        H2FrameParseState::RecvFrameHeader,
                    )));
                    return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                        UpstreamDnsState::ResolveStart,
                    )));
                }
                _ => return NextStep::Close,
            }
        }

        H2State::FrameParse(H2FrameParseState::RecvFrameHeader) => {
            let n = match read_client_data(conn, buf).await {
                Ok(n) if n > 0 => n,
                Ok(_) => {
                    println!("[H2] Client closed during frame header");
                    return NextStep::Close;
                }
                Err(e) => {
                    println!("[H2] Frame header read error: {}", e);
                    return NextStep::Close;
                }
            };

            conn.in_len = n;

            if n < 9 {
                println!("[H2] Incomplete frame header");
                return NextStep::Close;
            }

            let frame = parse_h2_frame_header(&buf[..n]);
            println!(
                "[H2] Frame parsed len={} type={} flags=0x{:02x} stream={}",
                frame.length, frame.kind, frame.flags, frame.stream_id
            );

            conn.scratch = frame.length as u64;

            return NextStep::Continue(ProxyState::H2(H2State::FlowControl(
                H2FlowControlState::FlowControlWaitWindowUpdate,
            )));
        }

        H2State::FlowControl(H2FlowControlState::FlowControlWaitWindowUpdate) => {
            let payload_len = conn.scratch as usize;
            if payload_len + 9 > conn.in_len {
                println!(
                    "[H2] Frame payload truncated (expected {} + 9, got {})",
                    payload_len, conn.in_len
                );
                return NextStep::Close;
            }

            println!(
                "[H2] Flow-control check for payload {} bytes (window update pending)",
                payload_len
            );

            return NextStep::Continue(ProxyState::H2(H2State::Proxy(
                H2ProxyState::ProxyFramesClientToUpstream,
            )));
        }

        H2State::Proxy(H2ProxyState::ProxyFramesClientToUpstream) => {
            let n = conn.in_len;
            if let Err(e) = write_upstream_data(conn, &buf[..n]).await {
                println!("[H2] Client->upstream write failed: {}", e);
                return NextStep::Close;
            }

            return NextStep::Continue(ProxyState::H2(H2State::Proxy(
                H2ProxyState::ProxyFramesUpstreamToClient,
            )));
        }

        H2State::Proxy(H2ProxyState::ProxyFramesUpstreamToClient) => {
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
            NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                UpstreamDnsState::ResolveStart
            )))
        ));
        assert_eq!(
            conn.next_state_after_upstream,
            Some(ProxyState::H2(H2State::FrameParse(
                H2FrameParseState::RecvFrameHeader
            )))
        );

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
