use std::sync::Arc;

use crate::{connection::Connection, fsm::NextStep, states::*};

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

use crate::connection::{ReadEnum, WriteEnum};

pub async unsafe fn transport_handler(conn: &mut Connection, s: TransportState) -> NextStep {
    println!("[TRANSPORT] {:?}", s);

    match s {
        TransportState::Conn(state) => match state {
            TransportConnState::AcceptClientConnection => {
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

            let reader: &mut (dyn AsyncRead + Unpin) = if let Some(ptr) = conn.client_tls {
                &mut *(ptr as *mut TlsStream<TcpStream>)
            } else {
                &mut *(conn.client_tcp.unwrap() as *mut TcpStream)
            };

            let mut buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);

            let n = match reader.read(buf).await {
                Ok(0) => {
                    println!("[H1] Req body EOF");
                    return NextStep::Continue(ProxyState::H1(H1State::Forward(
                        H1ForwardState::UpstreamRecvHeaders,
                    )));
                }
                Ok(n) => n,
                Err(e) => {
                    println!("[H1] Req body read error: {}", e);
                    return NextStep::Close;
                }
            };

            if let Some(ptr) = conn.upstream_tls {
                let mut a = (conn.upstream_tls.unwrap());
                if let Err(e) = (*a).write_all(&buf[..n]).await {
                    println!("[H1]  Req body write error: {}", e);
                    return NextStep::Close;
                }
            } else {
                let mut a = (conn.upstream_tcp.unwrap());
                if let Err(e) = (*a).write_all(&buf[..n]).await {
                    println!("[H1]  Req body write error: {}", e);
                    return NextStep::Close;
                }
            };

            NextStep::Continue(ProxyState::H1(H1State::Forward(
                H1ForwardState::ForwardRequestBody,
            )))
        }

        //--------------------------------------------------------------
        // UPSTREAM RECV RESPONSE HEADERS
        //--------------------------------------------------------------
        H1State::Forward(H1ForwardState::UpstreamRecvHeaders) => {
            println!("[H1] UpstreamRecvHeaders");

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
            println!("[UPSTREAM] Connecting TCP 142.250.74.4:443");

            match TcpStream::connect("142.250.74.4:443").await {
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
            println!("[UPSTREAM] Upstream TLS handshake");

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

            let domain = "www.google.com".try_into().unwrap();

            match connector.connect(domain, *tcp).await {
                Ok(tls) => {
                    conn.upstream_tls = Some(Box::into_raw(Box::new(tls)));
                    println!("TLS upstream done");
                    conn.upstream_tcp = None;

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

pub async unsafe fn h2_handler(_: &mut Connection, _: H2State) -> NextStep {
    println!("[H2] Not implemented");
    NextStep::Close
}

pub async unsafe fn h3_handler(_: &mut Connection, _: H3State) -> NextStep {
    println!("[H3] Not implemented");
    NextStep::Close
}

pub async unsafe fn intercept_handler(_: &mut Connection, _: InterceptState) -> NextStep {
    println!("[INTERCEPT] Not implemented");
    NextStep::Close
}
