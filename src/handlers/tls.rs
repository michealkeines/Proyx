use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig, server::TlsStream as ServerTlsStream};

use crate::{
    config::CONFIG,
    connection::{Connection, ReadEnum, WriteEnum},
    controller::ControllerMsg,
    fsm::NextStep,
    states::*,
};

use crate::CA::helpers::build_fake_cert_for_domain;

pub async unsafe fn tls_handler(conn: &mut Connection, s: TlsState) -> NextStep {
    println!("[TLS] {:?}", s);

    match s {
        TlsState::Handshake(TlsHandshakeState::HandshakeBegin) => {
            println!("[TLS] HandshakeBegin → MITM certificate generation");
            println!(
                "[TLS] HandshakeBegin sockets: tcp_present={} tls_present={} mitm_present={}",
                conn.client_tcp.is_some(),
                conn.client_tls.is_some(),
                conn.client_mitm_tls.is_some()
            );

            conn.in_len = 0;

            debug_assert!(
                conn.client_tcp.is_some(),
                "TLS handshake begin requires client TCP stream"
            );

            let sni = conn
                .target()
                .map(|t| t.host.clone())
                .unwrap_or_else(|| "localhost".to_string());
            println!("[TLS] Extracted SNI = {}", sni);

            let (leaf_cert, leaf_key) = build_fake_cert_for_domain(&sni);

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

        TlsState::Handshake(TlsHandshakeState::HandshakeRead) => {
            println!("[TLS] Accepting TLS handshake");
            println!(
                "[TLS] HandshakeRead streams: tcp_present={} tls_present={} mitm_present={}",
                conn.client_tcp.is_some(),
                conn.client_tls.is_some(),
                conn.client_mitm_tls.is_some()
            );

            let mut acceptor: &mut TlsAcceptor = &mut *(conn.scratch as *mut TlsAcceptor);

            if let Some(tcp_ptr) = conn.client_tcp.take() {
                println!("[TLS] Handshake using raw client TCP");
                let tcp_box: Box<TcpStream> = Box::from_raw(tcp_ptr);

                match acceptor.accept(*tcp_box).await {
                    Ok(tls_stream) => {
                        conn.client_tls = Some(Box::into_raw(Box::new(tls_stream)));
                    }
                    Err(e) => {
                        println!("[TLS] Handshake error: {}", e);
                        return NextStep::Close;
                    }
                }
            } else if let Some(tls_ptr) = conn.client_tls.take() {
                println!("[TLS] Handshake using existing client TLS (nested MITM inside CONNECT)");
                let tls_box: Box<ServerTlsStream<TcpStream>> = Box::from_raw(tls_ptr);

                match acceptor.accept(*tls_box).await {
                    Ok(nested_tls) => {
                        conn.client_mitm_tls = Some(Box::into_raw(Box::new(nested_tls)));
                    }
                    Err(e) => {
                        println!("[TLS] Nested handshake error: {}", e);
                        return NextStep::Close;
                    }
                }
            } else {
                if conn.client_mitm_tls.is_some() {
                    println!("[TLS] HandshakeRead found existing MITM TLS, skipping accept");
                    return NextStep::Continue(ProxyState::Tls(TlsState::Handshake(
                        TlsHandshakeState::HandshakeComplete,
                    )));
                }
                println!("[TLS] Missing client stream during handshake");
                return NextStep::Close;
            }

            return NextStep::Continue(ProxyState::Tls(TlsState::Handshake(
                TlsHandshakeState::HandshakeComplete,
            )));
        }

        TlsState::Handshake(TlsHandshakeState::HandshakeComplete) => {
            println!("[TLS] Client TLS Handshake Complete");
            conn.in_len = 0;

            if let Some(ptr) = conn.client_mitm_tls {
                let tls_stream = &*ptr;
                let (_, server_conn) = tls_stream.get_ref();
                if let Some(proto) = server_conn.alpn_protocol() {
                    conn.negotiated_alpn = Some(String::from_utf8_lossy(proto).to_string());
                }
                conn.readable = Some(ReadEnum::SeverTlsNested(ptr));
                conn.writable = Some(WriteEnum::SeverTlsNested(ptr));
            } else if let Some(ptr) = conn.client_tls {
                let tls_stream = &*ptr;
                let (_, server_conn) = tls_stream.get_ref();
                if let Some(proto) = server_conn.alpn_protocol() {
                    conn.negotiated_alpn = Some(String::from_utf8_lossy(proto).to_string());
                }
                conn.readable = Some(ReadEnum::SeverTls(ptr));
                conn.writable = Some(WriteEnum::SeverTls(ptr));
            }

            unsafe {
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
