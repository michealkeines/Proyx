use std::sync::Arc;

use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::{
    rustls::{ClientConfig, RootCertStore},
    TlsConnector,
};
use webpki_roots::TLS_SERVER_ROOTS;

use crate::{
    connection::Connection,
    fsm::NextStep,
    states::{
        H1ForwardState, H1State, ProxyState, UpstreamDnsState, UpstreamState, UpstreamTcpState,
        UpstreamTlsState,
    },
};

pub async unsafe fn upstream_handler(conn: &mut Connection, s: UpstreamState) -> NextStep {
    println!("[UPSTREAM] {:?}", s);

    match s {
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

            let mut roots = RootCertStore::empty();
            let der_bytes = std::fs::read("/Users/michealkeines/Proyx/src/CA/root.der").unwrap();
            roots.add(rustls_pki_types::CertificateDer::from(der_bytes)).unwrap();
            roots.extend(TLS_SERVER_ROOTS.iter().cloned());

            let mut cfg = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

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
