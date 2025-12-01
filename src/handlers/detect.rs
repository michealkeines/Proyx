use tokio::io::AsyncReadExt;

use crate::{
    connection::Connection,
    fsm::NextStep,
    states::{
        DetectBootstrapState, DetectState, H1ConnectState, H1RequestParseState, H1State,
        ProxyState, TlsHandshakeState, TlsState,
    },
};

use super::shared::looks_like_http1;

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

            if slice.starts_with(b"CONNECT ") {
                println!("[DETECT] CONNECT request detected");

                return NextStep::Continue(ProxyState::H1(H1State::Connect(
                    H1ConnectState::ConnectTunnelEstablished,
                )));
            }

            if slice.len() > 5 && slice[0] == 0x16 && slice[1] == 0x03 {
                println!("[DETECT] TLS ClientHello detected");

                return NextStep::Continue(ProxyState::Tls(TlsState::Handshake(
                    TlsHandshakeState::HandshakeBegin,
                )));
            }

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
