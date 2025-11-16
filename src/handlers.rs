use std::net::{Ipv4Addr, ToSocketAddrs};

use crate::{
    connection::Connection,
    fsm::NextStep,
    states::*,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, unix::SocketAddr},
};



// ========================================================================
// Utility for raw-pointer TCP access
// ========================================================================

#[inline]
unsafe fn tcp_mut(ptr: Option<*const TcpStream>) -> Option<&'static mut TcpStream> {
    match ptr {
        Some(p) if !p.is_null() => Some(&mut *(p as *mut TcpStream)),
        _ => None,
    }
}

#[inline]
unsafe fn tcp_ref(ptr: Option<*const TcpStream>) -> Option<&'static TcpStream> {
    match ptr {
        Some(p) if !p.is_null() => Some(&*(p)),
        _ => None,
    }
}



// ========================================================================
//  TRANSPORT HANDLER
// ========================================================================
pub async unsafe fn transport_handler(conn: &mut Connection, s: TransportState) -> NextStep {
    match s {
        TransportState::Conn(state) => match state {

            TransportConnState::AcceptClientConnection => {
                // TCP clients → wait for data
                if conn.client_tcp.is_some() && conn.is_reabable == false {
                    println!("we have a new connection, upateing to wait client read");
                    return NextStep::WaitClientRead;
                }

                if (conn.is_reabable) {
                    conn.is_reabable = false;
                } 

                // QUIC clients already have packet in in_buf
                return NextStep::Continue(ProxyState::Detect(
                    DetectState::Bootstrap(DetectBootstrapState::DetectProtocolBegin)
                ));
            }

            TransportConnState::ClientTcpHandshake => {
                // No SSL/TLS handshake here
                return NextStep::Continue(ProxyState::Transport(
                    TransportState::Conn(TransportConnState::ClientTcpEstablished)
                ));
            }

            TransportConnState::ClientTcpEstablished => {
                return NextStep::Continue(ProxyState::Detect(
                    DetectState::Bootstrap(DetectBootstrapState::DetectProtocolBegin)
                ));
            }
        },

        _ => NextStep::Close,
    }
}



// ========================================================================
//  DETECT HANDLER — Only HTTP/1.x support now
// ========================================================================
pub async unsafe fn detect_handler(conn: &mut Connection, s: DetectState) -> NextStep {
    match s {
        DetectState::Bootstrap(_) => {
            // TCP client?
            if let Some(ptr) = conn.client_tcp {
                let tcp = (ptr as *mut TcpStream).as_mut().unwrap();

                // Read from TCP into `in_buf`
                let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);
                let n = match tcp.read(buf).await {
                    Ok(n) if n > 0 => {
                        conn.in_len = n;
                        n
                    }
                    _ => return NextStep::Close,
                };

                // check for HTTP/1.x prefix
                let slice = &buf[..n];

                if slice.starts_with(b"GET ")
                    || slice.starts_with(b"POST ")
                    || slice.starts_with(b"HEAD ")
                    || slice.starts_with(b"PUT ")
                    || slice.starts_with(b"DELETE ")
                {
                    println!("[DETECT] Detected HTTP/1.x");
                    return NextStep::Continue(ProxyState::H1(
                        H1State::Request(H1RequestParseState::RecvHeaders)
                    ));
                }

                println!("[DETECT] Unknown → treat as HTTP/1.x");
                return NextStep::Continue(ProxyState::H1(
                    H1State::Request(H1RequestParseState::RecvHeaders)
                ));
            }

            // QUIC not implemented → close
            return NextStep::Close;
        }

        _ => NextStep::Close,
    }
}



// ========================================================================
//  H1 HANDLER (basic working pipeline)
// ========================================================================
pub async unsafe fn h1_handler(conn: &mut Connection, s: H1State) -> NextStep {
    match s {

        // ----------------------------------------------------------------
        // Read HTTP headers from client
        // ----------------------------------------------------------------
        H1State::Request(H1RequestParseState::RecvHeaders) => {
            let data = std::slice::from_raw_parts(conn.in_buf.as_ptr(), conn.in_len);

            if let Some(_) = twoway::find_bytes(data, b"\r\n\r\n") {
                return NextStep::Continue(ProxyState::H1(
                    H1State::Request(H1RequestParseState::HeadersComplete)
                ));
            }

            return NextStep::WaitClientRead;
        }


        // ----------------------------------------------------------------
        // After headers parsed → go upstream
        // ----------------------------------------------------------------
        H1State::Request(H1RequestParseState::HeadersComplete) => {
            return NextStep::Continue(ProxyState::Upstream(
                UpstreamState::Dns(UpstreamDnsState::ResolveStart)
            ));
        }


        // ----------------------------------------------------------------
        // After upstream finishes → send response
        // ----------------------------------------------------------------
        H1State::Forward(H1ForwardState::SendResponseHeadersToClient) => {
            if let Some(tcp) = tcp_mut(conn.client_tcp) {

                let response =
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

                let _ = tcp.write_all(response).await;
            }

            return NextStep::Continue(ProxyState::Shutdown(
                ShutdownState::GracefulShutdown
            ));
        }


        _ => NextStep::Close,
    }
}



// ========================================================================
//  UPSTREAM HANDLER — Minimal TCP connect only
// ========================================================================
pub async unsafe fn upstream_handler(conn: &mut Connection, s: UpstreamState) -> NextStep {
    match s {

        UpstreamState::Dns(UpstreamDnsState::ResolveStart) => {
            // Dummy address for now
            // let addr: Ipv4Addr = "142.250.74.110:80".parse().unwrap();
            conn.scratch = 80;

            return NextStep::Continue(ProxyState::Upstream(
                UpstreamState::Tcp(UpstreamTcpState::TcpConnectBegin)
            ));
        }

        UpstreamState::Tcp(UpstreamTcpState::TcpConnectBegin) => {
            match TcpStream::connect("142.250.74.110:80").await {
                Ok(s) => {
                    let raw_ptr = Box::into_raw(Box::new(s)) as *const TcpStream;
                    conn.upstream_tcp = Some(raw_ptr);

                    return NextStep::Continue(ProxyState::Upstream(
                        UpstreamState::Tcp(UpstreamTcpState::TcpConnectEstablished)
                    ));
                }

                Err(_) => return NextStep::Close,
            }
        }

        UpstreamState::Tcp(UpstreamTcpState::TcpConnectEstablished) => {
            return NextStep::Continue(ProxyState::H1(
                H1State::Forward(H1ForwardState::SendResponseHeadersToClient)
            ));
        }

        _ => NextStep::Close,
    }
}



// ========================================================================
// STREAM HANDLER (unused now)
// ========================================================================
pub async unsafe fn stream_handler(_: &mut Connection, _: StreamState) -> NextStep {
    NextStep::Close
}



// ========================================================================
// SHUTDOWN HANDLER
// ========================================================================
pub async unsafe fn shutdown_handler(_: &mut Connection, _: ShutdownState) -> NextStep {
    NextStep::Close
}



// ========================================================================
// DUMMY HANDLERS FOR FUTURE FEATURES
// ========================================================================

pub async unsafe fn tls_handler(_: &mut Connection, _: TlsState) -> NextStep {
    NextStep::Close
}

pub async unsafe fn quic_handler(_: &mut Connection, _: QuicState) -> NextStep {
    NextStep::Close
}

pub async unsafe fn h2_handler(_: &mut Connection, _: H2State) -> NextStep {
    NextStep::Close
}

pub async unsafe fn h3_handler(_: &mut Connection, _: H3State) -> NextStep {
    NextStep::Close
}

pub async unsafe fn intercept_handler(_: &mut Connection, _: InterceptState) -> NextStep {
    NextStep::Close
}
