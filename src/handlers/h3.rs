use crate::{
    connection::Connection,
    fsm::NextStep,
    states::*,
};

use super::shared::{
    parse_connect_target, read_client_data, read_upstream_data, tunnel_copy, write_client_data, write_upstream_data,
};

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
