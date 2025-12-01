use httparse::{Request, Status};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::error::TryRecvError;

use crate::{
    connection::Connection,
    config::CONFIG,
    controller::ControllerMsg,
    fsm::NextStep,
    states::*,
};

use super::shared::{
    parse_connect_target, read_client_data, read_upstream_data, split_host_port, tunnel_copy, write_client_data,
    write_upstream_data,
};

pub async unsafe fn h1_handler(conn: &mut Connection, s: H1State) -> NextStep {
    println!("[H1] {:?}", s);

    match s {
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
            conn.connect_response_sent = false;

            if CONFIG.connect.passthrough_tunnel {
                println!("[H1] CONNECT mode=tunnel (passthrough)");
                conn.upstream_tls_required = false;
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
            } else {
                println!("[H1] CONNECT mode=intercept (MITM)");
                conn.upstream_tls_required = true;
                conn.next_state_after_upstream = None;
                return NextStep::Continue(ProxyState::H1(H1State::Connect(
                    H1ConnectState::ConnectTunnelTransfer,
                )));
            }
        }

        H1State::Connect(H1ConnectState::ConnectTunnelTransfer) => {
            println!(
                "[H1] CONNECT transfer start: upstream_tcp={} upstream_tls={} connect_resp_sent={}",
                conn.upstream_tcp.is_some(),
                conn.upstream_tls.is_some(),
                conn.connect_response_sent
            );

            if !CONFIG.connect.passthrough_tunnel {
                conn.upstream_tls_required = true;
                if !conn.connect_response_sent {
                    println!("[H1] CONNECT sending 200 response to client (intercept mode)");
                    let _ = write_client_data(
                        conn,
                        b"HTTP/1.1 200 Connection Established\r\n\r\n",
                    )
                    .await;
                    conn.connect_response_sent = true;
                }

                conn.in_len = 0;
                conn.next_state_after_upstream = None;

                return NextStep::Continue(ProxyState::H1(H1State::Intercept(
                    H1InterceptState::SendToController,
                )));
            }

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

        H1State::Intercept(H1InterceptState::SendToController) => {
            if let Some(target) = conn.target() {
                let _ = conn
                    .controller_tx
                    .send(ControllerMsg::Raw(format!("CONNECT {}:{}", target.host, target.port)));
            } else {
                let _ = conn
                    .controller_tx
                    .send(ControllerMsg::Raw("CONNECT (unknown target)".into()));
            }

            return NextStep::Continue(ProxyState::H1(H1State::Intercept(
                H1InterceptState::WaitControllerDecision,
            )));
        }

        H1State::Intercept(H1InterceptState::WaitControllerDecision) => {
            match conn.controller_rx.try_recv() {
                Ok(ControllerMsg::Block) => {
                    let _ = write_client_data(conn, b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
                    return NextStep::Close;
                }
                Ok(ControllerMsg::Allow)
                | Ok(ControllerMsg::Modify(_))
                | Ok(ControllerMsg::Raw(_))
                | Err(TryRecvError::Empty)
                | Err(TryRecvError::Disconnected) => {
                    return NextStep::Continue(ProxyState::H1(H1State::Intercept(
                        H1InterceptState::ApplyModification,
                    )));
                }
            }
        }

        H1State::Intercept(H1InterceptState::ApplyModification) => {
            if !conn.connect_response_sent {
                let _ = write_client_data(
                    conn,
                    b"HTTP/1.1 200 Connection Established\r\n\r\n",
                )
                .await;
                conn.connect_response_sent = true;
            }

            conn.upstream_tls_required = true;
            conn.next_state_after_upstream = None;
            conn.in_len = 0;

            return NextStep::Continue(ProxyState::Tls(TlsState::Handshake(
                TlsHandshakeState::HandshakeBegin,
            )));
        }

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

                    if conn.in_len > header_len {
                        let body_bytes = conn.in_len - header_len;
                        buf.copy_within(header_len..header_len + body_bytes, 0);
                        conn.in_len = body_bytes;
                    } else {
                        conn.in_len = 0;
                    }

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

            let sess = &conn.client_h1_state;
            if sess.is_chunked {
                println!("[H1] Request uses chunked transfer");
                conn.scratch = 0;
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

        H1State::Forward(H1ForwardState::ForwardRequestBody) => {
            println!("[H1] ForwardRequestBody");

            let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);
            let mut remaining = conn.client_h1_state.body_len.unwrap_or(0);

            if remaining == 0 {
                return NextStep::Continue(ProxyState::H1(H1State::Forward(
                    H1ForwardState::UpstreamRecvHeaders,
                )));
            }

            if conn.in_len > 0 {
                let to_send = std::cmp::min(conn.in_len as u64, remaining) as usize;
                if let Err(e) = write_upstream_data(conn, &buf[..to_send]).await {
                    println!("[H1] Req body buffered write error: {}", e);
                    return NextStep::Close;
                }
                remaining -= to_send as u64;

                if conn.in_len > to_send {
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

        H1State::Forward(H1ForwardState::SendResponseHeadersToClient) => {
            println!("[H1] SendResponseHeadersToClient");
            let buf = std::slice::from_raw_parts_mut(conn.out_buf.as_ptr(), conn.out_cap);
            let n = conn.out_len;

            debug_assert!(
                conn.client_mitm_tls.is_some() || conn.client_tls.is_some() || conn.client_tcp.is_some(),
                "[H1] SendResponseHeadersToClient needs a client stream"
            );

            if let Err(e) = write_client_data(conn, &buf[..n]).await {
                println!("[H1] Response header write error: {}", e);
                return NextStep::Close;
            }

            let resp = &mut conn.upstream_h1_state;
            if resp.is_chunked {
                conn.scratch = 1;
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

            return NextStep::Continue(ProxyState::H1(H1State::Forward(
                H1ForwardState::UpstreamRecvBody,
            )));
        }

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
        conn.upstream_tls_required = !CONFIG.connect.passthrough_tunnel;
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

    if !is_connect {
        let include_port = target_port != default_port;
        rewritten.extend_from_slice(b"Host: ");
        rewritten.extend_from_slice(target_host.as_bytes());
        if include_port {
            rewritten.extend_from_slice(format!(":{}", target_port).as_bytes());
        }
        rewritten.extend_from_slice(b"\r\n");
    }

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
