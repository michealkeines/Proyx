use http::{
    Method, StatusCode, Uri, Version,
    header::{self, HeaderMap, HeaderName, HeaderValue},
};
use httparse::{Request, Status};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::error::TryRecvError;

use crate::{
    config::CONFIG, connection::Connection, controller::ControllerMsg, fsm::NextStep, states::*,
};

use super::shared::{
    parse_connect_target, read_client_data, read_upstream_data, split_host_port, tunnel_copy,
    write_client_data, write_upstream_data,
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
                    let _ = write_client_data(conn, b"HTTP/1.1 200 Connection Established\r\n\r\n")
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
                let _ =
                    write_client_data(conn, b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
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
                let _ = conn.controller_tx.send(ControllerMsg::Raw(format!(
                    "CONNECT {}:{}",
                    target.host, target.port
                )));
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
                let _ =
                    write_client_data(conn, b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
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
                conn.client_mitm_tls.is_some()
                    || conn.client_tls.is_some()
                    || conn.client_tcp.is_some(),
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
        "connection" | "proxy-connection" | "keep-alive" | "te" | "transfer-encoding" | "upgrade"
    )
}

fn header_map_from_httparse(raw: &[httparse::Header]) -> Result<HeaderMap, String> {
    let mut map = HeaderMap::with_capacity(raw.len());
    for h in raw.iter() {
        let name = HeaderName::from_bytes(h.name.as_bytes())
            .map_err(|e| format!("invalid header name '{}': {}", h.name, e))?;
        let value = HeaderValue::from_bytes(h.value)
            .map_err(|e| format!("invalid value for '{}': {}", h.name, e))?;
        map.append(name, value);
    }
    Ok(map)
}

fn header_values_contains_token(headers: &HeaderMap, name: &HeaderName, token: &str) -> bool {
    let needle = token.to_ascii_lowercase();
    headers.get_all(name).iter().any(|value| {
        value
            .to_str()
            .map(|v| {
                v.split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case(&needle))
            })
            .unwrap_or(false)
    })
}

fn header_values_contains_token_str(headers: &HeaderMap, name: &str, token: &str) -> bool {
    let needle = token.to_ascii_lowercase();
    headers.get_all(name).iter().any(|value| {
        value
            .to_str()
            .map(|v| {
                v.split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case(&needle))
            })
            .unwrap_or(false)
    })
}

fn parse_content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

fn version_from_httparse(version: Option<u8>) -> Version {
    match version {
        Some(0) => Version::HTTP_10,
        _ => Version::HTTP_11,
    }
}

fn connection_header_value(keep_alive: bool) -> HeaderValue {
    if keep_alive {
        HeaderValue::from_static("keep-alive")
    } else {
        HeaderValue::from_static("close")
    }
}

fn serialize_request(req: &http::Request<()>, request_target: &str) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(512);
    let target = if request_target.is_empty() {
        "/"
    } else {
        request_target
    };

    buf.extend_from_slice(req.method().as_str().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(target.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(
        match req.version() {
            Version::HTTP_10 => "HTTP/1.0",
            Version::HTTP_11 => "HTTP/1.1",
            _ => "HTTP/1.1",
        }
        .as_bytes(),
    );
    buf.extend_from_slice(b"\r\n");

    for (name, value) in req.headers() {
        buf.extend_from_slice(name.as_str().as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");

    Ok(buf)
}

fn serialize_response(resp: &http::Response<()>, reason_phrase: &str) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(512);
    let version_str = match resp.version() {
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        _ => "HTTP/1.1",
    };

    let status = resp.status();
    let reason = if reason_phrase.is_empty() {
        status.canonical_reason().unwrap_or("")
    } else {
        reason_phrase
    };

    buf.extend_from_slice(version_str.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(status.as_str().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(reason.as_bytes());
    buf.extend_from_slice(b"\r\n");

    for (name, value) in resp.headers() {
        buf.extend_from_slice(name.as_str().as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");

    Ok(buf)
}

fn prepare_h1_request(conn: &mut Connection, header_bytes: &[u8]) -> Result<(), String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = Request::new(&mut headers);
    let status = req
        .parse(header_bytes)
        .map_err(|e| format!("parse error: {}", e))?;
    if !matches!(status, Status::Complete(_)) {
        return Err("incomplete request headers".into());
    }

    let method_str = req.method.ok_or("missing method")?;
    let path = req.path.ok_or("missing path")?;
    let method =
        Method::from_bytes(method_str.as_bytes()).map_err(|e| format!("invalid method: {}", e))?;
    let version = version_from_httparse(req.version);
    let is_1_0 = version == Version::HTTP_10;

    let header_map = header_map_from_httparse(req.headers)?;
    let host_header = header_map
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let mut keep_alive = !is_1_0;
    if header_values_contains_token(&header_map, &header::CONNECTION, "close") {
        keep_alive = false;
    }
    if is_1_0 && header_values_contains_token(&header_map, &header::CONNECTION, "keep-alive") {
        keep_alive = true;
    }
    if header_map.contains_key("proxy-connection")
        || header_values_contains_token_str(&header_map, "proxy-connection", "close")
    {
        keep_alive = false;
    }

    let mut is_chunked =
        header_values_contains_token(&header_map, &header::TRANSFER_ENCODING, "chunked");
    let mut content_len = parse_content_length(&header_map);
    let expect_continue =
        header_values_contains_token(&header_map, &header::EXPECT, "100-continue");

    if is_chunked {
        content_len = None;
    }

    let is_connect = method == Method::CONNECT;
    let is_head = method == Method::HEAD;

    let mut target_host = String::new();
    let mut target_port: u16 = 80;
    let mut upstream_path = path.to_string();
    let mut default_port = 80u16;

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
        let uri: Uri = path
            .parse()
            .map_err(|_| "invalid absolute-form request-target".to_string())?;
        let scheme = uri
            .scheme_str()
            .ok_or_else(|| "absolute-form request missing scheme".to_string())?;
        default_port = if scheme.eq_ignore_ascii_case("https") {
            443
        } else {
            80
        };
        let authority = uri
            .authority()
            .map(|a| a.as_str().to_string())
            .ok_or_else(|| "absolute-form request missing authority".to_string())?;
        let (h, p) = split_host_port(&authority, default_port);
        target_host = h;
        target_port = p;
        upstream_path = uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        conn.upstream_tls_required = default_port == 443;
        conn.next_state_after_upstream = Some(ProxyState::H1(H1State::Forward(
            H1ForwardState::ForwardRequestHeaders,
        )));
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
        conn.next_state_after_upstream = Some(ProxyState::H1(H1State::Forward(
            H1ForwardState::ForwardRequestHeaders,
        )));
    }

    if target_host.is_empty() {
        return Err("unable to determine target host".into());
    }

    conn.set_target(target_host.clone(), target_port);

    let mut builder = http::Request::builder().method(&method).version(version);
    let uri = if is_connect {
        Uri::from_static("/")
    } else {
        upstream_path
            .parse::<Uri>()
            .map_err(|e| format!("invalid path: {}", e))?
    };
    builder = builder.uri(uri);

    {
        let headers = builder
            .headers_mut()
            .ok_or_else(|| "failed to access request headers".to_string())?;

        for (name, value) in header_map.iter() {
            let lower = name.as_str();
            if is_hop_by_hop(lower)
                || name == header::HOST
                || name == header::CONTENT_LENGTH
                || name == header::TRANSFER_ENCODING
                || name == header::EXPECT
            {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }

        if !is_connect {
            let include_port = target_port != default_port;
            let host_value = if include_port {
                format!("{}:{}", target_host, target_port)
            } else {
                target_host.clone()
            };
            headers.insert(
                header::HOST,
                HeaderValue::from_str(&host_value)
                    .map_err(|e| format!("invalid host header: {}", e))?,
            );
        }

        headers.insert(header::CONNECTION, connection_header_value(keep_alive));
        if expect_continue {
            headers.insert(header::EXPECT, HeaderValue::from_static("100-continue"));
        }
        if is_chunked {
            headers.insert(
                header::TRANSFER_ENCODING,
                HeaderValue::from_static("chunked"),
            );
        } else if let Some(len) = content_len {
            headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&len.to_string())
                    .map_err(|e| format!("invalid content-length: {}", e))?,
            );
        }
    }

    let request = builder
        .body(())
        .map_err(|e| format!("failed to build request: {}", e))?;

    let request_target = upstream_path.clone();
    let rewritten = serialize_request(&request, &request_target)?;

    if rewritten.len() > conn.out_cap {
        return Err("request headers exceed buffer".into());
    }

    unsafe {
        std::ptr::copy_nonoverlapping(rewritten.as_ptr(), conn.out_buf.as_ptr(), rewritten.len());
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
    let status = resp
        .parse(header_bytes)
        .map_err(|e| format!("parse error: {}", e))?;
    if !matches!(status, Status::Complete(_)) {
        return Err("incomplete response headers".into());
    }

    let version = version_from_httparse(resp.version);
    let status_code = StatusCode::from_u16(resp.code.ok_or("missing status code")?)
        .map_err(|e| format!("invalid status code: {}", e))?;
    let reason = resp
        .reason
        .map(|r| r.to_string())
        .unwrap_or_else(|| status_code.canonical_reason().unwrap_or("OK").to_string());
    let mut keep_alive = version != Version::HTTP_10;

    let header_map = header_map_from_httparse(resp.headers)?;
    if header_values_contains_token(&header_map, &header::CONNECTION, "close") {
        keep_alive = false;
    }
    if version == Version::HTTP_10
        && header_values_contains_token(&header_map, &header::CONNECTION, "keep-alive")
    {
        keep_alive = true;
    }
    if header_map.contains_key("proxy-connection")
        || header_values_contains_token_str(&header_map, "proxy-connection", "close")
    {
        keep_alive = false;
    }

    let mut is_chunked =
        header_values_contains_token(&header_map, &header::TRANSFER_ENCODING, "chunked");
    let mut content_len = parse_content_length(&header_map);

    if is_chunked {
        content_len = None;
    }

    let mut has_body = true;
    if (100..200).contains(&status_code.as_u16()) && status_code.as_u16() != 101 {
        has_body = false;
    }
    if status_code == StatusCode::NO_CONTENT || status_code == StatusCode::NOT_MODIFIED {
        has_body = false;
    }
    if conn.client_h1_state.is_head || conn.client_h1_state.is_connect {
        has_body = false;
    }

    if !has_body {
        content_len = Some(0);
        is_chunked = false;
    }

    let mut builder = http::Response::builder()
        .status(status_code)
        .version(version);

    {
        let headers_mut = builder
            .headers_mut()
            .ok_or_else(|| "failed to access response headers".to_string())?;

        for (name, value) in header_map.iter() {
            let lower = name.as_str();
            if is_hop_by_hop(lower)
                || name == header::CONTENT_LENGTH
                || name == header::TRANSFER_ENCODING
            {
                continue;
            }
            headers_mut.append(name.clone(), value.clone());
        }

        headers_mut.insert(header::CONNECTION, connection_header_value(keep_alive));

        if has_body {
            if is_chunked {
                headers_mut.insert(
                    header::TRANSFER_ENCODING,
                    HeaderValue::from_static("chunked"),
                );
            } else if let Some(len) = content_len {
                headers_mut.insert(
                    header::CONTENT_LENGTH,
                    HeaderValue::from_str(&len.to_string())
                        .map_err(|e| format!("invalid content-length: {}", e))?,
                );
            }
        }
    }

    let response = builder
        .body(())
        .map_err(|e| format!("failed to build response: {}", e))?;
    let rewritten = serialize_response(&response, &reason)?;

    if rewritten.len() > conn.out_cap {
        return Err("response headers exceed buffer".into());
    }

    unsafe {
        std::ptr::copy_nonoverlapping(rewritten.as_ptr(), conn.out_buf.as_ptr(), rewritten.len());
    }
    conn.out_len = rewritten.len();

    conn.upstream_h1_state.parsed_headers = true;
    conn.upstream_h1_state.parsed_body = false;
    conn.upstream_h1_state.keep_alive = keep_alive;
    conn.upstream_h1_state.is_chunked = is_chunked;
    conn.upstream_h1_state.content_len = content_len;
    conn.upstream_h1_state.body_len = if is_chunked { Some(0) } else { content_len };
    conn.upstream_h1_state.version_1_0 = version == Version::HTTP_10;

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
