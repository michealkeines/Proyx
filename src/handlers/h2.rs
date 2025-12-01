use std::io::ErrorKind;

use hpack::{Decoder, Encoder};

use crate::{connection::Connection, config::CONFIG, fsm::NextStep, states::*};

use super::shared::{
    read_client_data, read_upstream_data, split_host_port, write_client_data, write_upstream_data,
};

const H2_DEFAULT_MAX_FRAME_SIZE: usize = CONFIG.h2.max_frame_size;

pub async unsafe fn h2_handler(conn: &mut Connection, s: H2State) -> NextStep {
    println!("[H2] {:?}", s);

    let buf = std::slice::from_raw_parts_mut(conn.in_buf.as_ptr(), conn.in_cap);

    match s {
        H2State::Bootstrap(H2ConnBootstrapState::ClientPreface) => {
            const CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            let preface_len = CLIENT_PREFACE.len();

            conn.h2_pending_upstream_frames.clear();
            conn.h2_use_upstream_h2 = true;
            conn.h2_upstream_ready = false;
            conn.h2_upstream_preface_sent = false;
            conn.h2_client_max_frame_size = H2_DEFAULT_MAX_FRAME_SIZE;
            conn.h2_upstream_max_frame_size = H2_DEFAULT_MAX_FRAME_SIZE;
            conn.h2_decoder = Decoder::new();
            conn.h2_upstream_decoder = Decoder::new();
            conn.h2_client_encoder = Encoder::new();
            conn.h2_upstream_encoder = Encoder::new();

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
            conn.h2_client_preface_seen = true;

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

            if conn.h2_use_upstream_h2 {
                conn
                    .h2_pending_upstream_frames
                    .extend_from_slice(&buf[..total]);
            }
            if settings_len > 0 {
                apply_h2_settings(&mut conn.h2_client_max_frame_size, &buf[9..total]);
            }

            let settings_ack = build_h2_frame_header(0, 0x4, 0x1, 0);
            if let Err(e) = write_client_data(conn, &settings_ack).await {
                println!("[H2] Failed to send SETTINGS ACK: {}", e);
                return NextStep::Close;
            }
            println!("[H2] Sent SETTINGS ACK to client");

            if conn.in_len > total {
                let remaining = conn.in_len - total;
                buf.copy_within(total..total + remaining, 0);
                conn.in_len = remaining;
            } else {
                conn.in_len = 0;
            }

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

            if payload_len > conn.h2_client_max_frame_size {
                return h2_connection_error(
                    conn,
                    0x6,
                    "frame payload exceeds max frame size",
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
            let total = 9 + payload_len;

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

            if frame.kind == 0x4 {
                if frame.flags & 0x1 != 0 {
                    println!("[H2] Received SETTINGS ACK from client");
                    consume_h2_frame(conn, buf, total);
                    return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                        H2FrameParseState::RecvFrameHeader,
                    )));
                }

                if payload_len % 6 != 0 {
                    return h2_connection_error(conn, 0x6, "SETTINGS length not multiple of 6")
                        .await;
                }

                apply_h2_settings(&mut conn.h2_client_max_frame_size, &buf[9..total]);

                let settings_ack = build_h2_frame_header(0, 0x4, 0x1, 0);
                if let Err(e) = write_client_data(conn, &settings_ack).await {
                    println!("[H2] Failed to send SETTINGS ACK: {}", e);
                    return NextStep::Close;
                }

                consume_h2_frame(conn, buf, total);
                return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                    H2FrameParseState::RecvFrameHeader,
                )));
            }

            if frame.kind == 0x1 && frame.stream_id != 0 {
                let (frag, consumed_total) = match h2_read_headers_block(conn, buf, &frame, true).await {
                    Ok(v) => v,
                    Err(next) => return next,
                };

                let headers = match decode_h2_header_block(&mut conn.h2_decoder, &frag) {
                    Some(h) => h,
                    None => {
                        return h2_connection_error(conn, 0x1, "failed to decode HEADERS").await;
                    }
                };

                if conn.h2_use_upstream_h2 {
                    let frames = encode_h2_headers_for_peer(
                        &mut conn.h2_upstream_encoder,
                        &headers,
                        frame.stream_id,
                        frame.flags & 0x1 != 0,
                        conn.h2_upstream_max_frame_size,
                    );
                    conn.h2_pending_upstream_frames.extend_from_slice(&frames);
                }

                let (method, host, port) =
                    match extract_h2_pseudo_headers(&headers, 443) {
                        Some(v) => v,
                        None => {
                            return h2_connection_error(
                                conn,
                                0x1,
                                "failed to parse HEADERS pseudo-headers",
                            )
                            .await;
                        }
                    };

                consume_h2_frame(conn, buf, consumed_total);

                if method.eq_ignore_ascii_case("CONNECT") {
                    println!("[H2] CONNECT detected on stream {}", frame.stream_id);
                    conn.h2_use_upstream_h2 = false;
                    conn.h2_pending_upstream_frames.clear();
                    conn.set_target(host, port);
                    conn.upstream_tls_required = false;
                    conn.connect_response_sent = false;
                    conn.h2_connect_stream_id = Some(frame.stream_id);
                    conn.next_state_after_upstream = Some(ProxyState::H2(H2State::Proxy(
                        H2ProxyState::ProxyFramesClientToUpstream,
                    )));
                    return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                        UpstreamDnsState::ResolveStart,
                    )));
                }

                if conn.target().is_none() {
                    conn.set_target(host, port);
                }
                conn.next_state_after_upstream = Some(ProxyState::H2(H2State::UpstreamSettings(
                    H2UpstreamSettingsState::UpstreamSettingsExchange,
                )));
                return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                    UpstreamDnsState::ResolveStart,
                )));
            }

            if conn.h2_use_upstream_h2 {
                conn.h2_pending_upstream_frames
                    .extend_from_slice(&buf[..total]);
            }

            if frame.kind != 0x1 && conn.target().is_none() {
                consume_h2_frame(conn, buf, total);
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
                    conn.next_state_after_upstream = Some(ProxyState::H2(
                        H2State::UpstreamSettings(H2UpstreamSettingsState::UpstreamSettingsExchange),
                    ));
                }
                conn.in_len = 0;
                return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                    UpstreamDnsState::ResolveStart,
                )));
            }
            consume_h2_frame(conn, buf, total);

            if conn.next_state_after_upstream.is_none() {
                conn.next_state_after_upstream = Some(ProxyState::H2(
                    H2State::UpstreamSettings(H2UpstreamSettingsState::UpstreamSettingsExchange),
                ));
            }

            return NextStep::Continue(ProxyState::H2(H2State::FrameParse(
                H2FrameParseState::RecvFrameHeader,
            )));
        }

        H2State::UpstreamSettings(H2UpstreamSettingsState::UpstreamSettingsExchange) => {
            if !conn.h2_use_upstream_h2 || conn.h2_connect_stream_id.is_some() {
                conn.h2_upstream_ready = true;
                conn.h2_pending_upstream_frames.clear();
                return NextStep::Continue(ProxyState::H2(H2State::Proxy(
                    H2ProxyState::ProxyFramesClientToUpstream,
                )));
            }

            if conn.upstream_tcp.is_none() && conn.upstream_tls.is_none() {
                if conn.next_state_after_upstream.is_none() {
                    conn.next_state_after_upstream = Some(ProxyState::H2(
                        H2State::UpstreamSettings(H2UpstreamSettingsState::UpstreamSettingsExchange),
                    ));
                }
                return NextStep::Continue(ProxyState::Upstream(UpstreamState::Dns(
                    UpstreamDnsState::ResolveStart,
                )));
            }

            if let Err(e) = h2_flush_pending_to_upstream(conn).await {
                println!("[H2] Failed to flush client preface to upstream: {}", e);
                return NextStep::Close;
            }

            conn.in_len = 0;
            if conn.in_len < 9 {
                match read_upstream_data(conn, &mut buf[conn.in_len..9]).await {
                    Ok(n) if n > 0 => conn.in_len += n,
                    _ => return NextStep::Close,
                }
            }

            if conn.in_len < 9 {
                return NextStep::WaitRead(ProxyState::H2(H2State::UpstreamSettings(
                    H2UpstreamSettingsState::UpstreamSettingsExchange,
                )));
            }

            let header = parse_h2_frame_header(&buf[..9]);
            if header.kind != 0x4 || (header.flags & 0x1 != 0) {
                return h2_connection_error(conn, 0x1, "upstream did not start with SETTINGS").await;
            }

            let total = 9 + header.length;
            if total > conn.in_cap {
                println!(
                    "[H2] Upstream SETTINGS too large for buffer ({} > {})",
                    total, conn.in_cap
                );
                return NextStep::Close;
            }

            while conn.in_len < total {
                match read_upstream_data(conn, &mut buf[conn.in_len..total]).await {
                    Ok(n) if n > 0 => conn.in_len += n,
                    _ => {
                        return NextStep::WaitRead(ProxyState::H2(H2State::UpstreamSettings(
                            H2UpstreamSettingsState::UpstreamSettingsExchange,
                        )))
                    }
                }
            }

            apply_h2_settings(&mut conn.h2_upstream_max_frame_size, &buf[9..total]);

            let ack = build_h2_frame_header(0, 0x4, 0x1, 0);
            if let Err(e) = write_upstream_data(conn, &ack).await {
                println!("[H2] Failed to ack upstream SETTINGS: {}", e);
                return NextStep::Close;
            }

            conn.in_len = 0;
            conn.h2_upstream_ready = true;
            return NextStep::Continue(ProxyState::H2(H2State::Proxy(
                H2ProxyState::ProxyFramesClientToUpstream,
            )));
        }

        H2State::Proxy(H2ProxyState::ProxyFramesClientToUpstream) => {
            if let Some(stream_id) = conn.h2_connect_stream_id {
                let mut n = conn.in_len;
                println!(
                    "[H2] CONNECT tunnel entry: in_len={} upstream_tcp={} upstream_tls={}",
                    n,
                    conn.upstream_tcp.is_some(),
                    conn.upstream_tls.is_some()
                );

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

                if !conn.connect_response_sent {
                    if let Err(e) = send_h2_connect_response(conn, stream_id).await {
                        println!("[H2] Failed to send CONNECT response: {}", e);
                        return NextStep::Close;
                    }
                    conn.connect_response_sent = true;
                }

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

            if !conn.h2_upstream_ready {
                return NextStep::Continue(ProxyState::H2(H2State::UpstreamSettings(
                    H2UpstreamSettingsState::UpstreamSettingsExchange,
                )));
            }

            let mut forwarded = false;

            loop {
                if conn.in_len < 9 {
                    match read_client_data(conn, buf).await {
                        Ok(read) if read > 0 => {
                            conn.in_len = read;
                        }
                        _ => return NextStep::Close,
                    }
                    if conn.in_len < 9 {
                        return NextStep::WaitRead(ProxyState::H2(H2State::Proxy(
                            H2ProxyState::ProxyFramesClientToUpstream,
                        )));
                    }
                }

                let frame = parse_h2_frame_header(&buf[..9]);
                let total = 9 + frame.length;
                if total > conn.in_cap {
                    println!("[H2] Frame exceeds buffer: {}", total);
                    return NextStep::Close;
                }

                while conn.in_len < total {
                    match read_client_data(conn, &mut buf[conn.in_len..total]).await {
                        Ok(more) if more > 0 => conn.in_len += more,
                        _ => {
                            return NextStep::WaitRead(ProxyState::H2(H2State::Proxy(
                                H2ProxyState::ProxyFramesClientToUpstream,
                            )))
                        }
                    }
                }

                if frame.kind == 0x4 {
                    if frame.flags & 0x1 != 0 {
                        println!("[H2] Dropping client SETTINGS ACK");
                        consume_h2_frame(conn, buf, total);
                        continue;
                    }

                    apply_h2_settings(&mut conn.h2_client_max_frame_size, &buf[9..total]);
                    let ack = build_h2_frame_header(0, 0x4, 0x1, 0);
                    if let Err(e) = write_client_data(conn, &ack).await {
                        println!("[H2] Failed to ACK client SETTINGS: {}", e);
                        return NextStep::Close;
                    }
                    consume_h2_frame(conn, buf, total);
                    continue;
                }

                if frame.kind == 0x1 {
                    let (block, consumed) =
                        match h2_read_headers_block(conn, buf, &frame, true).await {
                            Ok(v) => v,
                            Err(next) => return next,
                        };
                    let headers = match decode_h2_header_block(&mut conn.h2_decoder, &block) {
                        Some(h) => h,
                        None => {
                            return h2_connection_error(conn, 0x1, "failed to decode HEADERS").await;
                        }
                    };

                    let encoded = encode_h2_headers_for_peer(
                        &mut conn.h2_upstream_encoder,
                        &headers,
                        frame.stream_id,
                        frame.flags & 0x1 != 0,
                        conn.h2_upstream_max_frame_size,
                    );

                    if let Err(e) = write_upstream_data(conn, &encoded).await {
                        println!("[H2] Failed to forward re-encoded HEADERS: {}", e);
                        return NextStep::Close;
                    }

                    forwarded = true;
                    consume_h2_frame(conn, buf, consumed);
                } else {
                    if frame.length > conn.h2_upstream_max_frame_size && frame.kind != 0x4 {
                        return h2_connection_error(
                            conn,
                            0x6,
                            "frame exceeds upstream SETTINGS_MAX_FRAME_SIZE",
                        )
                        .await;
                    }

                    if let Err(e) = write_upstream_data(conn, &buf[..total]).await {
                        println!("[H2] Client->upstream write failed: {}", e);
                        return NextStep::Close;
                    }
                    forwarded = true;
                    consume_h2_frame(conn, buf, total);
                }

                if conn.in_len == 0 {
                    break;
                }
            }

            if forwarded {
                NextStep::Continue(ProxyState::H2(H2State::Proxy(
                    H2ProxyState::ProxyFramesUpstreamToClient,
                )))
            } else {
                NextStep::WaitRead(ProxyState::H2(H2State::Proxy(
                    H2ProxyState::ProxyFramesClientToUpstream,
                )))
            }
        }

        H2State::Proxy(H2ProxyState::ProxyFramesUpstreamToClient) => {
            if let Some(stream_id) = conn.h2_connect_stream_id {
                return h2_connect_forward_upstream(conn, stream_id, buf).await;
            }

            let mut forwarded = false;

            loop {
                if conn.in_len < 9 {
                    match read_upstream_data(conn, buf).await {
                        Ok(n) if n > 0 => conn.in_len = n,
                        Ok(_) => {
                            println!("[H2] Upstream closed connection");
                            return NextStep::Close;
                        }
                        Err(e) => {
                            println!("[H2] Upstream read error: {}", e);
                            return NextStep::Close;
                        }
                    };
                    if conn.in_len < 9 {
                        return NextStep::WaitRead(ProxyState::H2(H2State::Proxy(
                            H2ProxyState::ProxyFramesUpstreamToClient,
                        )));
                    }
                }

                let frame = parse_h2_frame_header(&buf[..9]);
                let total = 9 + frame.length;
                if total > conn.in_cap {
                    println!("[H2] Upstream frame exceeds buffer: {}", total);
                    return NextStep::Close;
                }

                while conn.in_len < total {
                    match read_upstream_data(conn, &mut buf[conn.in_len..total]).await {
                        Ok(more) if more > 0 => conn.in_len += more,
                        _ => {
                            return NextStep::WaitRead(ProxyState::H2(H2State::Proxy(
                                H2ProxyState::ProxyFramesUpstreamToClient,
                            )))
                        }
                    }
                }

                if frame.kind == 0x4 {
                    if frame.flags & 0x1 != 0 {
                        println!("[H2] Dropping upstream SETTINGS ACK");
                        consume_h2_frame(conn, buf, total);
                        continue;
                    }

                    apply_h2_settings(&mut conn.h2_upstream_max_frame_size, &buf[9..total]);
                    let ack = build_h2_frame_header(0, 0x4, 0x1, 0);
                    if let Err(e) = write_upstream_data(conn, &ack).await {
                        println!("[H2] Failed to ack upstream SETTINGS: {}", e);
                        return NextStep::Close;
                    }
                    consume_h2_frame(conn, buf, total);
                    continue;
                }

                if frame.kind == 0x1 {
                    let (block, consumed) =
                        match h2_read_headers_block(conn, buf, &frame, false).await {
                            Ok(v) => v,
                            Err(next) => return next,
                        };
                    let headers =
                        match decode_h2_header_block(&mut conn.h2_upstream_decoder, &block) {
                            Some(h) => h,
                            None => {
                                return h2_connection_error(
                                    conn,
                                    0x1,
                                    "failed to decode upstream HEADERS",
                                )
                                .await;
                            }
                        };

                    let encoded = encode_h2_headers_for_peer(
                        &mut conn.h2_client_encoder,
                        &headers,
                        frame.stream_id,
                        frame.flags & 0x1 != 0,
                        conn.h2_client_max_frame_size,
                    );

                    if let Err(e) = write_client_data(conn, &encoded).await {
                        println!("[H2] Failed to forward upstream HEADERS: {}", e);
                        return NextStep::Close;
                    }

                    forwarded = true;
                    consume_h2_frame(conn, buf, consumed);
                } else {
                    if frame.length > conn.h2_client_max_frame_size && frame.kind != 0x4 {
                        return h2_connection_error(
                            conn,
                            0x6,
                            "upstream frame exceeds client SETTINGS_MAX_FRAME_SIZE",
                        )
                        .await;
                    }
                    if let Err(e) = write_client_data(conn, &buf[..total]).await {
                        println!("[H2] Upstream->client write failed: {}", e);
                        return NextStep::Close;
                    }
                    forwarded = true;
                    consume_h2_frame(conn, buf, total);
                }

                if conn.in_len == 0 {
                    break;
                }
            }

            if forwarded {
                NextStep::Continue(ProxyState::H2(H2State::Proxy(
                    H2ProxyState::ProxyFramesClientToUpstream,
                )))
            } else {
                NextStep::WaitRead(ProxyState::H2(H2State::Proxy(
                    H2ProxyState::ProxyFramesUpstreamToClient,
                )))
            }
        }

        _ => {
            println!("[H2] Unhandled state");
            NextStep::Close
        }
    }
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

fn decode_h2_header_block(decoder: &mut Decoder<'static>, block: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    decoder.decode(block).ok()
}

fn extract_h2_pseudo_headers(
    headers: &[(Vec<u8>, Vec<u8>)],
    default_port: u16,
) -> Option<(String, String, u16)> {
    let mut method: Option<String> = None;
    let mut authority: Option<String> = None;

    for (name, value) in headers {
        let name_str = std::str::from_utf8(name).ok()?;
        let val_str = std::str::from_utf8(value).ok()?;

        if name_str.eq_ignore_ascii_case(":method") {
            method = Some(val_str.to_string());
        } else if name_str.eq_ignore_ascii_case(":authority") {
            authority = Some(val_str.to_string());
        }
    }

    let method = method?;
    let authority = authority?;
    let (host, port) = split_host_port(&authority, default_port);
    Some((method, host, port))
}

fn encode_h2_headers_for_peer(
    encoder: &mut Encoder<'static>,
    headers: &[(Vec<u8>, Vec<u8>)],
    stream_id: u32,
    end_stream: bool,
    max_frame_size: usize,
) -> Vec<u8> {
    let block = encoder.encode(headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
    let mut frames = Vec::new();

    let max_frame_size = std::cmp::max(1, max_frame_size);

    if block.is_empty() {
        let mut flags = 0x4;
        if end_stream {
            flags |= 0x1;
        }
        frames.extend_from_slice(&build_h2_frame_header(0, 0x1, flags, stream_id));
        return frames;
    }

    let mut offset = 0usize;
    let mut first = true;
    while offset < block.len() {
        let chunk = std::cmp::min(max_frame_size, block.len() - offset);
        let is_last = offset + chunk == block.len();
        let mut flags = 0u8;

        if is_last {
            flags |= 0x4;
        }
        if first && end_stream {
            flags |= 0x1;
        }

        let kind = if first { 0x1 } else { 0x9 };
        frames.extend_from_slice(&build_h2_frame_header(chunk, kind, flags, stream_id));
        frames.extend_from_slice(&block[offset..offset + chunk]);

        offset += chunk;
        first = false;
    }

    frames
}

async unsafe fn h2_read_headers_block(
    conn: &mut Connection,
    buf: &mut [u8],
    frame: &H2Frame,
    from_client: bool,
) -> Result<(Vec<u8>, usize), NextStep> {
    let mut consumed_total = 9 + frame.length;
    let mut frag = Vec::new();

    let mut offset = 9;
    let mut remaining = frame.length;
    let mut pad_len = 0usize;

    if frame.flags & 0x8 != 0 {
        if remaining == 0 {
            return Err(h2_connection_error(conn, 0x1, "PADDED with zero length").await);
        }
        pad_len = buf[offset] as usize;
        offset += 1;
        remaining = remaining.saturating_sub(1);
    }

    if frame.flags & 0x20 != 0 {
        if remaining < 5 {
            return Err(
                h2_connection_error(conn, 0x1, "PRIORITY flag missing payload").await
            );
        }
        offset += 5;
        remaining -= 5;
    }

    if remaining < pad_len {
        return Err(h2_connection_error(conn, 0x1, "pad length exceeds payload").await);
    }

    let fragment_len = remaining - pad_len;
    frag.extend_from_slice(&buf[offset..offset + fragment_len]);

    let mut end_headers = frame.flags & 0x4 != 0;

    while !end_headers {
        if conn.in_len < consumed_total + 9 {
            let need = consumed_total + 9 - conn.in_len;
            match h2_read_side_data(conn, buf, from_client, conn.in_len, conn.in_len + need).await
            {
                Ok(n) if n > 0 => conn.in_len += n,
                _ => return Err(NextStep::Close),
            }
        }

        let next_header = parse_h2_frame_header(&buf[consumed_total..consumed_total + 9]);
        if next_header.kind != 0x9 || next_header.stream_id != frame.stream_id {
            return Err(h2_connection_error(conn, 0x1, "expected CONTINUATION").await);
        }

        let next_total = consumed_total + 9 + next_header.length;
        if next_total > conn.in_cap {
            return Err(
                h2_connection_error(conn, 0x6, "CONTINUATION too large for buffer").await
            );
        }

        while conn.in_len < next_total {
            match h2_read_side_data(conn, buf, from_client, conn.in_len, next_total).await {
                Ok(n) if n > 0 => conn.in_len += n,
                _ => return Err(NextStep::Close),
            }
        }

        frag.extend_from_slice(&buf[consumed_total + 9..next_total]);
        consumed_total = next_total;
        end_headers = next_header.flags & 0x4 != 0;
    }

    Ok((frag, consumed_total))
}

async unsafe fn h2_read_side_data(
    conn: &mut Connection,
    buf: &mut [u8],
    from_client: bool,
    start: usize,
    end: usize,
) -> std::io::Result<usize> {
    if from_client {
        read_client_data(conn, &mut buf[start..end]).await
    } else {
        read_upstream_data(conn, &mut buf[start..end]).await
    }
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

fn apply_h2_settings(max_frame_size: &mut usize, payload: &[u8]) {
    let mut offset = 0;
    while offset + 6 <= payload.len() {
        let id = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let value =
            u32::from_be_bytes([payload[offset + 2], payload[offset + 3], payload[offset + 4], payload[offset + 5]]);
        if id == 0x5 {
            let v = value as usize;
            if v >= 16384 && v <= 0x00FF_FFFF {
                *max_frame_size = v;
            }
        }
        offset += 6;
    }
}

async unsafe fn h2_flush_pending_to_upstream(conn: &mut Connection) -> std::io::Result<()> {
    const CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if !conn.h2_upstream_preface_sent && conn.h2_client_preface_seen {
        write_upstream_data(conn, CLIENT_PREFACE).await?;
        let upstream_settings = build_h2_frame_header(0, 0x4, 0x0, 0);
        write_upstream_data(conn, &upstream_settings).await?;
        conn.h2_upstream_preface_sent = true;
    }

    if conn.h2_pending_upstream_frames.is_empty() {
        return Ok(());
    }

    let mut offset = 0;
    let total = conn.h2_pending_upstream_frames.len();
    while offset + 9 <= total {
        let header =
            parse_h2_frame_header(&conn.h2_pending_upstream_frames[offset..offset + 9]);
        let frame_total = 9 + header.length;
        if offset + frame_total > total {
            break;
        }

        if header.kind == 0x4 && (header.flags & 0x1 != 0) {
        } else {
            let end = offset + frame_total;
            let frame_bytes = conn.h2_pending_upstream_frames[offset..end].to_vec();
            write_upstream_data(conn, &frame_bytes).await?;
        }

        offset += frame_total;
    }

    conn.h2_pending_upstream_frames.clear();
    Ok(())
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
        Err(std::io::Error::new(ErrorKind::NotConnected, "client transport missing"))
    }
}

async unsafe fn wait_upstream_transport_readable(conn: &Connection) -> std::io::Result<()> {
    if let Some(ptr) = conn.upstream_tls {
        (*ptr).get_ref().0.readable().await
    } else if let Some(ptr) = conn.upstream_tcp {
        (*ptr).readable().await
    } else {
        Err(std::io::Error::new(
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
        let chunk = std::cmp::min(conn.h2_client_max_frame_size, n - offset);
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

struct H2Frame {
    length: usize,
    kind: u8,
    flags: u8,
    stream_id: u32,
}
