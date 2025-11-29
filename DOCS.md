# Architecture

The proxy is driven by a single-threaded event loop that progresses each connection through a state machine. Every connection owns a `Connection` struct and yields control by returning a `NextStep` that either continues, waits for I/O, or closes the connection; different protocol handlers are chained only after the previous state completes.

### Lifecycle overview

1. **AcceptClientConnection** – listener spins up the `Connection`, caches buffers, and enters the transport handler.
2. **DetectProtocolBegin** – peek the first bytes to classify the client as HTTP/1, HTTP/2, HTTP/3, TLS, or CONNECT.
3. **HandshakeBegin → HandshakeRead → HandshakeComplete** – TLS handshake is MITMed by dynamically creating a certificate for the requested SNI, and the negotiated server name is cached so `upstream_handler` can contact the right host later.
4. **H1/H2/H3 request parsing** – once the protocol is known, the respective handler gathers headers/control frames, records the upstream target (either from `Host`/SNI or explicit CONNECT request), and then drives the shared upstream handshake through `next_state_after_upstream`. CONNECT requests additionally mark whether the upstream leg should skip TLS and move into bidirectional tunneling.
5. **Upstream DNS/TCP/TLS** – the generic upstream handler reads the cached host/port, performs a TCP connect against that target, negotiates TLS with the matching server name, and then resumes whichever protocol enqueued the downstream continuation.
6. **H1/H2/H3 forwarding loop** – send bytes downstream/upstream and repeat until the stream closes.
7. **Close** – tear down sockets and return to the listener.

### Protocol-specific notes

- **H1 handler** collects headers (TCP or TLS), uses `Host:` parsing to store the target host/port, primes `next_state_after_upstream`, and launches the upstream resolution so the request flow can survive the upstream TLS handshake. After the upstream TLS session is ready, the handler continues with request/body forwarding and response media streaming. CONNECT requests are parsed from the request line, dial the requested authority over plain TCP, emit `200 Connection Established`, and then tunnel bytes with `tokio::io::copy_bidirectional`.
- **H2 handler** now accepts the client preface and settings frame, records `next_state_after_upstream`, and reuses the shared upstream result to switch between client-to-upstream and upstream-to-client frame shuttling once the generic upstream path is ready. A minimal CONNECT path looks for `:method CONNECT`/`:authority`, opens a raw TCP upstream (skipping TLS), returns an indexed `:status 200` headers frame, and then maps DATA payloads to raw upstream bytes in both directions.
- **H3 handler** accepts the control stream payload, stores its continuation, and pumps headers/body frames once the upstream TLS path is ready. CONNECT is handled in the same state machine by detecting the CONNECT request line, skipping upstream TLS, replying with a `200 Connection Established`, and tunneling bytes directly.

Shared helper functions (`read_client_data`, `write_client_data`, etc.) simplify the byte-pumping logic across all handlers, and the upstream handler now always consults the cached target stored on `Connection` instead of hard-coded destinations.

## HTTP/2 flow (RFC 9113 aligned)

1. **Detect → TLS → ALPN**: TLS is MITMed; ALPN decides H2 vs H1. For H2 we clear any target derived from SNI so the request target is taken from pseudo-headers, not the SNI.
2. **Client preface**: Read the 24-byte `"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"` preface fully. If it mismatches, send GOAWAY(PROTOCOL_ERROR) and close.
3. **Server preface**: Immediately send our SETTINGS (empty payload = defaults, frame size 16,384) after validating the client preface.
4. **Client SETTINGS**: First frame must be SETTINGS (non-ACK). Length must be a multiple of 6 and ≤ the advertised max frame size; otherwise GOAWAY(FRAME_SIZE_ERROR). ACK with non-zero length is also FRAME_SIZE_ERROR. On success, send SETTINGS ACK.
5. **Frame parse loop**:
   - Enforce max frame size and SETTINGS invariants on subsequent frames; SETTINGS ACK with payload is rejected.
   - Ignore connection-level frames (e.g., WINDOW_UPDATE) until a HEADERS/CONNECT frame arrives to define the target.
   - Only when HEADERS/CONNECT pseudo-headers provide `:authority`/`:method` do we set the target and queue DNS/TCP/TLS upstream work via `next_state_after_upstream`.
6. **CONNECT tunneling**: For `:method CONNECT`, skip upstream TLS, reply with `:status 200` headers, and tunnel DATA frames to/from the upstream TCP stream.
7. **Regular requests**: After target is set and upstream is ready, proxy frames in both directions. Connection errors trigger GOAWAY with the appropriate code.

### CONNECT tunnel specifics (duplex loop)

- After upstream TCP connect completes, immediately send the CONNECT `:status 200` response once (before delivering any upstream data).
- Treat DATA frames on the CONNECT stream as opaque bytes. For each client DATA frame, write the payload (after padding stripping) to the upstream socket. For upstream bytes, emit DATA frames (chunked to the max frame size) back to the client.
- Stay in a duplex loop that waits on whichever side is readable first (client or upstream) so the upstream TLS handshake can progress even if the client pauses. PING/SETTINGS/WINDOW_UPDATE on stream 0 are answered/ignored but do not interrupt the tunnel.
- Close: if upstream EOFs, send an empty DATA frame with END_STREAM; if client sends END_STREAM, half-close upstream (today we just Close).

### What to expect in logs during an H2 CONNECT

1) Detect → TLS → ALPN: client TLS handshake completes, ALPN selects h2.
2) H2 preface: client preface and SETTINGS, we send server SETTINGS + SETTINGS ACK.
3) CONNECT HEADERS: frame parsed on stream > 0; target is set and upstream TCP connect begins.
4) Upstream TCP: `[UPSTREAM] TCP connect established host:port`.
5) Tunnel loop:
   - If no buffered client data: “CONNECT tunnel idle; waiting on client or upstream readability”.
   - On client readiness: “CONNECT tunnel: client became readable”; subsequent “CONNECT DATA frame …” followed by “CONNECT wrote … bytes to upstream”.
   - On upstream readiness: “CONNECT tunnel: upstream became readable”; “CONNECT upstream read N bytes”; “Forwarded N bytes upstream->client on CONNECT stream …”.
   - This alternates until one side closes.
6) Completion: when upstream closes, we send END_STREAM and close; when client closes, we close (future: half-close).

These logs confirm duplex progress (upstream TLS handshake bytes, client handshake responses, then application data) and make it clear which side is driving the tunnel at any moment.

### Testing

- `src/handlers.rs` contains Tokio-based unit tests that create paired `TcpStream`s to simulate clients and upstream peers; the tests cover both H2 and H3 flows, verifying state transitions and that bytes are forwarded in both directions while `next_state_after_upstream` carries the protocol forward.
- `tests/proxy_integration.rs` launches the proxy inside a `LocalSet`, spins up a dummy upstream server, and uses `curl --cacert src/CA/root.pem --http1.1` to verify an end-to-end HTTP/1.x request that tunnels through the MITMed TLS session. This provides a lightweight integration smoke test for the updated H1 flow and host-tracking behavior.
