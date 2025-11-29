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

### Testing

- `src/handlers.rs` contains Tokio-based unit tests that create paired `TcpStream`s to simulate clients and upstream peers; the tests cover both H2 and H3 flows, verifying state transitions and that bytes are forwarded in both directions while `next_state_after_upstream` carries the protocol forward.
- `tests/proxy_integration.rs` launches the proxy inside a `LocalSet`, spins up a dummy upstream server, and uses `curl --cacert src/CA/root.pem --http1.1` to verify an end-to-end HTTP/1.x request that tunnels through the MITMed TLS session. This provides a lightweight integration smoke test for the updated H1 flow and host-tracking behavior.
