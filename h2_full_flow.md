# HTTP/2 Full Flow (Detailed + ASCII Diagrams)

This document captures a **complete end-to-end HTTP/2 flow** between:

**Client → Proxy (MITM-capable) → Server**

The proxy can inspect, decode, modify, and re-encode H2 traffic.  
All low-level details (TCP, TLS/ALPN, H2 preface, HPACK, frames, streams) are included.

---

# 1. Overview of Components

```
Client  →  Proxy (frontend H2 endpoint)
            Proxy (backend H2 endpoint)  →  Server
```

The proxy terminates the TLS session with the client and establishes a separate TLS + H2 session with the server.

---

# 2. TCP + TLS (ALPN) Negotiation

### 2.1 Client → Proxy TCP Handshake

```
Client                               Proxy
  | ---- SYN -----------------------> |
  | <--- SYN/ACK ---------------------|
  | ---- ACK ------------------------>|
```

### 2.2 TLS Handshake (Proxy acting as MITM)

```
Client                                       Proxy                                    Server
  | ---- ClientHello (ALPN: h2,http/1.1) --> |
  |                                          | ---- ClientHello (ALPN: h2) ---------> |
  |                                          | <--- ServerHello + Cert --------------|
  | <--- ServerHello + ProxyCert ------------|
  | ---- Finished -------------------------->|
  |                                          | ---- Finished ------------------------>|
  | <--- Finished ---------------------------|
```

The proxy now decrypts all the client's H2 traffic.

---

# 3. HTTP/2 Connection Preface

Client sends the required connection preface:

```
PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
```

Proxy forwards or regenerates the equivalent towards the server.

---

# 4. Initial SETTINGS Exchange

### Client → Proxy:

```
SETTINGS
  SETTINGS_HEADER_TABLE_SIZE=4096
  SETTINGS_ENABLE_PUSH=1
  SETTINGS_MAX_CONCURRENT_STREAMS=1000
  SETTINGS_INITIAL_WINDOW_SIZE=65535
```

### Proxy → Server (may modify defaults):

```
SETTINGS
  SETTINGS_HEADER_TABLE_SIZE=2048
  SETTINGS_ENABLE_PUSH=0
  SETTINGS_MAX_CONCURRENT_STREAMS=100
  SETTINGS_INITIAL_WINDOW_SIZE=65535
```

Bidirectional ACKs follow.

---

# 5. HTTP/2 Request Flow (GET example)

## 5.1 Client → Proxy Frames

Client opens **Stream 1**:

```
+--------------------------------------------+
| HEADERS (stream=1, END_HEADERS)            |
|   :method      = GET                       |
|   :scheme      = https                     |
|   :path        = /api/data                 |
|   :authority   = example.com               |
|   user-agent   = MyBrowser/1.0             |
+--------------------------------------------+
```

No DATA frames (GET request body is empty).

---

# 6. Proxy Internal Processing (Frontend)

```
1. Receive TLS record → decrypt
2. Extract H2 frames from record layer
3. Identify stream (ID=1)
4. HPACK-decode HEADERS block:
      - update dynamic table
5. Policy engine: filtering, modification, inspection
6. Potential rewrites:
      - Change :path
      - Add/remove headers
      - Inject forwarding metadata (x-proxy-*)
7. HPACK-encode new header block (backend dynamic table)
8. Construct outbound HEADERS frame
9. Send over backend TLS session
```

---

# 7. Proxy → Server Frames (Modified)

```
HEADERS (stream=1, END_HEADERS)
   :method      = GET
   :scheme      = https
   :path        = /api/data?via=proxy
   :authority   = example.com
   x-proxy-added = true
```

---

# 8. Server Response Flow

```
HEADERS (stream=1, END_HEADERS)
   :status      = 200
   content-type = application/json

DATA (stream=1)
   {"msg":"ok"}

DATA (stream=1, END_STREAM)
```

---

# 9. Proxy Processing (Backend → Frontend)

```
1. Receive TLS record → decrypt
2. Parse H2 frame header
3. For HEADERS:
      - HPACK-decode using backend table
4. For DATA:
      - buffer and optionally modify body
5. Apply filters/modifiers:
      - adjust :status
      - insert headers
      - rewrite JSON or HTML
6. HPACK-encode new HEADERS block for client table
7. Emit modified HEADERS/DATA frames to client
```

---

# 10. Proxy → Client Modified Response

```
HEADERS (stream=1, END_HEADERS)
   :status        = 200
   content-type   = application/json
   x-proxy        = intercepted

DATA (stream=1)
   {"msg":"ok"}

DATA (stream=1, END_STREAM)
```

---

# 11. Full ASCII Pipeline (Request + Response)

```
              ┌──────────────────────────────────────────┐
              │                 CLIENT                    │
              └───────────────────┬───────────────────────┘
                                  │ TLS (ALPN=h2)
                                  ▼
                      ┌──────────────────────────┐
                      │     PROXY FRONTEND       │
                      │  - TLS decrypt           │
                      │  - H2 frame parse        │
                      │  - HPACK decode          │
                      └────────────┬─────────────┘
                                   │ modify headers/body
                                   ▼
                      ┌──────────────────────────┐
                      │     PROXY BACKEND        │
                      │  - HPACK encode          │
                      │  - H2 framing            │
                      │  - TLS encrypt           │
                      └────────────┬─────────────┘
                                   │
                                   ▼
                           ┌───────────────┐
                           │    SERVER      │
                           └───────────────┘
```

---

# 12. Connection-State Queue (H2 → canonical HTTP)

The frontend H2 handler now keeps a **single connection state** that owns a queue of canonical `HTTPRequest` objects. Each stream contributes to that queue:

1. Frames from the client are parsed (HEADERS, DATA, END_STREAM) and used to build a full `HTTPRequest`.
2. When a `FullRequestParsed` event occurs for a stream, the resulting object is appended to the queue instead of immediately triggering frame-level forwarding.
3. A dispatcher watches the queue and, when the front entry is ready, converts it into the required upstream form (still H2, but the conversion now happens once per request rather than per frame).
4. Response handling mirrors the same flow: upstream responses are read into canonical `HTTPResponse` objects and queued/matched to the originating stream before being re-encoded for the client.

This keeps multiplexed request/response state localized to one queue per connection, avoids racing on partial frames, and ensures we only send upstream once the complete request (or response) is available.

# 13. Reliability & Next Steps

**Architecture**
- The shared `Connection` state owns the raw pointers, queues, and partial stream builders so every handler (settings, parser, dispatcher) works through canonical structs instead of ad-hoc frame forwarding.
- The dispatcher only writes to the upstream/client once a whole request/response is ready, ensuring frame reassembly (headers + body) happens exactly once per stream even if DATA arrives on many frames.
- Maintaining this in a single state machine lets us hook in policy controllers and transformation layers between the queue and the re-encoding step.

**Edge cases to consider**
1. Flow-control / window updates: even though we queue complete requests, we still need to copy connection-level WINDOW_UPDATE frames through so the upstream/client can continue to send DATA; dropping or delaying those would stall a stream (or the whole connection).
2. Stream resets / GOAWAY: if a stream is reset while we are buffering its request/response, we must purge any pending queue entries and ensure resets propagate to their paired stream to avoid dangling canonical objects.
3. HPACK dynamic table divergence: different header encoders for client/upstream mean we must still track per-connection encoder state and the queue must not assume header blocks stay usable after re-encoding.
4. Large bodies: buffering full request/response bodies might require streaming within the canonical object or back-pressure signals so we do not overflow the proxy’s buffers while waiting for END_STREAM.
5. Prioritization/multiplexing fairness: queuing forces FIFO dispatch; if the upstream cannot keep up with the queue head, we may need to dequeue out-of-order or resume stalled streams once the head finishes.
6. CONNECT tunnels and upgrade semantics need to bypass the canonical queue (already gated by `CONNECT`) but we still need to guard the queue state in case a tunnel stream arrives before the canonical dispatcher drains earlier streams.

**Next improvements**
1. Add visibility hooks around the dispatcher so the controller can mutate canonical `HTTPRequest`/`HTTPResponse` structs (e.g., inject headers, log bodies) before they are re-encoded.
2. Introduce per-stream throttling tokens (or chunked body slices) so large uploads do not block the queue indefinitely; consider streaming canonical objects via iterators instead of collecting everything.
3. Bake regression tests around partial frame sequences, stream resets, and window updates to prove that the queue doesn’t deliver outputs until a stream is fully parsed, and that flow control remains sane.

# END
