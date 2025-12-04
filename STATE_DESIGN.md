# State-Based Proxy Architecture (H1 + H2)

This notes the plan for collapsing the existing sprawling state machine into a lean, canonical pipeline inspired by the
working MITM proxy in `other/`. That implementation already processes each request as a ``hyper`` `Request`/`Response`
pair, lets a controller mutate `Request`/`Response`, and multiplexes H2 streams through a single Tokio task. We now
reconcile that style with our `raw`-pointer buffers and state-based driver.

## Guiding principles

- **Single pipeline per protocol** – only H1 and H2 remain; H3 is removed entirely. H1 reuse the existing `H1Session`
  raw-buffers, while H2 introduces a canonical queue (`CanonicalRequest`, `CanonicalResponse`) that mimics event
  replay in `other/lib.rs`.
- **State transitions drive chaining** – every state returns a `NextStep` that names the next `ProxyState`, so we can
  continue pumping the same connection (`drive_connection`) without tangled callbacks.
- **Raw pointers stay localized** – the state machine owns the lifecycle of every `NonNull<u8>` buffer (headers/body).
  States move the buffer pointer along rather than re-allocating at every frame, mirroring how `hyper` buffers
  and yields completed bodies.
- **Intercept hooks stay central** – before every upstream dispatch we hit an intercept controller, letting the
  `service_fn` in `other/lib.rs` mutate request metadata.

## ProxyState (new union)

```
enum ProxyState {
    TransportBootstrap,
    TransportIo,
    TlsHandshake,
    ProtocolSelect,        // decide H1 vs H2 (ALPN or first byte)
    ConnectionReady,       // both TLS and transport are settled
    H1Session(H1State),
    H2Session(H2State),
    Intercept(InterceptState),
    Upstream(UpstreamState),
    Shutdown(ShutdownState),
}
```

By the time we reach `H1Session` or `H2Session`, ALPN has already decided the path. There is no `H3State` anymore.
`TransportBootstrap`, `TlsHandshake`, and `ProtocolSelect` remain so we can reuse the existing bootstrapping logic.

## H1State (canonical request/response flow)

```
enum H1State {
    RequestHeaders,            // read headers frame + pseudo state (raw pointer use)
    RequestBody,               // read body into raw buffer (chunked vs len)
    RequestReadyForController, // expose `H1Session` to intercept
    DispatchToUpstream,        // start connect/DNS/forward (reuses UpstreamState)
    ResponseHeaders,           // read ack/body from upstream
    ResponseBody,              // stream body back to client
    ResponseComplete,          // finalize keep-alive/close decisions
}
```

- **Raw pointers:** `RequestHeaders`/`RequestBody` operate on the `H1Session.headers`/`body` `NonNull` buffers so we never
  reallocate on partial frames; the state transitions simply move `headers_count`/`body_len` tracking forward.
- **Chaining:** `RequestReadyForController` transitions to `Intercept(InterceptState::Pipeline)`; if the controller
  makes an early decision, we branch back to `ResponseComplete`, otherwise we go to `DispatchToUpstream`.
- **Push-through:** when `DispatchToUpstream` finishes, `next_state_after_upstream` expects to land in
  `H1State::ResponseHeaders`, so we can resume the client-facing loop.

## H2State (canonical queue + frame reassembly)

```
enum H2State {
    Bootstrap,                // client preface + SETTINGS
    ClientFrameParse,         // read next frame header/payload
    BuildCanonicalRequest,    // HPACK decode + raw pointer copy into `CanonicalRequest`
    RequestQueueEnqueue,      // place canonical request into queue
    ControllerHook,           // run intercept logic (like the `service_fn` in `other/lib`)
    DispatchToUpstream,       // encode request headers/DATA + write through TLS
    UpstreamFrameCollect,     // read HEADERS/DATA from upstream into canonical response
    ResponseDispatch,         // HPACK encode + emit to client
    TransportWait,            // window updates, stream events, socket pumping
}
```

- **Canonical queue:** `BuildCanonicalRequest` fills a `CanonicalRequest` struct that owns raw header/body buffers (`NonNull<u8>`)
  instead of streaming each frame immediately. Once `RequestQueueEnqueue` completes, the dispatcher ensures only a single
  canonical object is sent upstream at a time (mirroring the canonical queue in `h2_full_flow.md` section 12).
- **Controller hook:** the intercept state exposes the canonical request/response pair so the `service_fn` middleware in
  `other/lib.rs` is conceptually the same as our `InterceptState::Pipeline` state.
- **Flow control:** `TransportWait` handles connection-level WINDOW_UPDATE and `PING` frames, ensuring we still pump the
  socket even while waiting for canonical objects to finish.

## Intercept + upstream helpers

- `InterceptState` now has two sub-states: `Pipeline` (request/response mutation) and `Drop` (rejecting/closing). Every
  request runs through `Pipeline` before we call `DispatchToUpstream`.
- `UpstreamState` stays responsible for DNS/TCP/TLS but is now only reached from `H1State::DispatchToUpstream` or
  `H2State::DispatchToUpstream`. After upstream completion, we resume the session in `ResponseHeaders`/`UpstreamFrameCollect`.

## Raw pointers + chaining notes

- Each canonical object references `H1Session` or H2 per-stream buffers via `NonNull<u8>`, so we maintain ABI control
  while letting the state machine manage buffer lifetime (`allocate_body`, drop in `H1Session`, etc.).
- States chain explicitly: `NextStep::Continue(ProxyState::H2Session(H2State::ClientFrameParse))` and similar ensures
  we never spawn extra tasks. This mirrors `hyper`’s event loop but keeps our state machine deterministic.
- The intercept hook can swap out canonical headers/bodies using the same heuristics demonstrated in `other/lib.rs`
  (mutating the request URI, injecting proxy headers, logging).

## Next steps for integration

1. Replace the old `ProxyState`/`H1State`/`H2State` enums with the ones above, removing the H3 guardrails entirely.
2. Rework `handlers/h1.rs` and `handlers/h2.rs` to follow the simplified pipeline: read headers/body, enqueue canonical
   object, run controller, dispatch, resume response.
3. Keep `states::H1Session` and its raw pointer helpers, but expose a `CanonicalRequestView`/`CanoncialResponseView`
   to the intercept layer.

This design keeps the raw-pointer buffering/chaining you currently rely on while importing the clarity of the working
`other` MITM implementation.
