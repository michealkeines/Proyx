# UI Mode Design

This file captures the live UI experience for the proxy, starting from the current
React/Vite renderer that sits behind the Tauri shell.

## Architecture Overview

- **Tauri shell + framework UI**: `proyxui/src-tauri/src/lib.rs` runs `MitmProxy`, exposes commands
  (`get_connections`, `get_intercept_queue`, `toggle_live_intercept`, `resume_intercept`,
  `replay_connection`, `drop_request`, `modify_intercept`, `drop_intercept`, `save_to_collection`)
  and emits every `ProxyEvent` through `AppHandle::emit("proxy-event", …)`. The renderer under `proyxui/src`
  uses `@tauri-apps/api/core` + `@tauri-apps/api/event` to call those commands and listen for updates.
- **State layer**: `src/state/connection-store.tsx` hydrates from `get_connections`/`get_intercept_queue`,
  normalizes backend snapshots into `Connection` objects, listens to `proxy-event`, and exposes `dispatch`
  helpers so the tabs can select, resume, drop, modify, and toggle live intercept.
- **Modularity**: Tabs live under `src/tabs/*` and are registered via `src/tabs/descriptors.ts`.
  Each tab owns its layout and actions while shared helpers like `ConnectionStateBadge` capture
  the request/intercept/response status indicators.

## Tab Layout

1. **Site Map Tab**
   - Visualize connections grouped by host, with per-connection badges showing the current state.
   - Filters (protocol, state) live inside the tab and reduce `state.connections` prior to grouping.
   - Each entry provides a “View details” button that dispatches the `select` action so the preview card
     (shown in `App.tsx`) updates accordingly.
2. **Request Replay Tab**
   - Shows historical requests sorted by timestamp. Selecting an item loads its `bodyPreview` into the editor.
   - Allows editing the payload and replaying/dropping/saving through the store’s reducer actions and the
     corresponding Tauri commands (`replay_connection`, `drop_request`, `save_to_collection`).
   - The payload editor is controlled, so updates are preserved in the reducer via the `modify` action.
3. **Live Intercept Tab**
   - Displays intercepted connections grouped by host with Resume/Modify/Drop buttons.
   - Toggles live intercept through `toggle_live_intercept` (which flips `state.liveInterceptEnabled` and calls
     the backend command). Each action invokes the matching command (`resume_intercept`, `modify_intercept`, `drop_intercept`)
     after updating the reducer state for optimistic feedback.
   - Badges show the connection state; the tab also reports the queue size by reading `state.connections`.

Descriptors register these tabs with the shared `TabBar`, so new panels only need a descriptor entry.

## Connection States in UI

Each connection snapshot from the backend is normalized to `Connection` (see `connection-store.tsx`) and assigned one of: `request`, `intercept`, or `response`.
- `request` entries are newly observed and still awaiting action.
- `intercept` entries have been marked by the proxy and show up in the Live Intercept queue.
- `response` indicates the downstream client has finished and the response metadata is available.

The `ConnectionStateBadge` component renders the current state, timestamp, and summary (read/write sizes are placeholders until richer metadata is pumped through).

## Modularity & Scalability

- **Componentization**: Tabs focus on rendering while memoized selectors/filter logic lives inside `useMemo`.
- **Command/Event Layer**: Tabs invoke backend commands via `invoke`. The store listens to `proxy-event` so every `ProxyEvent::ConnectionUpdated`
  and `ProxyEvent::LiveInterceptToggled` can refresh the reducer state without manual polling.
- **Plugin-friendly**: The descriptor array in `src/tabs/descriptors.ts` makes introducing new tabs trivial; each tab exports its panel component and optional badge.
- **Performance**: Filtering/grouping already memoizes the output; consider virtualization when real connection volumes grow and the renderer must stay responsive.

## Current Implementation Notes

- The renderer is React-based; `src/main.tsx` mounts `App.tsx`, which renders the header, focused connection preview, tab bar, and active panel.
- `ConnectionProvider` wraps the app, keeps the reducer, and wires to Tauri via `invoke`/`listen`.
- Each tab takes dependencies from `useConnectionStore` and issues commands through the store's actions + `invoke` wrappers.
- The Tauri backend (in `proyxui/src-tauri/src/lib.rs`) manages the proxy state, proxies commands to `ProxyState`, and emits `proxy-event` updates when snapshots change.

## Next Steps

1. Pump additional metadata through `ProxyState` (headers, durations, body previews) so the reducer can surface more informative badges and filters.
2. Let `modify_intercept`/`drop_intercept` mutate the actual waiting requests instead of just logging the payload size, and preserve modified bodies inside the store.
3. Add replay helpers that persist collections, allow scheduling, or pre-populate request editors for later use.
4. Introduce integration tests for the Tauri commands/event stream plus renderer tests that assert each tab issues the correct `invoke` calls.
5. Keep this document aligned with the React renderer and `README.md` so future contributors understand how the UI consumes the backend.
