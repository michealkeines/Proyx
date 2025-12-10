# UI Mode Design

This file captures the planned multi-tab UI mode for the proxy, building on top of
the Tauri 2.9.5 stack. The goal is to support the three connection states
request / intercept / response while remaining modular and scalable.

## Architecture Overview

- **Tauri shell + framework UI**: The Tauri backend exposes the proxy state machine
  via typed commands (`tauri::command`) and data feeds (e.g., event emitters or watchers).
  The renderer (e.g., React/Solid/Svelte) lives in `src-tauri/../dist`, consumes APIs
  defined in `tauri::Builder`, and uses `@tauri-apps/api` to send invocations like
  `send_request`, `toggle_live_intercept`, etc.
- **State layer**: Keep a dedicated store (Redux-style / signal-based) that tracks
  per-connection metadata (request, intercept flags, response) and UI mode (tab
  selection, live intercept enabled). This store should be hydrated on startup via
  `tauri::invoke("get_active_connections")` and then updated through event listeners.
- **Modularity**: Each tab lives in its own directory (e.g., `tabs/SiteMap`, `tabs/Replay`),
  exporting a panel component plus metadata for registering it with the tab bar.
  Shared components such as `ConnectionTable`, `RequestPreview`, and `StateBadge`
  live under `components` and consume the global store.

## Tab Layout

1. **Site Map Tab**
   - Visualize the tree of domains / hosts handled by the proxy.
   - Show request/response summaries as nodes; clicking a node opens the details
     panel with request metadata, replay controls, and response previews.
   - Provide filters (protocol, status, intercept state) so large trees remain navigable.
2. **Request Replay Tab**
   - Present a list view (or table) of historical requests keyed by timestamp or ID.
   - Allow selecting any request and editing headers/body before replaying.
   - Expose quick actions: `Replay request`, `Drop request`, `Save to collection`.
3. **Live Intercept Tab**
   - Contains a toggle switch for enabling/disabling live intercept mode.
   - When enabled, new requests land in a queue and render inside this tab with
     action buttons for `Resume`, `Modify`, `Drop`.
   - Each queued request includes a badge showing its current state (request/intercept/response).
   - The live queue is paginated or grouped by host so UI stays responsive under load.

Tabs should be registered through a simple descriptor array:

```ts
const tabs = [
  { id: "site-map", title: "Sitemap", component: SiteMapTab, priority: 1 },
  { id: "replay", title: "Request Replay", component: ReplayTab, priority: 2 },
  {
    id: "live-intercept",
    title: "Live Intercept",
    component: LiveInterceptTab,
    badge: liveQueueCount,
  },
];
```

This descriptor drives the shared `TabBar` component so adding new modes later
only requires registering them here.

## Connection States in UI

Each connection has three primary states:

- `request`: request metadata available, waiting for proxy to decide.
- `intercept`: connection is paused, waiting on user action.
- `response`: response data received, ready to display or replay.

UI elements (buttons, badges, summaries) display via a `ConnectionStateBadge`
component that maps the current state to colors/icons and hints. The badge can
also surface timestamps (e.g., how long the connection has been paused).

The live intercept panel is the only place where `intercept` requests remain
blocked until the user clicks **Resume**. While the toggle is on, the backend
rathen than auto-forwarding connections should keep them in the intercept queue
and emit `ConnectionIntercepted` events to update the UI.

## Modularity & Scalability

- **Componentization**: Tab containers only orchestrate the layout; shared logic
  (filters, sorting, pagination) lives in hooks/services.
- **Command/Event layer**: Backend exposes targeted commands such as
  `toggle_live_intercept`, `release_intercept`, `replay_connection`. Commands
  return lightweight DTOs; they never bundle rendering or state concerns.
- **Plugin-friendly**: Tabs register via the descriptor above and optionally
  expose extension points (`onSelect`, `onClose`) so future modes can augment
  the tab bar without touching its core.
- **Performance**: Limit re-renders by memoizing heavy lists and virtualizing long tables.
  Shared components access the store through selectors to avoid unnecessary updates.

## Current Implementation Notes

- The Rust shell is now structured like the example template (`proyx_ui_lib`), so `build.rs` runs the Tauri codegen, the tray/menu/plugins are wired before `tauri::Builder`, and `src-tauri/src/main.rs` merely delegates to `run()`.
- Commands such as `get_connections`, `toggle_live_intercept`, and `resume_intercept` emit `Result` values and the event stream now uses `AppHandle::emit`. The backend list/resume logic stays in `proxy-backend`, and the renderer (per README) lives under `src-tauri/dist`.
- `src-tauri/tauri.conf.json` retains the expected `bundle`/`build`/`app` schema from the example, points `frontendDist` at `../dist`, and reuses the copied icon/capability assets so the configuration parses cleanly.

## Next Steps

1. Replace the example renderer under `src-tauri/dist` with the actual multi-tab layout described earlier, wiring each tab to the shared commands/events we now expose.
2. Implement request editors/modifiers for intercepted payloads so the Live Intercept tab can surface `Modify`/`Save` and send annotated data back through new Tauri commands (e.g., `modify_intercept`, `save_request`).
3. Add richer filters, pagination, and virtualization for the site map and replay tables so the UI stays responsive under load; reuse helper services so layout components stay lightweight.
4. Introduce integration tests or harnesses that exercise `ProxyState` events + Tauri commands to ensure the UI and backend stay in sync when toggling live intercept, resuming connections, and replaying traffic.
5. Expand documentation (`README.md`, `ui_mode_design.md`, etc.) with rollout steps for the renderer toolchain, the Tauri workspace structure, and how to trust/build the bundled `proyx-ui` binary.
