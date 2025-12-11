## Done

- Config discovery now walks up the tree and normalizes `ca_dir`, allowing both the CLI proxy and the Tauri shell to share the same CA artifacts even when launched from different working directories.
- `ProxyState` streams headers, sizes, durations, tags, and previews, and the Live Intercept and Request Replay tabs consume that metadata to surface better badges, previews, and size indicators.
- Modify/drop intercept commands now resolve to concrete decisions so waiting requests either resume or drop with the appropriate status; the UI queues edited bodies inside `ProxyState`.

## Next Steps

1. Replay the modified payload: reconstruct the edited request body (`Incoming`) before resuming interceptions so downstream servers see the latest edits instead of the original stream.
2. Extend replay helpers with persistence/scheduling so Saved collections can pre-populate the editor or be replayed on a schedule, and surface saved metadata in the UI.
3. Add integration/unit coverage for the `ConnectionStore`, Tauri commands, and `proxy-event` wiring (including the live intercept queue) so each tab’s invocations stay reliable.
4. Evaluate UI scalability: add virtualization/pagination or memoized selectors when histories grow large, and keep enriching `ProxyState` metadata to power richer filtering and badges.
5. Keep `ui_mode_design.md` and this README in sync with the renderer so new contributors understand how each tab consumes the backend and which commands/events exist.
