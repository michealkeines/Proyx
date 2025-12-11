import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ConnectionStateBadge } from "../../components/ConnectionStateBadge";
import { useConnectionStore } from "../../state/connection-store";

const directionLabels = {
  client_to_server: "Client → Server",
  server_to_client: "Server → Client",
} as const;

const formatWsTimestamp = (timestampMs: number) =>
  new Date(timestampMs).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

export const RequestReplayTab = () => {
  const { state, dispatch } = useConnectionStore();
  const [payload, setPayload] = useState("");

  const sortedConnections = useMemo(() => {
    return [...state.connections].sort((a, b) => (a.timestamp > b.timestamp ? -1 : 1));
  }, [state.connections]);

  const selected = state.connections.find((connection) => connection.id === state.selectedConnectionId) ?? sortedConnections[0];

  useEffect(() => {
    if (selected) {
      setPayload(selected.bodyPreview);
    }
  }, [selected?.id]);

  const isWebsocket = selected?.isWebsocket ?? false;

  const requestRaw = selected
    ? `${selected.method} ${selected.protocol.toUpperCase()}://${selected.host}${selected.path}\n${selected.requestHeaders
        .map((header) => `${header.name}: ${header.value}`)
        .join("\n")}\n\n${selected.bodyPreview || ""}`
    : "";

  const responseBodyText = selected?.responseBodyPreview || "Response preview unavailable for this request.";

  const handleReplay = async () => {
    if (!selected || isWebsocket) return;
    dispatch({ type: "resume", payload: { id: selected.id } });
    try {
      await invoke("replay_connection", { id: selected.id, payload });
    } catch (error) {
      console.error("replay_connection failed", error);
    }
  };

  const handleDrop = async () => {
    if (!selected || isWebsocket) return;
    dispatch({ type: "drop", payload: { id: selected.id } });
    try {
      await invoke("drop_request", { id: selected.id });
    } catch (error) {
      console.error("drop_request failed", error);
    }
  };

  const handleSave = async () => {
    if (!selected || isWebsocket) return;
    dispatch({ type: "modify", payload: { id: selected.id, preview: payload } });
    try {
      await invoke("save_to_collection", { id: Number(selected.id) });
      console.log("Saved replay payload for", selected.id);
    } catch (error) {
      console.error("save_to_collection failed", error);
    }
  };

  const renderHeaders = (headers: Array<{ name: string; value: string }>) =>
    headers.length ? (
      <ul className="header-list">
        {headers.map((header, index) => (
          <li key={`${header.name}-${index}`}>
            <strong>{header.name}:</strong> {header.value}
          </li>
        ))}
      </ul>
    ) : (
      <p className="header-list__empty">No headers captured for this request.</p>
    );

  return (
    <section className="tab-panel request-replay-tab">
      <div className="replay-grid">
        <div className="replay-grid__list">
          <h2>History</h2>
          <ul>
            {sortedConnections.map((connection) => (
              <li key={connection.id}>
                <button
                  type="button"
                  className={`replay-grid__item ${selected?.id === connection.id ? "is-active" : ""}`}
                  onClick={() => dispatch({ type: "select", payload: { id: connection.id } })}
                >
                  <div>
                    <p className="replay-grid__title">{connection.method} {connection.path}</p>
                    <p className="replay-grid__sub">{connection.host}</p>
                  </div>
                  <ConnectionStateBadge state={connection.state} timestamp={connection.timestamp} durationMs={connection.durationMs} />
                </button>
              </li>
            ))}
          </ul>
        </div>
        <div className="replay-grid__editor">
          {selected ? (
            <>
              <header className="replay-grid__header">
                <div>
                  <p className="replay-grid__label">Selected request</p>
                  <h3>{selected.method} {selected.path}</h3>
                </div>
                <div className="replay-grid__meta">
                  <span>{selected.host}</span>
                  <span>Status {selected.status}</span>
                  <span>
                    Request{" "}
                    {selected.requestSize
                      ? `${selected.requestSize.toLocaleString()} B`
                      : "size unknown"}
                  </span>
                </div>
              </header>
              <section className="request-replay__details">
                <div className="request-replay__section">
                  <p className="request-replay__section-label">Original request</p>
                  <textarea readOnly className="request-replay__raw" value={requestRaw.trim()} />
                </div>
                <details open className="request-replay__section">
                  <summary>Request headers</summary>
                  {renderHeaders(selected.requestHeaders)}
                </details>
                <details open className="request-replay__section">
                  <summary>Response headers</summary>
                  {renderHeaders(selected.responseHeaders)}
                </details>
                <div className="request-replay__section">
                  <p className="request-replay__section-label">Response preview</p>
                  <textarea readOnly className="request-replay__raw" value={responseBodyText} />
                </div>
              </section>
              {isWebsocket && (
                <p className="websocket-note">
                  WebSocket connections bypass the intercept queue, so we only log their handshake.
                </p>
              )}
              {isWebsocket && (
                <section className="websocket-log">
                  <header className="websocket-log__header">
                    <h3>WebSocket exchanges</h3>
                    <span>{selected.wsEvents.length} messages</span>
                  </header>
                  <ul>
                    {selected.wsEvents.map((event, index) => (
                      <li key={`${event.timestampMs}-${index}`} className="websocket-log__item">
                        <div>
                          <span className="websocket-log__direction">{directionLabels[event.direction]}</span>
                          <span className="websocket-log__time">{formatWsTimestamp(event.timestampMs)}</span>
                        </div>
                        <p className="websocket-log__payload">
                          {event.payloadPreview || "Binary payload"}
                        </p>
                      </li>
                    ))}
                    {!selected.wsEvents.length && (
                      <li className="websocket-log__empty">Waiting for WebSocket frames…</li>
                    )}
                  </ul>
                </section>
              )}
              <textarea
                value={payload}
                onChange={(event) => setPayload(event.currentTarget.value)}
                className="payload-editor"
                rows={8}
              />
              <div className="action-row">
                <button type="button" onClick={handleReplay} disabled={isWebsocket}>
                  Replay request
                </button>
                <button type="button" className="ghost-btn" onClick={handleDrop} disabled={isWebsocket}>
                  Drop request
                </button>
                <button type="button" className="ghost-btn" onClick={handleSave} disabled={isWebsocket}>
                  Save to collection
                </button>
              </div>
            </>
          ) : (
            <p className="tab-panel__empty">Select a request to inspect before replaying.</p>
          )}
        </div>
      </div>
    </section>
  );
};
