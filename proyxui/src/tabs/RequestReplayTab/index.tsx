import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ConnectionStateBadge } from "../../components/ConnectionStateBadge";
import { useConnectionStore } from "../../state/connection-store";

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

  const handleReplay = async () => {
    if (!selected) return;
    dispatch({ type: "resume", payload: { id: selected.id } });
    try {
      await invoke("replay_connection", { id: selected.id, payload });
    } catch (error) {
      console.error("replay_connection failed", error);
    }
  };

  const handleDrop = async () => {
    if (!selected) return;
    dispatch({ type: "drop", payload: { id: selected.id } });
    try {
      await invoke("drop_request", { id: selected.id });
    } catch (error) {
      console.error("drop_request failed", error);
    }
  };

  const handleSave = async () => {
    if (!selected) return;
    dispatch({ type: "modify", payload: { id: selected.id, preview: payload } });
    try {
      await invoke("save_to_collection", { id: Number(selected.id) });
      console.log("Saved replay payload for", selected.id);
    } catch (error) {
      console.error("save_to_collection failed", error);
    }
  };

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
              <p className="replay-grid__preview">
                {selected.bodyPreview || "Preview unavailable for this request."}
              </p>
              <textarea
                value={payload}
                onChange={(event) => setPayload(event.currentTarget.value)}
                className="payload-editor"
                rows={8}
              />
              <div className="action-row">
                <button type="button" onClick={handleReplay}>
                  Replay request
                </button>
                <button type="button" className="ghost-btn" onClick={handleDrop}>
                  Drop request
                </button>
                <button type="button" className="ghost-btn" onClick={handleSave}>
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
