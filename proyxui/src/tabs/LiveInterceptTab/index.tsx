import { useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Connection } from "../../state/connection-store";
import { ConnectionStateBadge } from "../../components/ConnectionStateBadge";
import { useConnectionStore } from "../../state/connection-store";

export const LiveInterceptTab = () => {
  const { state, dispatch } = useConnectionStore();

  const intercepted = useMemo(
    () => state.connections.filter((connection) => connection.state === "intercept"),
    [state.connections],
  );

  const groupedByHost = useMemo(() => {
    const map: Record<string, Connection[]> = {};
    intercepted.forEach((connection) => {
      if (!map[connection.host]) {
        map[connection.host] = [];
      }
      map[connection.host].push(connection);
    });
    return map;
  }, [intercepted]);

  const toggleLiveIntercept = async () => {
    const nextState = !state.liveInterceptEnabled;
    dispatch({ type: "toggleLiveIntercept" });
    try {
      await invoke("toggle_live_intercept", { enabled: nextState });
    } catch (error) {
      console.error("toggle_live_intercept failed", error);
    }
  };

  const handleResume = async (connection: Connection) => {
    dispatch({ type: "resume", payload: { id: connection.id } });
    try {
      await invoke("resume_intercept", { id: connection.id });
    } catch (error) {
      console.error("resume_intercept failed", error);
    }
  };

  const handleModify = async (connection: Connection) => {
    const preview = connection.bodyPreview
      ? `${connection.bodyPreview}\n// modified in UI`
      : "// modified in UI";
    dispatch({ type: "modify", payload: { id: connection.id, preview } });
    try {
      await invoke("modify_intercept", { id: connection.id, preview });
    } catch (error) {
      console.error("modify_intercept failed", error);
    }
  };

  const handleDrop = async (connection: Connection) => {
    dispatch({ type: "drop", payload: { id: connection.id } });
    try {
      await invoke("drop_intercept", { id: connection.id });
    } catch (error) {
      console.error("drop_intercept failed", error);
    }
  };

  return (
    <section className="tab-panel live-intercept-tab">
      <div className="live-intercept-tab__top">
        <label className="toggle-chip">
          <input
            type="checkbox"
            checked={state.liveInterceptEnabled}
            onChange={toggleLiveIntercept}
          />
          <span>
            Live intercept {state.liveInterceptEnabled ? "enabled" : "paused"}
          </span>
        </label>
        <p>Active queue: {intercepted.length}</p>
      </div>

      {!intercepted.length ? (
        <p className="tab-panel__empty">No intercepted requests in the queue.</p>
      ) : (
        <div className="live-queue">
          {Object.entries(groupedByHost).map(([host, connections]) => (
            <div className="live-queue__group" key={host}>
              <header>
                <h3>{host}</h3>
                <span className="live-queue__badge">{connections.length} pending</span>
              </header>
              {connections.map((connection) => (
                <article className="live-queue__item" key={connection.id}>
                  <div>
                    <ConnectionStateBadge
                      state={connection.state}
                      timestamp={connection.timestamp}
                      durationMs={connection.durationMs}
                    />
                    <p className="live-queue__path">
                      {connection.method} {connection.path}
                    </p>
                    <p className="live-queue__meta">
                      {(connection.tags.length ? connection.tags.join(" · ") : "No tags")} ·{" "}
                      {connection.protocol.toUpperCase()}
                    </p>
                    {connection.bodyPreview && (
                      <p className="live-queue__preview">{connection.bodyPreview}</p>
                    )}
                    <p className="live-queue__meta">
                      Request{" "}
                      {connection.requestSize
                        ? `${connection.requestSize.toLocaleString()} B`
                        : "unknown size"}
                    </p>
                  </div>
                  <div className="live-queue__actions">
                    <button type="button" onClick={() => handleResume(connection)}>
                      Resume
                    </button>
                    <button type="button" className="ghost-btn" onClick={() => handleModify(connection)}>
                      Modify
                    </button>
                    <button type="button" className="ghost-btn" onClick={() => handleDrop(connection)}>
                      Drop
                    </button>
                  </div>
                </article>
              ))}
            </div>
          ))}
        </div>
      )}
    </section>
  );
};
