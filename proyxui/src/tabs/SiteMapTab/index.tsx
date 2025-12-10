import { useMemo, useState } from "react";
import { ConnectionStateBadge } from "../../components/ConnectionStateBadge";
import { Connection, ConnectionStateKind, useConnectionStore } from "../../state/connection-store";

const protocolOptions: Array<"all" | "http" | "https"> = ["all", "http", "https"];
const stateOptions: Array<"all" | ConnectionStateKind> = ["all", "request", "intercept", "response"];

export const SiteMapTab = () => {
  const { state, dispatch } = useConnectionStore();
  const [protocolFilter, setProtocolFilter] = useState<typeof protocolOptions[number]>("all");
  const [stateFilter, setStateFilter] = useState<typeof stateOptions[number]>("all");

  const filteredConnections = useMemo(() => {
    return state.connections.filter((connection) => {
      const matchesProtocol =
        protocolFilter === "all" || connection.protocol === protocolFilter;
      const matchesState =
        stateFilter === "all" || connection.state === stateFilter;
      return matchesProtocol && matchesState;
    });
  }, [state.connections, protocolFilter, stateFilter]);

  const groupedByHost = useMemo(() => {
    const map: Record<string, Connection[]> = {};
    filteredConnections.forEach((connection) => {
      if (!map[connection.host]) {
        map[connection.host] = [] as typeof filteredConnections;
      }
      map[connection.host].push(connection);
    });
    return map;
  }, [filteredConnections]);

  if (!filteredConnections.length) {
    return <p className="tab-panel__empty">No connections match the current filters.</p>;
  }

  return (
    <section className="tab-panel site-map-tab">
      <div className="tab-panel__filters">
        <label>
          Protocol
          <select value={protocolFilter} onChange={(event) => setProtocolFilter(event.target.value as typeof protocolFilter)}>
            {protocolOptions.map((option) => (
              <option key={option} value={option}>
                {option.toUpperCase()}
              </option>
            ))}
          </select>
        </label>
        <label>
          State
          <select value={stateFilter} onChange={(event) => setStateFilter(event.target.value as typeof stateFilter)}>
            {stateOptions.map((option) => (
              <option key={option} value={option}>
                {option === "all" ? "ALL" : option.toUpperCase()}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="site-map-tree">
        {Object.entries(groupedByHost).map(([host, connections]) => (
          <details key={host} className="site-map-tree__host" open>
            <summary>
              <div>
                <p className="site-map-tree__host-name">{host}</p>
                <p className="site-map-tree__host-summary">{connections.length} calls</p>
              </div>
              <span className="site-map-tree__host-count">{connections.length}</span>
            </summary>
            <ul>
              {connections.map((connection) => (
                <li key={connection.id} className="site-map-tree__item">
                  <div>
                    <ConnectionStateBadge
                      state={connection.state}
                      timestamp={connection.timestamp}
                      durationMs={connection.durationMs}
                    />
                    <div className="site-map-tree__line">
                      <span className="site-map-tree__path">
                        {connection.method} {connection.path}
                      </span>
                      <span className="site-map-tree__status">Status {connection.status}</span>
                    </div>
                    <div className="site-map-tree__meta">
                      <span>{connection.protocol.toUpperCase()}</span>
                      <span className="site-map-tree__tags">{connection.tags.join(" · ")}</span>
                    </div>
                  </div>
                  <button
                    type="button"
                    className="ghost-btn"
                    onClick={() => dispatch({ type: "select", payload: { id: connection.id } })}
                  >
                    View details
                  </button>
                </li>
              ))}
            </ul>
          </details>
        ))}
      </div>
    </section>
  );
};
