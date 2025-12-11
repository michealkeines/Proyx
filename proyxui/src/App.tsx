import type { Connection } from "./state/connection-store";
import { useMemo, useState } from "react";
import { ConnectionProvider, useConnectionStore } from "./state/connection-store";
import { ConnectionStateBadge } from "./components/ConnectionStateBadge";
import { TabBar } from "./components/TabBar";
import { baseTabDescriptors } from "./tabs/descriptors";
import "./App.css";

const trafficFilters = [
  "All",
  "HTTP",
  "HTTPS",
  "WebSocket",
  "JSON",
  "Form",
  "XML",
  "Document",
  "Media",
  "Other",
] as const;

const AppContent = () => {
  const { state, dispatch } = useConnectionStore();
  const [activeTab, setActiveTab] = useState(baseTabDescriptors[0].id);
  const [activeTrafficFilter, setActiveTrafficFilter] = useState<typeof trafficFilters[number]>("All");

  const interceptedCount = useMemo(
    () => state.connections.filter((connection) => connection.state === "intercept").length,
    [state.connections],
  );

  const tabsWithBadges = useMemo(() => {
    return baseTabDescriptors.map((tab) => ({
      ...tab,
      badge: tab.id === "live-intercept" ? interceptedCount : tab.badge,
    }));
  }, [interceptedCount]);

  const hostGroups = useMemo(() => {
    const map: Record<string, Connection[]> = {};
    state.connections.forEach((connection) => {
      if (!map[connection.host]) {
        map[connection.host] = [];
      }
      map[connection.host].push(connection);
    });
    return map;
  }, [state.connections]);

  const favoriteHosts = useMemo(() => {
    return Object.entries(hostGroups)
      .sort(([, listA], [, listB]) => listB.length - listA.length)
      .slice(0, 3)
      .map(([host, list]) => ({
        host,
        count: list.length,
        connection: list[0],
      }));
  }, [hostGroups]);

  const protocolSummary = useMemo(() => {
    const summary = { http: 0, https: 0, websocket: 0 };
    state.connections.forEach((connection) => {
      if (connection.isWebsocket) {
        summary.websocket += 1;
      } else {
        summary[connection.protocol] += 1;
      }
    });
    return summary;
  }, [state.connections]);

  const selectedConnection =
    state.connections.find((connection) => connection.id === state.selectedConnectionId) ??
    state.connections[0];

  const ActivePanel =
    tabsWithBadges.find((tab) => tab.id === activeTab)?.component ?? tabsWithBadges[0].component;

  const trafficNote = selectedConnection
    ? `${selectedConnection.method} ${selectedConnection.path}`
    : "Waiting for traffic…";

  const heroStats = [
    { label: "Connections", value: state.connections.length.toString() },
    { label: "Intercept queue", value: interceptedCount.toString() },
    {
      label: "Live intercept",
      value: state.liveInterceptEnabled ? "Live" : "Paused",
    },
  ];

  const heroActions = [
    { id: "pause", icon: "▐▐", label: "Pause" },
    { id: "notes", icon: "✎", label: "Notes" },
    { id: "clear", icon: "🗑", label: "Clear" },
  ];

  return (
    <div className="app-shell">
      <header className="hero-card" aria-label="Proyx status banner">
        <div className="hero-card__brand">
          <span className="hero-card__orb" aria-hidden />
          <div>
            <p className="hero-card__label">PROYX · Listening on 172.16.2.133:9090</p>
            <h1>Live traffic monitoring</h1>
          </div>
        </div>
        <div className="hero-card__actions">
          {heroActions.map((action) => (
            <button key={action.id} type="button" className="icon-chip">
              <span>{action.icon}</span>
              <small>{action.label}</small>
            </button>
          ))}
        </div>
        <div className="hero-card__stats">
          {heroStats.map((stat) => (
            <span key={stat.label} className="hero-card__stat">
              <strong>{stat.value}</strong>
              <small>{stat.label}</small>
            </span>
          ))}
        </div>
      </header>

      <div className="traffic-filter">
        {trafficFilters.map((filter) => (
          <button
            key={filter}
            type="button"
            className={`traffic-filter__chip ${activeTrafficFilter === filter ? "is-active" : ""}`}
            onClick={() => setActiveTrafficFilter(filter)}
          >
            {filter}
          </button>
        ))}
      </div>

      <div className="app-shell__layout">
        <aside className="app-shell__sidebar">
          <div className="sidebar-card sidebar-card--pinned">
            <div className="sidebar-card__head">
              <p className="sidebar-card__title">Favorites</p>
              <span className="sidebar-card__note">pin</span>
            </div>
            <ul className="sidebar-list">
              {favoriteHosts.length ? (
                favoriteHosts.map((favorite) => (
                  <li key={favorite.host}>
                    <button
                      type="button"
                      className="sidebar-list__item"
                      onClick={() =>
                        favorite.connection &&
                        dispatch({ type: "select", payload: { id: favorite.connection.id } })
                      }
                    >
                      <div>
                        <p className="sidebar-list__host">{favorite.host}</p>
                        <p className="sidebar-list__meta">{favorite.count} calls</p>
                      </div>
                      {favorite.connection && (
                        <ConnectionStateBadge
                          state={favorite.connection.state}
                          timestamp={favorite.connection.timestamp}
                          durationMs={favorite.connection.durationMs}
                        />
                      )}
                    </button>
                  </li>
                ))
              ) : (
                <li className="sidebar-list__empty">No favorites yet.</li>
              )}
            </ul>
          </div>
          <div className="sidebar-card sidebar-card--protocols">
            <p className="sidebar-card__title">Protocol overview</p>
            <ul className="sidebar-protocols">
              {([
                ["HTTP", protocolSummary.http],
                ["HTTPS", protocolSummary.https],
                ["WebSocket", protocolSummary.websocket],
              ] as const).map(([label, count]) => (
                <li key={label}>
                  <span>{label}</span>
                  <strong>{count}</strong>
                </li>
              ))}
            </ul>
          </div>
          <div className="sidebar-card sidebar-card--details">
            <p className="sidebar-card__title">Live highlight</p>
            <p className="sidebar-card__desc">
              {selectedConnection
                ? `${selectedConnection.host} · ${selectedConnection.protocol.toUpperCase()}`
                : "No traffic yet."}
            </p>
            <div className="sidebar-card__meta">
              <span>{selectedConnection?.status ? `Status ${selectedConnection.status}` : "Awaiting"}</span>
              <span>
                {selectedConnection
                  ? `${selectedConnection.requestSize?.toLocaleString() ?? 0} B`
                  : "--"}{" "}
                sent
              </span>
            </div>
          </div>
        </aside>

        <main className="app-shell__main">
          <div className="app-shell__main-content">
            {selectedConnection ? (
              <section className="focus-card">
                <div className="focus-card__header">
                  <div>
                    <p className="focus-card__label">Focused connection</p>
                    <h2>{selectedConnection.host}</h2>
                    <p className="focus-card__path">
                      {selectedConnection.method} {selectedConnection.path}
                    </p>
                  </div>
                  <div className="focus-card__badges">
                    <ConnectionStateBadge
                      state={selectedConnection.state}
                      timestamp={selectedConnection.timestamp}
                      durationMs={selectedConnection.durationMs}
                    />
                    <span className="focus-card__protocol">{selectedConnection.protocol.toUpperCase()}</span>
                  </div>
                </div>
                <div className="focus-card__meta">
                  <span>{selectedConnection.timestamp || "Awaiting"}</span>
                  <span>
                    {selectedConnection.durationMs ? `${selectedConnection.durationMs} ms latency` : "Latency unknown"}
                  </span>
                </div>
              </section>
            ) : (
              <p className="tab-panel__empty">Waiting for incoming connections.</p>
            )}

            <div className="mode-tab-row">
              <TabBar tabs={tabsWithBadges} activeId={activeTab} onChange={setActiveTab} />
              <p className="mode-tab-row__note">{trafficNote}</p>
            </div>

            <section className="panel-area">
              <ActivePanel />
            </section>
          </div>
        </main>
      </div>
    </div>
  );
};

const App = () => (
  <ConnectionProvider>
    <AppContent />
  </ConnectionProvider>
);

export default App;
