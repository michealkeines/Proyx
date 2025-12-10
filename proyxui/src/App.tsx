import { useMemo, useState } from "react";
import { ConnectionProvider, useConnectionStore } from "./state/connection-store";
import { ConnectionStateBadge } from "./components/ConnectionStateBadge";
import { TabBar } from "./components/TabBar";
import { baseTabDescriptors } from "./tabs/descriptors";
import "./App.css";

const AppContent = () => {
  const { state } = useConnectionStore();
  const [activeTab, setActiveTab] = useState(baseTabDescriptors[0].id);

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

  const selectedConnection =
    state.connections.find((connection) => connection.id === state.selectedConnectionId) ??
    state.connections[0];

  const ActivePanel =
    tabsWithBadges.find((tab) => tab.id === activeTab)?.component ?? tabsWithBadges[0].component;

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">Proxy UI · Live mode</p>
          <h1>Multi-mode connection explorer</h1>
        </div>
        <div className="app-header__stats">
          <span className="stat-pill">{state.connections.length} connections</span>
          <span className="stat-pill">Live intercept {state.liveInterceptEnabled ? "on" : "off"}</span>
        </div>
      </header>

      <section className="selection-preview">
        {selectedConnection ? (
          <div className="selection-preview__card">
            <div>
              <p className="selection-preview__label">Focused connection</p>
              <h2>{selectedConnection.host}</h2>
              <p className="selection-preview__desc">
                {selectedConnection.method} {selectedConnection.path}
              </p>
            </div>
            <div className="selection-preview__badges">
              <ConnectionStateBadge
                state={selectedConnection.state}
                timestamp={selectedConnection.timestamp}
                durationMs={selectedConnection.durationMs}
              />
              <span className="stat-pill">{selectedConnection.protocol.toUpperCase()}</span>
            </div>
          </div>
        ) : (
          <p className="tab-panel__empty">No connection selected.</p>
        )}
      </section>

      <TabBar tabs={tabsWithBadges} activeId={activeTab} onChange={setActiveTab} />
      <main className="panel-area">
        <ActivePanel />
      </main>
    </div>
  );
};

const App = () => (
  <ConnectionProvider>
    <AppContent />
  </ConnectionProvider>
);

export default App;
