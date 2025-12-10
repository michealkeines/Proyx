import type { ComponentType } from "react";

export interface TabDescriptor {
  id: string;
  title: string;
  component: ComponentType;
  priority: number;
  badge?: number;
}

interface TabBarProps {
  tabs: TabDescriptor[];
  activeId: string;
  onChange: (id: string) => void;
}

export const TabBar = ({ tabs, activeId, onChange }: TabBarProps) => {
  const sortedTabs = [...tabs].sort((a, b) => a.priority - b.priority);

  return (
    <nav className="tab-bar" aria-label="Proxy mode tabs">
      {sortedTabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          className={`tab-button ${tab.id === activeId ? "active" : ""}`}
          onClick={() => onChange(tab.id)}
        >
          <span>{tab.title}</span>
          {typeof tab.badge === "number" && tab.badge > 0 && (
            <span className="tab-button__badge" aria-label={`${tab.badge} pending items`}>
              {tab.badge}
            </span>
          )}
        </button>
      ))}
    </nav>
  );
};
