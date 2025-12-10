import type { ConnectionStateKind } from "../state/connection-store";

interface ConnectionStateBadgeProps {
  state: ConnectionStateKind;
  timestamp?: string;
  durationMs?: number;
}

const stateLabels: Record<ConnectionStateKind, string> = {
  request: "Request",
  intercept: "Intercept",
  response: "Response",
};

export const ConnectionStateBadge = ({
  state,
  timestamp,
  durationMs,
}: ConnectionStateBadgeProps) => {
  const label = stateLabels[state] ?? "Request";
  const extra = durationMs ? ` · ${durationMs}ms` : "";

  return (
    <span className={`state-badge state-badge--${state}`}>
      <span className="state-badge__label">{label}</span>
      {timestamp && <span className="state-badge__time">{timestamp}</span>}
      {durationMs && <span className="state-badge__duration">{extra}</span>}
    </span>
  );
};
