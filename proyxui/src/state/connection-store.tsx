import { ReactNode, createContext, useContext, useEffect, useReducer } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";

export type ConnectionStateKind = "request" | "intercept" | "response";

export type WebSocketDirection = "client_to_server" | "server_to_client";

export interface WebSocketEvent {
  timestampMs: number;
  direction: WebSocketDirection;
  payloadPreview: string;
}

export interface Connection {
  id: string;
  host: string;
  path: string;
  method: string;
  status: number;
  protocol: "http" | "https";
  state: ConnectionStateKind;
  timestamp: string;
  durationMs: number;
  requestSize: number;
  responseSize: number;
  tags: string[];
  bodyPreview: string;
  isWebsocket: boolean;
  wsEvents: WebSocketEvent[];
}

type SnapshotState = "request" | "intercept" | "waiting_io" | "response";

interface ConnectionSnapshotDto {
  id: number;
  method: string;
  uri: string;
  state: SnapshotState;
  queued_at: number | string;
  status_code: number | null;
  tags?: string[];
  duration_ms?: number | null;
  request_headers?: Array<{ name: string; value: string }>;
  response_headers?: Array<{ name: string; value: string }>;
  request_size?: number | null;
  response_size?: number | null;
  body_preview?: string | null;
  is_websocket?: boolean;
  ws_events?: Array<{
    timestamp_ms: number;
    direction: WebSocketDirection;
    payload_preview: string;
  }>;
}

type ProxyEventPayload =
  | { type: "connection_updated"; payload: ConnectionSnapshotDto }
  | { type: "live_intercept_toggled"; payload: { enabled: boolean } };

const formatTimestamp = (queuedAt: number) =>
  new Date(queuedAt).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

const mapSnapshotState = (state: SnapshotState): ConnectionStateKind => {
  if (state === "request") {
    return "request";
  }
  if (state === "intercept") {
    return "intercept";
  }
  return "response";
};

const normalizeSnapshot = (snapshot: ConnectionSnapshotDto): Connection => {
  const queuedAt =
    typeof snapshot.queued_at === "number" ? snapshot.queued_at : Number(snapshot.queued_at);
  let host = snapshot.uri;
  let path = snapshot.uri;
  let protocol: Connection["protocol"] = "https";

  try {
    const parsed = new URL(snapshot.uri);
    host = parsed.host || parsed.hostname;
    const pathname = parsed.pathname || "/";
    path = `${pathname}${parsed.search}`;
    protocol = parsed.protocol === "http:" ? "http" : "https";
  } catch {
    if (snapshot.uri.startsWith("http://")) {
      protocol = "http";
    }
  }

  const timestamp = Number.isFinite(queuedAt) && queuedAt > 0 ? formatTimestamp(queuedAt) : "";
  const isWebsocket = snapshot.is_websocket ?? false;
  const wsEvents =
    snapshot.ws_events?.map((event) => ({
      timestampMs: event.timestamp_ms,
      direction: event.direction,
      payloadPreview: event.payload_preview,
    })) ?? [];

  return {
    id: snapshot.id.toString(),
    host,
    path,
    method: snapshot.method,
    status: snapshot.status_code ?? 0,
    protocol,
    state: mapSnapshotState(snapshot.state),
    timestamp,
    durationMs: snapshot.duration_ms ?? 0,
    requestSize: snapshot.request_size ?? 0,
    responseSize: snapshot.response_size ?? 0,
    tags: snapshot.tags ?? [],
    bodyPreview: snapshot.body_preview ?? "",
    isWebsocket,
    wsEvents,
  };
};

interface ConnectionStore {
  connections: Connection[];
  selectedConnectionId: string | null;
  liveInterceptEnabled: boolean;
}

type ConnectionAction =
  | { type: "setConnections"; payload: Connection[] }
  | { type: "updateConnection"; payload: Connection }
  | { type: "setLiveIntercept"; payload: boolean }
  | { type: "select"; payload: { id: string } }
  | { type: "toggleLiveIntercept" }
  | { type: "resume"; payload: { id: string } }
  | { type: "drop"; payload: { id: string } }
  | { type: "modify"; payload: { id: string; preview: string } };

const initialState: ConnectionStore = {
  connections: [],
  selectedConnectionId: null,
  liveInterceptEnabled: false,
};

const connectionReducer = (state: ConnectionStore, action: ConnectionAction): ConnectionStore => {
  switch (action.type) {
    case "setConnections": {
      const selectedId = state.selectedConnectionId ?? action.payload[0]?.id ?? null;
      return {
        ...state,
        connections: action.payload,
        selectedConnectionId: selectedId,
      };
    }
    case "updateConnection": {
      const updatedConnections = state.connections.some((connection) => connection.id === action.payload.id)
        ? state.connections.map((connection) =>
            connection.id === action.payload.id ? action.payload : connection,
          )
        : [...state.connections, action.payload];
      return {
        ...state,
        connections: updatedConnections,
        selectedConnectionId: state.selectedConnectionId ?? action.payload.id,
      };
    }
    case "setLiveIntercept":
      return {
        ...state,
        liveInterceptEnabled: action.payload,
      };
    case "select":
      return {
        ...state,
        selectedConnectionId: action.payload.id,
      };
    case "toggleLiveIntercept":
      return {
        ...state,
        liveInterceptEnabled: !state.liveInterceptEnabled,
      };
    case "resume":
      return {
        ...state,
        connections: state.connections.map((connection) =>
          connection.id === action.payload.id
            ? { ...connection, state: "response", status: 200 }
            : connection,
        ),
      };
    case "drop":
      return {
        ...state,
        connections: state.connections.map((connection) =>
          connection.id === action.payload.id
            ? { ...connection, state: "response", status: 499 }
            : connection,
        ),
      };
    case "modify":
      return {
        ...state,
        connections: state.connections.map((connection) =>
          connection.id === action.payload.id
            ? { ...connection, bodyPreview: action.payload.preview }
            : connection,
        ),
      };
    default:
      return state;
  }
};

const ConnectionContext = createContext<
  | {
      state: ConnectionStore;
      dispatch: React.Dispatch<ConnectionAction>;
    }
  | undefined
>(undefined);

export const ConnectionProvider = ({ children }: { children: ReactNode }) => {
  const [state, dispatch] = useReducer(connectionReducer, initialState);

  useEffect(() => {
    let isActive = true;
    let unlisten: UnlistenFn | undefined;

    const initialize = async () => {
      try {
        const snapshots: ConnectionSnapshotDto[] = await invoke("get_connections");
        if (!isActive) return;
        const connections = snapshots.map(normalizeSnapshot);
        dispatch({ type: "setConnections", payload: connections });
      } catch (error) {
        console.error("Failed to load connections", error);
      }

      try {
        const queueSnapshots: ConnectionSnapshotDto[] = await invoke("get_intercept_queue");
        if (!isActive) return;
        queueSnapshots.forEach((snapshot) => {
          dispatch({ type: "updateConnection", payload: normalizeSnapshot(snapshot) });
        });
      } catch (error) {
        console.error("Failed to load intercept queue", error);
      }

      try {
        const liveIntercept = await invoke<boolean>("get_live_intercept");
        if (!isActive) return;
        dispatch({ type: "setLiveIntercept", payload: liveIntercept });
      } catch (error) {
        console.error("Failed to load live intercept state", error);
      }

      try {
        unlisten = await listen<ProxyEventPayload>("proxy-event", (event) => {
          if (!isActive) return;
          const payload = event.payload;
          if (payload.type === "connection_updated") {
            dispatch({ type: "updateConnection", payload: normalizeSnapshot(payload.payload) });
          } else if (payload.type === "live_intercept_toggled") {
            dispatch({ type: "setLiveIntercept", payload: payload.payload.enabled });
          }
        });
      } catch (error) {
        console.error("Failed to subscribe to proxy events", error);
      }
    };

    initialize();

    return () => {
      isActive = false;
      unlisten?.();
    };
  }, []);

  return (
    <ConnectionContext.Provider value={{ state, dispatch }}>
      {children}
    </ConnectionContext.Provider>
  );
};

export const useConnectionStore = () => {
  const context = useContext(ConnectionContext);
  if (!context) {
    throw new Error("useConnectionStore must be used within ConnectionProvider");
  }
  return context;
};
