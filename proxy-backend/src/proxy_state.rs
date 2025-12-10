use serde::Serialize;
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, broadcast, oneshot};

#[derive(Clone)]
pub struct ProxyState {
    inner: Arc<ProxyStateInner>,
}

struct ProxyStateInner {
    live_intercept: AtomicBool,
    next_id: AtomicU64,
    sessions: Mutex<HashMap<u64, ConnectionSnapshot>>,
    intercept_waiters: Mutex<HashMap<u64, oneshot::Sender<()>>>,
    event_tx: broadcast::Sender<ProxyEvent>,
}

#[derive(Clone, Serialize)]
pub struct ConnectionSnapshot {
    pub id: u64,
    pub method: String,
    pub uri: String,
    pub state: ConnectionState,
    pub queued_at: u64,
    pub status_code: Option<u16>,
}

#[derive(Clone, Copy, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Request,
    Intercept,
    WaitingIo,
    Response,
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ProxyEvent {
    ConnectionUpdated(ConnectionSnapshot),
    LiveInterceptToggled { enabled: bool },
}

impl Default for ProxyState {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyState {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(1024);
        Self {
            inner: Arc::new(ProxyStateInner {
                live_intercept: AtomicBool::new(false),
                next_id: AtomicU64::new(1),
                sessions: Mutex::new(HashMap::new()),
                intercept_waiters: Mutex::new(HashMap::new()),
                event_tx,
            }),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ProxyEvent> {
        self.inner.event_tx.subscribe()
    }

    pub fn is_live_intercept(&self) -> bool {
        self.inner.live_intercept.load(Ordering::SeqCst)
    }

    pub fn set_live_intercept(&self, enabled: bool) {
        self.inner.live_intercept.store(enabled, Ordering::SeqCst);
        let _ = self
            .inner
            .event_tx
            .send(ProxyEvent::LiveInterceptToggled { enabled });
    }

    pub async fn register_connection(&self, method: String, uri: String) -> u64 {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let snapshot = ConnectionSnapshot {
            id,
            method,
            uri,
            state: ConnectionState::Request,
            queued_at: Self::now_millis(),
            status_code: None,
        };
        let mut sessions = self.inner.sessions.lock().await;
        sessions.insert(id, snapshot.clone());
        drop(sessions);
        let _ = self
            .inner
            .event_tx
            .send(ProxyEvent::ConnectionUpdated(snapshot));
        id
    }

    pub async fn update_state(&self, id: u64, state: ConnectionState, status_code: Option<u16>) {
        let mut sessions = self.inner.sessions.lock().await;
        if let Some(snapshot) = sessions.get_mut(&id) {
            snapshot.state = state;
            if status_code.is_some() {
                snapshot.status_code = status_code;
            }
            let cloned = snapshot.clone();
            drop(sessions);
            let _ = self
                .inner
                .event_tx
                .send(ProxyEvent::ConnectionUpdated(cloned));
        }
    }

    pub async fn wait_for_resume(&self, id: u64) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        let mut waiters = self.inner.intercept_waiters.lock().await;
        waiters.insert(id, tx);
        rx
    }

    pub async fn resume_intercept(&self, id: u64) -> bool {
        let mut waiters = self.inner.intercept_waiters.lock().await;
        if let Some(tx) = waiters.remove(&id) {
            let _ = tx.send(());
            true
        } else {
            false
        }
    }

    pub async fn snapshots(&self) -> Vec<ConnectionSnapshot> {
        let sessions = self.inner.sessions.lock().await;
        sessions.values().cloned().collect()
    }

    pub async fn intercept_queue(&self) -> Vec<ConnectionSnapshot> {
        let sessions = self.inner.sessions.lock().await;
        sessions
            .values()
            .filter(|snapshot| snapshot.state == ConnectionState::Intercept)
            .cloned()
            .collect()
    }

    fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_millis() as u64)
            .unwrap_or_default()
    }
}
