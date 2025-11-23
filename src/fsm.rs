use crate::states::ProxyState;

#[derive(Debug)]
pub enum NextStep {
    /// Move to a new state immediately (no I/O dependency)
    Continue(ProxyState),

    /// Suspend until client socket readable
    WaitRead(ProxyState),

    /// Suspend until client socket writable
    WaitWrite(ProxyState),

    /// Suspend waiting for controller (interceptor)
    WaitController,

    /// Suspend for a timer (QUIC PTO, keepalive, handshake timeout)
    WaitTimer(std::time::Duration),

    /// Fatal: close connection immediately
    Close,
}
