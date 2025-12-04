use std::alloc::Layout;
use std::ptr::NonNull;

use crate::config::CONFIG;

pub struct H1Session {
    pub headers: NonNull<u8>,
    pub headers_cap: usize,
    pub body: Option<NonNull<u8>>,
    pub body_cap: usize,
    pub headers_count: Option<u64>,
    pub body_len: Option<u64>,
    pub parsed_headers: bool,
    pub parsed_body: bool,
    pub content_len: Option<u64>,
    pub is_chunked: bool,
    pub keep_alive: bool,
    pub chunk_remaining: u64,
    pub expect_continue: bool,
    pub is_head: bool,
    pub is_connect: bool,
    pub version_1_0: bool,
}

impl H1Session {
    pub unsafe fn allocate_body(&mut self) -> bool {
        if (self.body_len.is_none()) {
            return false;
        }
        let len = self.body_len.unwrap();
        if (len == 0) {
            return false;
        }
        let k = CONFIG.buffers.h1_body_max as u64;
        if (len > k) {
            println!("BODY SIZE is too big\n");
            return false;
        }

        self.body = {
            let raw = std::alloc::alloc_zeroed(
                std::alloc::Layout::from_size_align(len as usize, 32).unwrap(),
            );
            Some(NonNull::new(raw).expect("failed alloc headers buf"))
        };
        self.body_cap = len as usize;

        return true;
    }
    pub unsafe fn new() -> H1Session {
        let in_cap = CONFIG.buffers.h1_headers_cap;
        let headers = {
            let raw =
                std::alloc::alloc_zeroed(std::alloc::Layout::from_size_align(in_cap, 32).unwrap());
            NonNull::new(raw).expect("failed alloc headers buf")
        };
        Self {
            headers: headers,
            headers_cap: in_cap,
            body: None,
            body_cap: 0,
            headers_count: None,
            body_len: None,
            parsed_body: false,
            parsed_headers: false,
            content_len: None,
            is_chunked: false,
            keep_alive: false,
            chunk_remaining: 0,
            expect_continue: false,
            is_head: false,
            is_connect: false,
            version_1_0: false,
        }
    }
}

impl Drop for H1Session {
    fn drop(&mut self) {
        unsafe {
            if self.headers_cap > 0 {
                let layout = Layout::from_size_align(self.headers_cap, 32).unwrap();
                std::alloc::dealloc(self.headers.as_ptr(), layout);
            }

            if let Some(body_ptr) = self.body.take() {
                if self.body_cap > 0 {
                    let layout = Layout::from_size_align(self.body_cap, 32).unwrap();
                    std::alloc::dealloc(body_ptr.as_ptr(), layout);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyState {
    Transport(TransportState),
    Tls(TlsState),
    Quic(QuicState),
    Detect(DetectState),
    H1(H1State),
    H2(H2State),
    H3(H3State),
    Intercept(InterceptState),
    Upstream(UpstreamState),
    Stream(StreamState),
    Shutdown(ShutdownState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportConnState {
    AcceptClientConnection,
    ClientTcpHandshake,
    ClientTcpEstablished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportIoState {
    ClientReadInitialData,
    ClientWritePendingData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportDetectState {
    ClientDetectTls,
    ClientDetectQuic,
    ClientDetectProtocolGuess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKeepaliveState {
    ClientKeepAliveIdle,
    ClientKeepAliveTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    Conn(TransportConnState),
    Io(TransportIoState),
    Detect(TransportDetectState),
    KeepAlive(TransportKeepaliveState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsHandshakeState {
    HandshakeBegin,
    HandshakeRead,
    HandshakeWrite,
    HandshakePending,
    HandshakeComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsAlpnState {
    AlpnStart,
    AlpnComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsClientAuthState {
    ExpectClientCertificate,
    VerifyClientCertificate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRenegotiationState {
    RenegotiationBegin,
    RenegotiationPending,
    RenegotiationComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsShutdownState {
    ShutdownBegin,
    ShutdownWrite,
    ShutdownComplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsState {
    Handshake(TlsHandshakeState),
    Alpn(TlsAlpnState),
    ClientAuth(TlsClientAuthState),
    Renegotiation(TlsRenegotiationState),
    Shutdown(TlsShutdownState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicInitialState {
    InitialPacket,
    VersionNegotiation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicZeroRttState {
    ZeroRttDataRecv,
    ZeroRttAccepted,
    ZeroRttRejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicHandshakeState {
    CryptoSetup,        // parse CRYPTO frames
    Handshake,          // handshake keys in progress
    HandshakeConfirmed, // handshake keys confirmed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicReadyState {
    TransportReady, // 1-RTT keys active, streams can open
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicStreamState {
    StreamOpen,
    StreamRecv,
    StreamSend,
    StreamHalfClosedLocal,
    StreamHalfClosedRemote,
    StreamClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicPathState {
    ConnectionMigrationStart,
    ConnectionMigrationComplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicState {
    Initial(QuicInitialState),
    ZeroRtt(QuicZeroRttState),
    Handshake(QuicHandshakeState),
    Ready(QuicReadyState),
    Stream(QuicStreamState),
    Path(QuicPathState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectBootstrapState {
    DetectProtocolBegin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectAwaitState {
    WaitingForProtocolDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectResultState {
    ProtocolSelectedH1,
    ProtocolSelectedH2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectErrorState {
    ProtocolUnknown,
    ProtocolSelectionError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectState {
    Bootstrap(DetectBootstrapState),
    Await(DetectAwaitState),
    Result(DetectResultState),
    Error(DetectErrorState),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H1State {
    RequestHeaders,
    RequestBody,
    RequestReadyForController,
    DispatchToUpstream,
    ResponseHeaders,
    ResponseBody,
    ResponseComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2State {
    Bootstrap,
    ClientFrameParse,
    BuildCanonicalRequest,
    RequestQueueEnqueue,
    ControllerHook,
    DispatchToUpstream,
    UpstreamFrameCollect,
    ResponseDispatch,
    TransportWait,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptPipelineState {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptDropState {
    Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptState {
    Pipeline(InterceptPipelineState),
    Drop(InterceptDropState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamDnsState {
    ResolveStart,
    ResolveWait,
    ResolveComplete,
    ResolveFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTcpState {
    TcpConnectBegin,
    TcpConnectWaitWritable,
    TcpConnectEstablished,
    TcpConnectFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTlsState {
    TlsHandshakeBegin,
    TlsHandshakeRead,
    TlsHandshakeWrite,
    TlsHandshakePending,
    TlsHandshakeComplete,
    TlsHandshakeFailed,
}

/// QUIC upstream handshake + transport bootstrap.
/// This reuses the same QUIC logic internally, but upstream-specific events live here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamQuicState {
    QuicInitialPacket,
    QuicCryptoSetup,
    QuicHandshake,
    QuicHandshakeConfirmed,
    QuicTransportReady,
    QuicConnectionFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProtocolState {
    DetectProtocol,
    ProtocolSelectedH1,
    ProtocolSelectedH2,
    ProtocolDetectFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTimeoutState {
    ConnectTimeout,
    ReadTimeout,
    WriteTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamRetryState {
    RetryConnect,
    FallbackServer,
    NoMoreFallbacks,
}

/// Unified upstream state wrapper
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamState {
    Dns(UpstreamDnsState),
    Tcp(UpstreamTcpState),
    Tls(UpstreamTlsState),
    Quic(UpstreamQuicState),
    Protocol(UpstreamProtocolState),
    Timeout(UpstreamTimeoutState),
    Retry(UpstreamRetryState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirectionState {
    ClientToUpstream,
    UpstreamToClient,
    Bidirectional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamWaitState {
    WaitClientReadable,
    WaitUpstreamReadable,
    WaitClientWritable,
    WaitUpstreamWritable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamBackpressureState {
    BackpressureClient,
    BackpressureUpstream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamTerminationState {
    StreamTlsShutdown,
    StreamQuicFin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamState {
    Direction(StreamDirectionState),
    Wait(StreamWaitState),
    Backpressure(StreamBackpressureState),
    Termination(StreamTerminationState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownState {
    GracefulShutdown,
    ShutdownDrainBuffers,
    ShutdownWaitUpstreamClose,
    ForcedClose,
    Closed,
}
