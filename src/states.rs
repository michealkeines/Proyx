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
    CryptoSetup,          // parse CRYPTO frames
    Handshake,            // handshake keys in progress
    HandshakeConfirmed,   // handshake keys confirmed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicReadyState {
    TransportReady,   // 1-RTT keys active, streams can open
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
    ProtocolSelectedH3,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1RequestParseState {
    RecvHeaders,
    HeadersComplete,
    RecvBody,
    BodyComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1ChunkedState {
    ChunkedSize,
    ChunkedData,
    ChunkedTrailer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1ContinueState {
    ExpectContinue,
    SendContinue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1ConnectState {
    ConnectTunnelEstablished,
    ConnectTunnelTransfer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1InterceptState {
    SendToController,
    WaitControllerDecision,
    ApplyModification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1UpstreamConnectState {
    ResolveUpstreamDNS,
    ConnectUpstreamTcp,
    UpstreamTcpEstablished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1UpstreamTlsState {
    UpstreamTlsHandshakeBegin,
    UpstreamTlsHandshakeRead,
    UpstreamTlsHandshakeWrite,
    UpstreamTlsHandshakeComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1UpstreamProtoSelectState {
    UpstreamProtocolSelect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1ForwardState {
    ForwardRequestHeaders,
    ForwardRequestBody,
    UpstreamRecvHeaders,
    UpstreamRecvBody,
    SendResponseHeadersToClient,
    SendResponseBodyToClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1ConnLifecycleState {
    ClientClosed,
    UpstreamClosed,
    CheckKeepAlive,
    PrepareNextRequest,
    CloseConnection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H1State {
    Request(H1RequestParseState),
    Chunked(H1ChunkedState),
    Continue(H1ContinueState),
    Connect(H1ConnectState),
    Intercept(H1InterceptState),
    UpstreamConnect(H1UpstreamConnectState),
    UpstreamTls(H1UpstreamTlsState),
    UpstreamProtoSelect(H1UpstreamProtoSelectState),
    Forward(H1ForwardState),
    Lifecycle(H1ConnLifecycleState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2ConnBootstrapState {
    ClientPreface,
    RecvClientSettings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2FrameParseState {
    RecvFrameHeader,
    RecvFramePayload,
    RecvContinuation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2HpackState {
    HpackDecode,
    HpackTableUpdate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2InterceptState {
    SendToController,
    WaitControllerDecision,
    ApplyModification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2UpstreamConnectState {
    ConnectUpstreamTcp,
    UpstreamTlsHandshakeBegin,
    UpstreamTlsHandshakeComplete,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2UpstreamSettingsState {
    UpstreamSettingsExchange,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2ProxyState {
    ProxyFramesClientToUpstream,
    ProxyFramesUpstreamToClient,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2FlowControlState {
    FlowControlWaitWindowUpdate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2StreamLifecycleState {
    StreamHalfClosedRemote,
    StreamHalfClosedLocal,
    StreamClosed,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2ControlState {
    StreamReset,
    PriorityUpdate,
    GoawayReceived,
    GoawaySent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H2State {
    Bootstrap(H2ConnBootstrapState),
    FrameParse(H2FrameParseState),
    Hpack(H2HpackState),
    Intercept(H2InterceptState),
    UpstreamConnect(H2UpstreamConnectState),
    UpstreamSettings(H2UpstreamSettingsState),
    Proxy(H2ProxyState),
    FlowControl(H2FlowControlState),
    Stream(H2StreamLifecycleState),
    Control(H2ControlState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3ControlState {
    ControlStreamSetup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3RequestParseState {
    RecvHeaders,
    RecvBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3ResponseParseState {
    RecvResponseHeaders,
    RecvResponseBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3QpackState {
    QpackDecodeHeaders,
    QpackTableUpdate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3DatagramState {
    RecvDatagram,
    SendDatagram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3ZeroRttState {
    ZeroRttRequest,
    ZeroRttResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3InterceptState {
    SendToController,
    WaitControllerDecision,
    ApplyModification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3UpstreamState {
    ConnectUpstream,
    UpstreamQuicHandshake,
    UpstreamQuicReady,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3ForwardState {
    ForwardHeaders,
    ForwardBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3StreamLifecycleState {
    StreamReset,
    StreamsDone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3SessionState {
    FinalizeConnection,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3State {
    Control(H3ControlState),

    RequestParse(H3RequestParseState),
    ResponseParse(H3ResponseParseState),

    Qpack(H3QpackState),

    Datagram(H3DatagramState),

    ZeroRtt(H3ZeroRttState),

    Intercept(H3InterceptState),

    Upstream(H3UpstreamState),

    Forward(H3ForwardState),

    Stream(H3StreamLifecycleState),

    Session(H3SessionState),
}



#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptPipelineState {
    SendRawToController,
    WaitControllerDecision,
    ApplyControllerModification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptBodyState {
    InterceptReadBody,
    InterceptWriteBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptDropState {
    InterceptDropConnection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptState {
    Pipeline(InterceptPipelineState),
    Body(InterceptBodyState),
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
    ProtocolSelectedH3,
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
