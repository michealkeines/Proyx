use std::{
    net::SocketAddr,
    ptr::NonNull,
};

use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use crate::handlers::*;
use crate::states::{ProxyState, TransportConnState};
use crate::controller::ControllerMsg;
use crate::fsm::NextStep;

/// Fully raw-pointer based connection representation.
///  
/// All TCP and UDP sockets are raw pointers to Tokio socket objects
/// that live elsewhere (in the accept loop or QUIC global dispatcher).
///
pub struct Connection {
    // -----------------------------------------------------------------
    // CLIENT SIDE (DOWNSTREAM)
    // -----------------------------------------------------------------

    /// Raw pointer to client TCP stream (None if QUIC)
    pub client_tcp: Option<*const TcpStream>,

    /// Raw pointer to shared UDP socket (only for QUIC)
    pub client_udp: Option<*const UdpSocket>,

    /// Remote peer of QUIC client
    pub client_quic_addr: Option<SocketAddr>,


    // -----------------------------------------------------------------
    // UPSTREAM SIDE (REMOTE SERVER)
    // -----------------------------------------------------------------

    pub upstream_tcp: Option<*const TcpStream>,
    pub upstream_udp: Option<*const UdpSocket>,
    pub upstream_quic_addr: Option<SocketAddr>,


    // -----------------------------------------------------------------
    // FSM
    // -----------------------------------------------------------------

    pub state: ProxyState,

    pub is_reabable: bool,
    pub is_writable: bool,


    // -----------------------------------------------------------------
    // RAW BUFFERS
    // -----------------------------------------------------------------

    pub in_buf: NonNull<u8>,
    pub in_cap: usize,
    pub in_len: usize,

    pub out_buf: NonNull<u8>,
    pub out_cap: usize,
    pub out_len: usize,


    // -----------------------------------------------------------------
    // CONTROLLER PIPE
    // -----------------------------------------------------------------

    pub controller_tx: UnboundedSender<ControllerMsg>,
    pub controller_rx: UnboundedReceiver<ControllerMsg>,


    // -----------------------------------------------------------------
    // MISC
    // -----------------------------------------------------------------

    pub scratch: u64,
    pub last_activity: std::time::Instant,
}

impl Connection {

    // ===================================================================
    // PUBLIC CONSTRUCTORS
    // ===================================================================

    /// Create a TCP inbound connection with RAW POINTER socket
    pub fn new_tcp_raw(
        client_ptr: *const TcpStream,
        tx: UnboundedSender<ControllerMsg>,
        rx: UnboundedReceiver<ControllerMsg>,
    ) -> Self {
        unsafe { Self::create(Some(client_ptr), None, None, tx, rx, None, None, None) }
    }

    /// Create a QUIC inbound connection with a raw pointer to shared UDP socket
    pub fn new_udp_raw(
        peer: SocketAddr,
        udp_ptr: *const UdpSocket,
        tx: UnboundedSender<ControllerMsg>,
        rx: UnboundedReceiver<ControllerMsg>,
    ) -> Self {
        unsafe { Self::create(None, Some(udp_ptr), Some(peer), tx, rx, None, None, None) }
    }

    /// Create a QUIC upstream connection (raw UDP)
    pub fn new_upstream_udp_raw(
        peer: SocketAddr,
        udp_ptr: *const UdpSocket,
        tx: UnboundedSender<ControllerMsg>,
        rx: UnboundedReceiver<ControllerMsg>,
    ) -> Self {
        unsafe { Self::create(None, None, None, tx, rx, None, Some(udp_ptr), Some(peer)) }
    }

    /// Create a TCP upstream connection (raw TCP)
    pub fn new_upstream_tcp_raw(
        tcp_ptr: *const TcpStream,
        tx: UnboundedSender<ControllerMsg>,
        rx: UnboundedReceiver<ControllerMsg>,
    ) -> Self {
        unsafe { Self::create(None, None, None, tx, rx, Some(tcp_ptr), None, None) }
    }


    // ===================================================================
    // INTERNAL UNIFIED CONSTRUCTOR
    // ===================================================================

    unsafe fn create(
        client_tcp: Option<*const TcpStream>,
        client_udp: Option<*const UdpSocket>,
        client_quic_addr: Option<SocketAddr>,

        tx: UnboundedSender<ControllerMsg>,
        rx: UnboundedReceiver<ControllerMsg>,
        upstream_tcp: Option<*const TcpStream>,
        upstream_udp: Option<*const UdpSocket>,
        upstream_quic_addr: Option<SocketAddr>,
    ) -> Self {

        // allocate SIMD-aligned buffers
        let in_cap = 64 * 1024;
        let out_cap = 64 * 1024;

        let in_buf = {
            let raw = std::alloc::alloc_zeroed(
                std::alloc::Layout::from_size_align(in_cap, 32).unwrap()
            );
            NonNull::new(raw).expect("failed alloc in_buf")
        };

        let out_buf = {
            let raw = std::alloc::alloc_zeroed(
                std::alloc::Layout::from_size_align(out_cap, 32).unwrap()
            );
            NonNull::new(raw).expect("failed alloc out_buf")
        };

        Self {
            // client raw sockets
            client_tcp,
            client_udp,
            client_quic_addr,

            // upstream raw sockets
            upstream_tcp,
            upstream_udp,
            upstream_quic_addr,

            // initial FSM state
            state: ProxyState::Transport(
                crate::states::TransportState::Conn(TransportConnState::AcceptClientConnection)
            ),

            is_reabable: false,
            is_writable: false,

            // buffers
            in_buf, in_cap, in_len: 0,
            out_buf, out_cap, out_len: 0,

            // controller channel
            controller_tx: tx,
            controller_rx: rx,

            // misc
            scratch: 0,
            last_activity: std::time::Instant::now(),
        }
    }


    // ===================================================================
    // QUIC PACKET INGEST
    // ===================================================================

    pub unsafe fn push_udp_datagram(&mut self, pkt: &[u8]) {
        let len = pkt.len().min(self.in_cap);
        std::ptr::copy_nonoverlapping(pkt.as_ptr(), self.in_buf.as_ptr(), len);
        self.in_len = len;
    }
}


// ===================================================================
// FSM DISPATCHER
// ===================================================================

pub async unsafe fn drive_connection(conn: &mut Connection) -> NextStep {
    println!("drivecconntion,{:?} ", conn.state);
    match &conn.state {
        ProxyState::Transport(s) => transport_handler(conn, *s).await,
        ProxyState::Tls(s)       => tls_handler(conn, s.clone()).await,
        ProxyState::Quic(s)      => quic_handler(conn, s.clone()).await,
        ProxyState::Detect(s)    => detect_handler(conn, s.clone()).await,
        ProxyState::H1(s)        => h1_handler(conn, s.clone()).await,
        ProxyState::H2(s)        => h2_handler(conn, s.clone()).await,
        ProxyState::H3(s)        => h3_handler(conn, s.clone()).await,
        ProxyState::Intercept(s) => intercept_handler(conn, s.clone()).await,
        ProxyState::Upstream(s)  => upstream_handler(conn, s.clone()).await,
        ProxyState::Stream(s)    => stream_handler(conn, s.clone()).await,
        ProxyState::Shutdown(s)  => shutdown_handler(conn, *s).await,
    }
}
