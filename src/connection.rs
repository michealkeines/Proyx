use std::{net::SocketAddr, ptr::NonNull};

use crate::controller::ControllerMsg;
use crate::fsm::NextStep;
use crate::handlers::*;
use crate::states::{H1Session, ProxyState, TransportConnState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::net::{UnixDatagram, UnixStream};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;

#[derive(Debug, Clone, Copy)]
pub enum ReadEnum {
    Tcp(*mut TcpStream),
    ClientTls(*mut ClientTlsStream<TcpStream>),
    SeverTls(*mut ServerTlsStream<TcpStream>),
    UnixStream(*mut UnixStream),
    UnixDatagram(*mut UnixDatagram),
    Udp(*mut UdpSocket),
}

impl ReadEnum {
    pub async unsafe fn readable(&mut self) -> std::io::Result<()> {
        match self {
            ReadEnum::Tcp(p) => (*p).as_mut().unwrap().readable().await,
            ReadEnum::ClientTls(p) => (*p).as_mut().unwrap().get_mut().0.readable().await,
            ReadEnum::SeverTls(p) => (*p).as_mut().unwrap().get_mut().0.readable().await,
            ReadEnum::UnixStream(p) => (*p).as_mut().unwrap().readable().await,
            ReadEnum::UnixDatagram(p) => (*p).as_mut().unwrap().readable().await,
            ReadEnum::Udp(p) => (*p).as_mut().unwrap().readable().await,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum WriteEnum {
    Tcp(*mut TcpStream),
    ClientTls(*mut ClientTlsStream<TcpStream>),
    SeverTls(*mut ServerTlsStream<TcpStream>),
    UnixStream(*mut UnixStream),
    UnixDatagram(*mut UnixDatagram),
    Udp(*mut UdpSocket),
}

impl WriteEnum {
    pub async unsafe fn writable(&mut self) -> std::io::Result<()> {
        match self {
            WriteEnum::Tcp(p) => (*p).as_mut().unwrap().writable().await,

            WriteEnum::ClientTls(p) => (*p).as_mut().unwrap().get_mut().0.writable().await,

            WriteEnum::SeverTls(p) => (*p).as_mut().unwrap().get_mut().0.writable().await,

            WriteEnum::UnixStream(p) => (*p).as_mut().unwrap().writable().await,

            WriteEnum::UnixDatagram(p) => (*p).as_mut().unwrap().writable().await,

            WriteEnum::Udp(p) => (*p).as_mut().unwrap().writable().await,
        }
    }
}

pub struct Connection {
    pub client_tcp: Option<*mut TcpStream>,
    pub client_tls: Option<*mut ServerTlsStream<TcpStream>>,
    /// Raw pointer to shared UDP socket (only for QUIC)
    pub client_udp: Option<*mut UdpSocket>,

    /// Remote peer of QUIC client
    pub client_quic_addr: Option<SocketAddr>,

    pub upstream_tcp: Option<*mut TcpStream>,
    pub upstream_tls: Option<*mut ClientTlsStream<TcpStream>>,

    pub upstream_udp: Option<*mut UdpSocket>,
    pub upstream_quic_addr: Option<SocketAddr>,

    pub state: ProxyState,

    pub readable: Option<ReadEnum>,
    pub writable: Option<WriteEnum>,

    pub client_h1_state: H1Session,
    pub upstream_h1_state: H1Session,

    pub in_buf: NonNull<u8>,
    pub in_cap: usize,
    pub in_len: usize,

    pub out_buf: NonNull<u8>,
    pub out_cap: usize,
    pub out_len: usize,

    pub controller_tx: UnboundedSender<ControllerMsg>,
    pub controller_rx: UnboundedReceiver<ControllerMsg>,

    pub scratch: u64,
    pub last_activity: std::time::Instant,
}

impl Connection {
    pub fn new_tcp_raw(
        client_ptr: *mut TcpStream,
        tx: UnboundedSender<ControllerMsg>,
        rx: UnboundedReceiver<ControllerMsg>,
    ) -> Self {
        unsafe { Self::create(Some(client_ptr), None, None, tx, rx, None, None, None) }
    }

    pub fn new_udp_raw(
        peer: SocketAddr,
        udp_ptr: *mut UdpSocket,
        tx: UnboundedSender<ControllerMsg>,
        rx: UnboundedReceiver<ControllerMsg>,
    ) -> Self {
        unsafe { Self::create(None, Some(udp_ptr), Some(peer), tx, rx, None, None, None) }
    }

    pub fn new_upstream_udp_raw(
        peer: SocketAddr,
        udp_ptr: *mut UdpSocket,
        tx: UnboundedSender<ControllerMsg>,
        rx: UnboundedReceiver<ControllerMsg>,
    ) -> Self {
        unsafe { Self::create(None, None, None, tx, rx, None, Some(udp_ptr), Some(peer)) }
    }

    pub fn new_upstream_tcp_raw(
        tcp_ptr: *mut TcpStream,
        tx: UnboundedSender<ControllerMsg>,
        rx: UnboundedReceiver<ControllerMsg>,
    ) -> Self {
        unsafe { Self::create(None, None, None, tx, rx, Some(tcp_ptr), None, None) }
    }

    unsafe fn create(
        client_tcp: Option<*mut TcpStream>,
        client_udp: Option<*mut UdpSocket>,
        client_quic_addr: Option<SocketAddr>,

        tx: UnboundedSender<ControllerMsg>,
        rx: UnboundedReceiver<ControllerMsg>,
        upstream_tcp: Option<*mut TcpStream>,
        upstream_udp: Option<*mut UdpSocket>,
        upstream_quic_addr: Option<SocketAddr>,
    ) -> Self {
        // allocate SIMD-aligned buffers
        let in_cap = 64 * 1024;
        let out_cap = 64 * 1024;

        let in_buf = {
            let raw =
                std::alloc::alloc_zeroed(std::alloc::Layout::from_size_align(in_cap, 32).unwrap());
            NonNull::new(raw).expect("failed alloc in_buf")
        };

        let out_buf = {
            let raw =
                std::alloc::alloc_zeroed(std::alloc::Layout::from_size_align(out_cap, 32).unwrap());
            NonNull::new(raw).expect("failed alloc out_buf")
        };

        Self {
            // client raw sockets
            client_tcp,
            client_tls: None,
            client_udp,
            client_quic_addr,

            // upstream raw sockets
            upstream_tcp,
            upstream_tls: None,
            upstream_udp,
            upstream_quic_addr,

            // initial FSM state
            state: ProxyState::Transport(crate::states::TransportState::Conn(
                TransportConnState::AcceptClientConnection,
            )),

            readable: None,
            writable: None,

            client_h1_state: H1Session::new(),
            upstream_h1_state: H1Session::new(),

            // buffers
            in_buf,
            in_cap,
            in_len: 0,
            out_buf,
            out_cap,
            out_len: 0,

            // controller channel
            controller_tx: tx,
            controller_rx: rx,

            // misc
            scratch: 0,
            last_activity: std::time::Instant::now(),
        }
    }

    pub unsafe fn push_udp_datagram(&mut self, pkt: &[u8]) {
        let len = pkt.len().min(self.in_cap);
        std::ptr::copy_nonoverlapping(pkt.as_ptr(), self.in_buf.as_ptr(), len);
        self.in_len = len;
    }
}

pub async unsafe fn drive_connection(conn: &mut Connection) -> NextStep {
    println!("drivecconntion,{:?} ", conn.state);
    match &conn.state {
        ProxyState::Transport(s) => transport_handler(conn, *s).await,
        ProxyState::Tls(s) => tls_handler(conn, s.clone()).await,
        ProxyState::Quic(s) => quic_handler(conn, s.clone()).await,
        ProxyState::Detect(s) => detect_handler(conn, s.clone()).await,
        ProxyState::H1(s) => h1_handler(conn, s.clone()).await,
        ProxyState::H2(s) => h2_handler(conn, s.clone()).await,
        ProxyState::H3(s) => h3_handler(conn, s.clone()).await,
        ProxyState::Intercept(s) => intercept_handler(conn, s.clone()).await,
        ProxyState::Upstream(s) => upstream_handler(conn, s.clone()).await,
        ProxyState::Stream(s) => stream_handler(conn, s.clone()).await,
        ProxyState::Shutdown(s) => shutdown_handler(conn, *s).await,
    }
}
