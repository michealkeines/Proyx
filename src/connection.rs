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

#[derive(Debug, Clone)]
pub struct TargetAddr {
    pub host: String,
    pub port: u16,
}

impl TargetAddr {
    pub fn socket_addr(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
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

    pub next_state_after_upstream: Option<ProxyState>,
    pub target_addr: Option<TargetAddr>,
    pub upstream_tls_required: bool,
    pub connect_response_sent: bool,
    pub h2_connect_stream_id: Option<u32>,
    pub negotiated_alpn: Option<String>,
    pub upstream_pool: Vec<PooledUpstream>,

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
            next_state_after_upstream: None,
            target_addr: None,
            upstream_tls_required: true,
            connect_response_sent: false,
            h2_connect_stream_id: None,
            negotiated_alpn: None,
            last_activity: std::time::Instant::now(),
            upstream_pool: Vec::new(),
        }
    }

    pub unsafe fn push_udp_datagram(&mut self, pkt: &[u8]) {
        let len = pkt.len().min(self.in_cap);
        std::ptr::copy_nonoverlapping(pkt.as_ptr(), self.in_buf.as_ptr(), len);
        self.in_len = len;
    }
}

#[derive(Debug)]
pub struct PooledUpstream {
    pub target: TargetAddr,
    pub tcp: Option<*mut TcpStream>,
    pub tls: Option<*mut ClientTlsStream<TcpStream>>,
}

impl Connection {
    pub fn take_pooled_upstream(&mut self, target: &TargetAddr, tls_required: bool) -> bool {
        if let Some(idx) = self.upstream_pool.iter().position(|p| p.target.host == target.host && p.target.port == target.port) {
            let entry = self.upstream_pool.remove(idx);
            if tls_required {
                if let Some(tls) = entry.tls {
                    self.upstream_tls = Some(tls);
                    return true;
                }
            } else if let Some(tcp) = entry.tcp {
                self.upstream_tcp = Some(tcp);
                return true;
            }
        }
        false
    }

    pub fn store_current_upstream_in_pool(&mut self) {
        if self.target_addr.is_none() {
            return;
        }

        if self.upstream_tls.is_none() && self.upstream_tcp.is_none() {
            return;
        }

        let entry = PooledUpstream {
            target: self.target_addr.as_ref().unwrap().clone(),
            tcp: self.upstream_tcp.take(),
            tls: self.upstream_tls.take(),
        };

        self.upstream_pool.push(entry);
    }
}

impl Connection {
    pub fn set_target(&mut self, host: String, port: u16) {
        self.target_addr = Some(TargetAddr { host, port });
    }

    pub fn target(&self) -> Option<&TargetAddr> {
        self.target_addr.as_ref()
    }

    pub unsafe fn fill_target_from_tls_sni(&mut self, default_port: u16) {
        if self.target_addr.is_some() {
            return;
        }

        if let Some(ptr) = self.client_tls {
            let tls_stream = &*ptr;
            let (_, server_conn) = tls_stream.get_ref();

            if let Some(host) = server_conn.server_name() {
                self.target_addr = Some(TargetAddr {
                    host: host.to_string(),
                    port: default_port,
                });
            }
        }
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
