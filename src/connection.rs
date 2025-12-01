use std::{alloc::Layout, net::SocketAddr, ptr::NonNull};

use crate::config::CONFIG;
use crate::controller::ControllerMsg;
use crate::fsm::NextStep;
use crate::handlers::*;
use crate::states::{H1Session, ProxyState, TransportConnState};
use hpack::{Decoder, Encoder};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::net::{UnixDatagram, UnixStream};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
type NestedServerTlsStream = ServerTlsStream<ServerTlsStream<TcpStream>>;

#[derive(Debug, Clone, Copy)]
pub enum ReadEnum {
    Tcp(*mut TcpStream),
    ClientTls(*mut ClientTlsStream<TcpStream>),
    SeverTls(*mut ServerTlsStream<TcpStream>),
    SeverTlsNested(*mut NestedServerTlsStream),
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
            ReadEnum::SeverTlsNested(p) => {
                let outer = (*p).as_mut().unwrap();
                let (inner_tls, _) = outer.get_mut();
                let (tcp, _) = inner_tls.get_mut();
                tcp.readable().await
            }
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
    SeverTlsNested(*mut NestedServerTlsStream),
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

            WriteEnum::SeverTlsNested(p) => {
                let outer = (*p).as_mut().unwrap();
                let (inner_tls, _) = outer.get_mut();
                let (tcp, _) = inner_tls.get_mut();
                tcp.writable().await
            }

            WriteEnum::UnixStream(p) => (*p).as_mut().unwrap().writable().await,

            WriteEnum::UnixDatagram(p) => (*p).as_mut().unwrap().writable().await,

            WriteEnum::Udp(p) => (*p).as_mut().unwrap().writable().await,
        }
    }
}

pub struct Connection {
    pub client_tcp: Option<*mut TcpStream>,
    pub client_tls: Option<*mut ServerTlsStream<TcpStream>>,
    /// Nested TLS stream when MITMing inside a CONNECT tunnel (TLS over TLS).
    pub client_mitm_tls: Option<*mut NestedServerTlsStream>,
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
    pub h2_pending_upstream_frames: Vec<u8>,
    pub h2_use_upstream_h2: bool,
    pub h2_client_max_frame_size: usize,
    pub h2_upstream_max_frame_size: usize,
    pub h2_upstream_preface_sent: bool,
    pub h2_client_preface_seen: bool,
    pub h2_upstream_ready: bool,

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
    pub h2_decoder: Decoder<'static>,
    pub h2_upstream_decoder: Decoder<'static>,
    pub h2_client_encoder: Encoder<'static>,
    pub h2_upstream_encoder: Encoder<'static>,
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
        let in_cap = CONFIG.buffers.io_cap;
        let out_cap = CONFIG.buffers.io_cap;

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
            client_mitm_tls: None,
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
            h2_pending_upstream_frames: Vec::new(),
            h2_use_upstream_h2: true,
            h2_client_max_frame_size: CONFIG.h2.max_frame_size,
            h2_upstream_max_frame_size: CONFIG.h2.max_frame_size,
            h2_upstream_preface_sent: false,
            h2_client_preface_seen: false,
            h2_upstream_ready: false,
            h2_decoder: Decoder::new(),
            h2_upstream_decoder: Decoder::new(),
            h2_client_encoder: Encoder::new(),
            h2_upstream_encoder: Encoder::new(),
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

unsafe fn drop_tcp(ptr: Option<*mut TcpStream>) {
    if let Some(p) = ptr {
        drop(Box::from_raw(p));
    }
}

unsafe fn drop_client_tls(ptr: Option<*mut ClientTlsStream<TcpStream>>) {
    if let Some(p) = ptr {
        drop(Box::from_raw(p));
    }
}

unsafe fn drop_server_tls(ptr: Option<*mut ServerTlsStream<TcpStream>>) {
    if let Some(p) = ptr {
        drop(Box::from_raw(p));
    }
}

unsafe fn drop_nested_server_tls(ptr: Option<*mut NestedServerTlsStream>) {
    if let Some(p) = ptr {
        drop(Box::from_raw(p));
    }
}

unsafe fn drop_pooled_upstream(entry: PooledUpstream) {
    drop_client_tls(entry.tls);
    drop_tcp(entry.tcp);
}

impl Connection {
    pub fn take_pooled_upstream(&mut self, target: &TargetAddr, tls_required: bool) -> bool {
        if let Some(idx) = self
            .upstream_pool
            .iter()
            .position(|p| p.target.host == target.host && p.target.port == target.port)
        {
            let mut entry = self.upstream_pool.remove(idx);
            let mut reused = false;

            if tls_required {
                if let Some(tls) = entry.tls.take() {
                    self.upstream_tls = Some(tls);
                    reused = true;
                }
            } else if let Some(tcp) = entry.tcp.take() {
                self.upstream_tcp = Some(tcp);
                reused = true;
            }

            unsafe {
                if let Some(tls) = entry.tls.take() {
                    drop_client_tls(Some(tls));
                }
                if let Some(tcp) = entry.tcp.take() {
                    drop_tcp(Some(tcp));
                }
            }

            return reused;
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

        let target = self.target_addr.as_ref().unwrap().clone();

        if let Some(idx) = self
            .upstream_pool
            .iter()
            .position(|p| p.target.host == target.host && p.target.port == target.port)
        {
            let existing = self.upstream_pool.remove(idx);
            unsafe { drop_pooled_upstream(existing) };
        }

        if self.upstream_pool.len() >= CONFIG.upstream.pool_limit {
            let evicted = self.upstream_pool.remove(0);
            unsafe { drop_pooled_upstream(evicted) };
        }

        let entry = PooledUpstream {
            target,
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
                return;
            }
        }

        if let Some(ptr) = self.client_mitm_tls {
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

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe {
            drop_server_tls(self.client_tls.take());
            drop_nested_server_tls(self.client_mitm_tls.take());
            drop_tcp(self.client_tcp.take());
            drop_client_tls(self.upstream_tls.take());
            drop_tcp(self.upstream_tcp.take());

            for entry in self.upstream_pool.drain(..) {
                drop_pooled_upstream(entry);
            }

            let in_layout = Layout::from_size_align(self.in_cap, 32).unwrap();
            std::alloc::dealloc(self.in_buf.as_ptr(), in_layout);
            let out_layout = Layout::from_size_align(self.out_cap, 32).unwrap();
            std::alloc::dealloc(self.out_buf.as_ptr(), out_layout);
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
