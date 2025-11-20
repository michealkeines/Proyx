use tokio::net::{TcpListener, UdpSocket, TcpStream};
use futures::future;

use crate::{
    connection::Connection,
    fsm::NextStep,
    scheduling::schedule_next,
    states::{ProxyState, TransportState, TransportConnState, QuicState, QuicInitialState},
    scheduling::ConnPtr,
};

use std::{ptr, mem, net::SocketAddr};


//
// ============================================================
//   QUIC INTRUSIVE LINKED LIST (RAW POINTER TABLE)
// ============================================================
//

#[repr(C)]
pub struct QuicNode {
    pub cid: u64,
    pub conn: ConnPtr,       // *mut Connection
    pub next: *mut QuicNode, // raw next pointer
}

static mut QUIC_LIST: *mut QuicNode = ptr::null_mut();


/// Lookup QUIC CID in intrusive list
pub unsafe fn quic_lookup(cid: u64) -> Option<ConnPtr> {
    let mut cur = QUIC_LIST;
    while !cur.is_null() {
        let node = &*cur;
        if node.cid == cid {
            return Some(node.conn);
        }
        cur = node.next;
    }
    None
}

/// Insert new QUIC entry (prepend)
pub unsafe fn quic_insert(cid: u64, conn: ConnPtr) {
    let node = Box::into_raw(Box::new(QuicNode {
        cid,
        conn,
        next: QUIC_LIST,
    }));
    QUIC_LIST = node;
}

/// Remove QUIC CID
pub unsafe fn quic_remove(cid: u64) {
    let mut cur = QUIC_LIST;
    let mut prev: *mut QuicNode = ptr::null_mut();

    while !cur.is_null() {
        let node = &*cur;

        if node.cid == cid {
            if prev.is_null() {
                // remove head
                QUIC_LIST = node.next;
            } else {
                (*prev).next = node.next;
            }
            drop(Box::from_raw(cur)); // free node
            return;
        }

        prev = cur;
        cur = node.next;
    }
}



//
// ============================================================
//   MAIN LISTENER
// ============================================================
//

pub async unsafe fn run_main_listener(addr: &str) -> std::io::Result<()> {
    // Init intrusive list
    QUIC_LIST = ptr::null_mut();

    // Bind TCP
    let tcp_listener = TcpListener::bind(addr).await?;

    // Bind UDP socket inside Box -> raw pointer stable forever
    let udp_box = Box::new(UdpSocket::bind(addr).await?);
    let udp_ptr: *mut UdpSocket = Box::into_raw(udp_box);

    println!("Listening on TCP+UDP {}", addr);

    // Keep UDP socket alive forever
    tokio::task::spawn_local(async move {
        udp_quic_receive_loop(udp_ptr).await;
    });

    // TCP accept loop (raw pointer sockets)
    tokio::task::spawn_local(async move {
        tcp_accept_loop(tcp_listener).await;
    });

    future::pending::<()>().await;
    Ok(())
}



//
// ============================================================
//   TCP ACCEPT LOOP
// ============================================================
//

async unsafe fn tcp_accept_loop(listener: TcpListener) {
    loop {
        let (client_stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("TCP accept error: {}", e);
                continue;
            }
        };
        println!("accepted new connect:");
        // Box the TcpStream → raw pointer
        let boxed = Box::new(client_stream);
        let raw_tcp_ptr: *mut TcpStream = Box::into_raw(boxed);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        // Allocate Connection → *mut Connection
        let conn: ConnPtr = Box::into_raw(Box::new(
            Connection::new_tcp_raw(raw_tcp_ptr, tx, rx),
        ));

        // Kick FSM
        schedule_next(
            conn,
            NextStep::Continue(
                ProxyState::Transport(
                    TransportState::Conn(TransportConnState::AcceptClientConnection)
                )
            )
        );
    }
}



//
// ============================================================
//   UDP QUIC RECEIVE LOOP (RAW POINTERS)
// ============================================================
//

async unsafe fn udp_quic_receive_loop(udp_socket_ptr: *mut UdpSocket) {
    let mut buf = [0u8; 2048];

    loop {
        let udp = udp_socket_ptr.as_ref().unwrap();

        let (len, peer) = match udp.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("UDP recv error: {}", e);
                continue;
            }
        };

        let packet = &buf[..len];
        let dcid = quic_extract_dcid(packet);

        // ------------------------------
        // QUIC connection lookup or create
        // ------------------------------
        let conn = match quic_lookup(dcid) {
            Some(c) => c,

            None => {
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

                let conn_ptr: ConnPtr = Box::into_raw(Box::new(
                    Connection::new_udp_raw(peer, udp_socket_ptr, tx, rx)
                ));

                // Insert into intrusive list
                quic_insert(dcid, conn_ptr);

                // Kick FSM start
                schedule_next(
                    conn_ptr,
                    NextStep::Continue(
                        ProxyState::Quic(
                            QuicState::Initial(QuicInitialState::InitialPacket)
                        )
                    )
                );

                conn_ptr
            }
        };

        // ------------------------------
        // Push datagram into buffer
        // ------------------------------
        (*conn).push_udp_datagram(packet);

        // Continue FSM
        schedule_next(
            conn,
            NextStep::Continue(
                ProxyState::Quic(
                    QuicState::Initial(QuicInitialState::InitialPacket)
                )
            )
        );
    }
}



//
// ============================================================
//   QUIC DCID PARSER
// ============================================================
//

pub fn quic_extract_dcid(packet: &[u8]) -> u64 {
    if packet.len() < 10 {
        return 0;
    }
    unsafe {
        let ptr = packet.as_ptr().add(2) as *mut u64;
        u64::from_be(*ptr)
    }
}
