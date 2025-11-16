use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::rc::Rc;

use tokio::net::tcp;
use tokio::{task};
use tokio::io::AsyncWriteExt;

use crate::{
    connection::{Connection, drive_connection},
    controller::{ControllerMsg, process_controller_message},
    fsm::NextStep,
};


/// Single-threaded wrapper for Connection
pub type ConnPtr = *mut Connection;


#[inline]
pub fn conn_mut(conn: &ConnPtr) -> &mut Connection {
    unsafe { &mut *conn.as_mut().unwrap() }
}


// ======================================================================
// schedule_immediate — run FSM now
// ======================================================================

pub unsafe fn schedule_immediate(conn: ConnPtr) {
    let conn_local = conn.clone();

    task::spawn_local(async move {
        let next = {
            let c = unsafe { &mut *conn_local.as_mut().unwrap() };
            drive_connection(c).await
        };

        schedule_next(conn_local, next);
    });
}



// ======================================================================
// schedule_next — handle I/O waits, timers, controller, close
// ======================================================================
//
// MUST support:
//  ✔ TCP client readable/writable
//  ✔ TCP upstream readable/writable
//  ✔ UDP QUIC → no readable/writable waits (datagram-driven)
//  ✔ Raw pointers for TCP + UDP
// ======================================================================

pub unsafe fn schedule_next(conn: ConnPtr, step: NextStep) {
    match step {
        // --------------------------------------------------------------
        // Continue immediately
        // --------------------------------------------------------------
        NextStep::Continue(new_state) => {
            conn_mut(&conn).state = new_state;
            schedule_immediate(conn);
        }


        // --------------------------------------------------------------
        // CLIENT TCP READABLE
        // --------------------------------------------------------------
        NextStep::WaitClientRead => {
            let c = conn_mut(&conn);

            if let Some(ptr) = c.client_tcp {
                let tcp = unsafe { ptr.as_ref().unwrap() }.clone();

                tokio::task::spawn_local(async move {
                    let _ = tcp.readable().await;
                    schedule_immediate(conn);
                });
            }
        }


        // --------------------------------------------------------------
        // CLIENT TCP WRITABLE
        // --------------------------------------------------------------
        NextStep::WaitClientWrite => {
            let c = conn_mut(&conn);

            if let Some(ptr) = c.client_tcp {
                let tcp = unsafe { ptr.as_ref().unwrap() }.clone();

                tokio::task::spawn_local(async move {
                    let _ = tcp.writable().await;
                    schedule_immediate(conn);
                });
            }
        }


        // --------------------------------------------------------------
        // UPSTREAM TCP READABLE
        // --------------------------------------------------------------
        NextStep::WaitUpstreamRead => {
            let c = conn_mut(&conn);

            if let Some(ptr) = c.upstream_tcp {
                let tcp = unsafe { ptr.as_ref().unwrap() }.clone();

                tokio::task::spawn_local(async move {
                    let _ = tcp.readable().await;
                    schedule_immediate(conn);
                });
            }
        }


        // --------------------------------------------------------------
        // UPSTREAM TCP WRITABLE
        // --------------------------------------------------------------
        NextStep::WaitUpstreamWrite => {
            let c = conn_mut(&conn);

            if let Some(ptr) = c.upstream_tcp {
                let tcp = unsafe { ptr.as_ref().unwrap() }.clone();

                tokio::task::spawn_local(async move {
                    let _ = tcp.writable().await;
                    schedule_immediate(conn);
                });
            }
        }


        // --------------------------------------------------------------
        // UDP / QUIC DOES NOT WAIT ON READABILITY/WRTIABILITY
        //
        // QUIC flow never uses these states; datagrams trigger FSM.
        // --------------------------------------------------------------


        // --------------------------------------------------------------
        // Wait for controller message
        // --------------------------------------------------------------
        NextStep::WaitController => {
            tokio::task::spawn_local(async move {
                schedule_immediate(conn);
            });
        }


        // --------------------------------------------------------------
        // Timer wait
        // --------------------------------------------------------------
        NextStep::WaitTimer(duration) => {
            tokio::task::spawn_local(async move {
                tokio::time::sleep(duration).await;
                schedule_immediate(conn);
            });
        }


        // --------------------------------------------------------------
        // Connection teardown
        // --------------------------------------------------------------
        NextStep::Close => {
            cleanup_connection(conn);
        }
    }
}



// ======================================================================
// cleanup_connection — close sockets, free buffers
// ======================================================================

pub fn cleanup_connection(conn: ConnPtr) {
    let c = conn_mut(&conn);

    // ------------------------------
    // TCP client
    // ------------------------------
    if let Some(ptr) = c.client_tcp.take() {
        
    }

    // ------------------------------
    // TCP upstream
    // ------------------------------
    if let Some(ptr) = c.upstream_tcp.take() {
    }

    // ------------------------------
    // UDP sockets: DO NOT CLOSE
    //
    // These are global listener sockets stored as raw pointers.
    // We only drop the reference here, not the socket.
    // ------------------------------
    c.client_udp = None;
    c.upstream_udp = None;

    // ------------------------------
    // Free buffers
    // ------------------------------
    unsafe {
        if c.in_cap != 0 {
            let layout = std::alloc::Layout::from_size_align(c.in_cap, 8).unwrap();
            std::alloc::dealloc(c.in_buf.as_ptr(), layout);
        }

        if c.out_cap != 0 {
            let layout = std::alloc::Layout::from_size_align(c.out_cap, 8).unwrap();
            std::alloc::dealloc(c.out_buf.as_ptr(), layout);
        }
    }

    // ------------------------------
    // Notify controller
    // ------------------------------
    c.controller_rx.close();
    // let _ = c.controller_tx.send(ControllerMsg::ConnectionClosed);

    // Rc cleanup happens naturally.
}
