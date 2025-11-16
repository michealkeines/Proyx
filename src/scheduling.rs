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
            println!("[FSM] Continue → {:?}", new_state);

            conn_mut(&conn).state = new_state;
            schedule_immediate(conn);
        }


        // --------------------------------------------------------------
        // CLIENT TCP READABLE
        // --------------------------------------------------------------
        NextStep::WaitClientRead => {
            // println!("[FSM] WaitClientRead");

            let c = conn_mut(&conn);
            c.is_reabable = true;
            if let Some(ptr) = c.client_tcp {
                let tcp = ptr.as_ref().unwrap().clone();

                tokio::task::spawn_local(async move {
                    // println!("[I/O] waiting: client.readable()");
                    let _ = tcp.readable().await;
                    
                    // println!("[I/O] ready: client.readable()");
                    schedule_immediate(conn);
                });
            } else {
                println!("[WARN] WaitClientRead but no TCP client");
                schedule_immediate(conn);
            }
        }


        // --------------------------------------------------------------
        // CLIENT TCP WRITABLE
        // --------------------------------------------------------------
        NextStep::WaitClientWrite => {
            println!("[FSM] WaitClientWrite");

            let c = conn_mut(&conn);
            c.is_writable = true;
            if let Some(ptr) = c.client_tcp {
                let tcp = ptr.as_ref().unwrap().clone();

                tokio::task::spawn_local(async move {
                    println!("[I/O] waiting: client.writable()");
                    let _ = tcp.writable().await;
                    
                    println!("[I/O] ready: client.writable()");
                    schedule_immediate(conn);
                });
            } else {
                println!("[WARN] WaitClientWrite but no TCP client");
                schedule_immediate(conn);
            }
        }


        // --------------------------------------------------------------
        // UPSTREAM TCP READABLE
        // --------------------------------------------------------------
        NextStep::WaitUpstreamRead => {
            println!("[FSM] WaitUpstreamRead");

            let c = conn_mut(&conn);

            if let Some(ptr) = c.upstream_tcp {
                let tcp = ptr.as_ref().unwrap().clone();

                tokio::task::spawn_local(async move {
                    println!("[I/O] waiting: upstream.readable()");
                    let _ = tcp.readable().await;
                    println!("[I/O] ready: upstream.readable()");
                    schedule_immediate(conn);
                });
            } else {
                println!("[WARN] WaitUpstreamRead but no upstream TCP");
                schedule_immediate(conn);
            }
        }


        // --------------------------------------------------------------
        // UPSTREAM TCP WRITABLE
        // --------------------------------------------------------------
        NextStep::WaitUpstreamWrite => {
            println!("[FSM] WaitUpstreamWrite");

            let c = conn_mut(&conn);

            if let Some(ptr) = c.upstream_tcp {
                let tcp = ptr.as_ref().unwrap().clone();

                tokio::task::spawn_local(async move {
                    println!("[I/O] waiting: upstream.writable()");
                    let _ = tcp.writable().await;
                    println!("[I/O] ready: upstream.writable()");
                    schedule_immediate(conn);
                });
            } else {
                println!("[WARN] WaitUpstreamWrite but no upstream TCP");
                schedule_immediate(conn);
            }
        }


        // --------------------------------------------------------------
        // UDP / QUIC - no waiting here
        // --------------------------------------------------------------
        NextStep::WaitController => {
            println!("[FSM] WaitController");
            tokio::task::spawn_local(async move {
                println!("[CTRL] controller event wake");
                schedule_immediate(conn);
            });
        }


        // --------------------------------------------------------------
        // Timer wait
        // --------------------------------------------------------------
        NextStep::WaitTimer(duration) => {
            println!("[FSM] WaitTimer for {:?}ms", duration.as_millis());

            tokio::task::spawn_local(async move {
                tokio::time::sleep(duration).await;
                println!("[TIMER] timer done");
                schedule_immediate(conn);
            });
        }


        // --------------------------------------------------------------
        // Connection teardown
        // --------------------------------------------------------------
        NextStep::Close => {
            println!("[FSM] Close → cleaning up conn");
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
