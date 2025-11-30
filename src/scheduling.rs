use tokio::task;

use crate::{
    connection::{Connection, drive_connection},
    controller::{ControllerMsg, process_controller_message},
    fsm::NextStep,
};

pub type ConnPtr = *mut Connection;

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

pub unsafe fn schedule_next(conn: ConnPtr, step: NextStep) {
    match step {
        NextStep::Continue(new_state) => {
            println!("[FSM] Continue → {:?}", new_state);

            (*conn).state = new_state;
            schedule_immediate(conn);
        }

        NextStep::WaitRead(next_step) => {
            // println!("[FSM] WaitClientRead");

            if let Some(ptr) = (*conn).readable {
                tokio::task::spawn_local(async move {
                    // println!("[I/O] waiting: client.readable()");
                    let _ = (*conn).readable.unwrap().readable();

                    // println!("[I/O] ready: client.readable()");
                    schedule_next(conn, NextStep::Continue(next_step));
                });
            }
        }

        NextStep::WaitWrite(next_step) => {
            println!("[FSM] WaitClientWrite");

            if let Some(ptr) = (*conn).writable {
                tokio::task::spawn_local(async move {
                    println!("[I/O] waiting: client.writable()");
                    let _ = (*conn).writable.unwrap().writable();

                    println!("[I/O] ready: client.writable()");
                    schedule_next(conn, NextStep::Continue(next_step));
                });
            }
        }

        NextStep::WaitController => {
            println!("[FSM] WaitController");
            tokio::task::spawn_local(async move {
                println!("[CTRL] controller event wake");
                schedule_immediate(conn);
            });
        }

        NextStep::WaitTimer(duration) => {
            println!("[FSM] WaitTimer for {:?}ms", duration.as_millis());

            tokio::task::spawn_local(async move {
                tokio::time::sleep(duration).await;
                println!("[TIMER] timer done");
                schedule_immediate(conn);
            });
        }

        NextStep::Close => {
            println!("[FSM] Close → cleaning up conn");
            cleanup_connection(conn);
        }
    }
}

pub fn cleanup_connection(conn: ConnPtr) {
    unsafe {
        drop(Box::from_raw(conn));
    }
}
