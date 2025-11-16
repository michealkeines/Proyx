use crate::scheduling::{ConnPtr, conn_mut, schedule_next};
use crate::fsm::NextStep;
use crate::states::ProxyState;

#[derive(Debug)]
pub enum ControllerMsg {
    Raw(String),
    Allow,
    Block,
    Modify(Vec<u8>),
    // Later: header modify, body chunk inject, etc.
}

pub unsafe fn process_controller_message(conn: &ConnPtr, msg: ControllerMsg) {
    let c = conn_mut(conn);

    // Debug logging
    println!("[controller] received: {:?}", msg);

    // For now, just store something so handler can inspect
    match msg {
        ControllerMsg::Raw(s) => {
            // store hash or small marker
            c.scratch = seahash::hash(s.as_bytes());
        }

        ControllerMsg::Allow => {
            c.scratch = 1;
        }

        ControllerMsg::Block => {
            c.scratch = 2;
        }

        ControllerMsg::Modify(data) => {
            // Not rewriting anything yet — only marking we got modification
            c.scratch = seahash::hash(&data);
        }
    }

    // After controller responded → FSM resumes from its current state
    //
    // We DO NOT modify c.state here.
    // The handler (H1/H2/H3/Intercept) already expects that after WaitController
    // the next invocation of drive_connection() resumes the same state's logic.
    //
    schedule_next(conn.clone(), NextStep::Continue(c.state.clone()));
}
