use crate::fsm::NextStep;
use crate::scheduling::{ConnPtr, schedule_next};
use crate::states::ProxyState;

#[derive(Debug)]
pub enum ControllerMsg {
    Raw(String),
    Allow,
    Block,
    Modify(Vec<u8>),
    // Later: header modify, body chunk inject, etc.
}

pub unsafe fn process_controller_message(conn: ConnPtr, msg: ControllerMsg) {
    // Debug logging
    println!("[controller] received: {:?}", msg);

    //
    // We DO NOT modify c.state here.
    // The handler (H1/H2/H3/Intercept) already expects that after WaitController
    // the next invocation of drive_connection() resumes the same state's logic.
    //
    schedule_next(conn.clone(), NextStep::Continue((*conn).state.clone()));
}
