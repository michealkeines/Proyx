use crate::{connection::Connection, fsm::NextStep, states::ShutdownState};

pub async unsafe fn shutdown_handler(_: &mut Connection, _: ShutdownState) -> NextStep {
    println!("[SHUTDOWN]");
    NextStep::Close
}
