use crate::{connection::Connection, fsm::NextStep, states::QuicState};

pub async unsafe fn quic_handler(_: &mut Connection, _: QuicState) -> NextStep {
    println!("[QUIC] Not implemented");
    NextStep::Close
}
