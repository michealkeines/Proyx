use crate::{
    connection::{Connection, ReadEnum},
    fsm::NextStep,
    states::{DetectBootstrapState, DetectState, ProxyState, TransportConnState, TransportState},
};

pub async unsafe fn transport_handler(conn: &mut Connection, s: TransportState) -> NextStep {
    println!("[TRANSPORT] {:?}", s);

    match s {
        TransportState::Conn(state) => match state {
            TransportConnState::AcceptClientConnection => {
                debug_assert!(
                    conn.client_tcp.is_some(),
                    "Transport handler expected client TCP socket"
                );

                println!(
                    "[TRANSPORT] AcceptClientConnection, readable={:?}",
                    conn.readable
                );

                if conn.client_tcp.is_some() {
                    conn.readable = Some(ReadEnum::Tcp(conn.client_tcp.unwrap()));
                    println!(" → Waiting for first client read");
                    return NextStep::WaitRead(ProxyState::Detect(DetectState::Bootstrap(
                        DetectBootstrapState::DetectProtocolBegin,
                    )));
                }

                return NextStep::Continue(ProxyState::Detect(DetectState::Bootstrap(
                    DetectBootstrapState::DetectProtocolBegin,
                )));
            }

            TransportConnState::ClientTcpHandshake => {
                println!("[TRANSPORT] Skipping TCP handshake");
                return NextStep::Continue(ProxyState::Transport(TransportState::Conn(
                    TransportConnState::ClientTcpEstablished,
                )));
            }

            TransportConnState::ClientTcpEstablished => {
                println!("[TRANSPORT] Client established –> Detect");
                return NextStep::Continue(ProxyState::Detect(DetectState::Bootstrap(
                    DetectBootstrapState::DetectProtocolBegin,
                )));
            }
        },

        _ => {
            println!("[TRANSPORT] Unhandled state");
            return NextStep::Close;
        }
    }
}
