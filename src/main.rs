mod listener;
mod intercept;
mod controller;
mod states;
mod fsm;
mod connection;
mod scheduling;
use tokio::task::LocalSet;
mod handlers;

use crate::listener::run_main_listener;

pub async fn run_main_listener_safe(addr: &str) -> std::io::Result<()> {
    unsafe { run_main_listener(addr).await }
}


#[tokio::main(flavor = "current_thread")]
async fn main() {
    let local = LocalSet::new();

    local.run_until(async {
        run_main_listener_safe("0.0.0.0:443").await.unwrap();
    }).await;
}


