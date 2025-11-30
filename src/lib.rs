pub mod CA;
pub mod config;
pub mod connection;
pub mod controller;
pub mod fsm;
pub mod handlers;
pub mod intercept;
pub mod listener;
pub mod scheduling;
pub mod states;

pub async fn run_main_listener_safe(addr: &str) -> std::io::Result<()> {
    unsafe { listener::run_main_listener(addr).await }
}
