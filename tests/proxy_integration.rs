use std::{error::Error, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
    task::LocalSet,
    time::sleep,
};

use Proyx::run_main_listener_safe;

async fn run_dummy_upstream(port: u16) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let (mut socket, _) = listener.accept().await?;

    let mut buffer = Vec::new();
    loop {
        let mut chunk = [0u8; 1024];
        let n = socket.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..n]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    socket
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO")
        .await?;

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn h1_flow_with_curl() -> Result<(), Box<dyn Error + Send + Sync>> {
    let proxy_port = 18443;
    let upstream_port = 18444;

    let proxy_addr = format!("127.0.0.1:{}", proxy_port);

    let local = LocalSet::new();
    local.spawn_local({
        let proxy_addr = proxy_addr.clone();
        async move {
            run_main_listener_safe(&proxy_addr).await.unwrap();
        }
    });

    local
        .run_until(async move {
            let upstream_handle = tokio::spawn(run_dummy_upstream(upstream_port));
            // give the proxy and upstream a moment to start
            sleep(Duration::from_millis(100)).await;

            let root_pem = std::env::current_dir()?
                .join("src/CA/root.pem")
                .to_string_lossy()
                .into_owned();

            let output = Command::new("curl")
                .arg("--silent")
                .arg("--show-error")
                .arg("--http1.1")
                .arg("--cacert")
                .arg(root_pem)
                .arg("-H")
                .arg(format!("Host: 127.0.0.1:{}", upstream_port))
                .arg(format!("https://127.0.0.1:{}", proxy_port))
                .output()
                .await?;

            assert!(
                output.status.success(),
                "curl failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let body = std::str::from_utf8(&output.stdout)?;
            assert!(body.trim() == "HELLO");

            upstream_handle.await??;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        })
        .await?;

    Ok(())
}
