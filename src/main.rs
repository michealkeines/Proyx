use Proyx::run_main_listener_safe;
use tokio::task::LocalSet;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let local = LocalSet::new();

    local
        .run_until(async {
            run_main_listener_safe("0.0.0.0:443").await.unwrap();
        })
        .await;
}
