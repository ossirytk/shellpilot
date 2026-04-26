use shellpilot::run;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    run().await
}
