//! SmartFuzz CLI entrypoint.

use clap::Parser;
use smartfuzz::cli::Args;
use smartfuzz::ScanEngine;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let mut args = Args::parse();

    if let Err(e) = args.apply_config_file() {
        eprintln!("smartfuzz config error: {e:#}");
        std::process::exit(1);
    }

    let filter = if args.verbose {
        EnvFilter::new("smartfuzz=debug,info")
    } else {
        EnvFilter::new("smartfuzz=warn")
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();

    if let Err(e) = run(args).await {
        eprintln!("smartfuzz error: {e:#}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> anyhow::Result<()> {
    // Config already applied in main
    let engine = ScanEngine::new(args);
    let _result = engine.run().await?;
    Ok(())
}
