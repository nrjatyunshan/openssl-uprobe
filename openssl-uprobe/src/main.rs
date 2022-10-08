use aya::{include_bytes_aligned, Bpf};
use aya::programs::UProbe;
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn,LevelFilter};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::builder().format_timestamp(None).filter_level(LevelFilter::Info).init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/openssl-uprobe"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/openssl-uprobe"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut UProbe = bpf.program_mut("uprobe_enter_openssl_write").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("SSL_write"), 0, "libssl", opt.pid.try_into()?)?;

    let program: &mut UProbe = bpf.program_mut("uprobe_exit_openssl_write").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("SSL_write"), 0, "libssl", opt.pid.try_into()?)?;

    let program: &mut UProbe = bpf.program_mut("uprobe_enter_openssl_read").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("SSL_read"), 0, "libssl", opt.pid.try_into()?)?;

    let program: &mut UProbe = bpf.program_mut("uprobe_exit_openssl_read").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("SSL_read"), 0, "libssl", opt.pid.try_into()?)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
