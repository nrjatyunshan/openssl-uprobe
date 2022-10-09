use aya::programs::UProbe;
use aya::{include_bytes_aligned, Bpf};
use clap::Parser;
use log::{info, LevelFilter};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(LevelFilter::Info)
        .init();

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/openssl-uprobe"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/openssl-uprobe"
    ))?;

    // TODO: 扫描 /proc/ 目录中的所有进程, 并从进程对应的 maps 里拿到 libssl
    // 的绝对路径, 最后拼成 /proc/pid/root/path/to/libssl.so.x.x 的形式.
    // 通过循环对每个有效的进程设置以下 4 个 hook 函数.
    let target = "libssl";
    let fn_name = "uprobe_enter_openssl_write";
    let program: &mut UProbe = bpf.program_mut(fn_name).unwrap().try_into()?;
    program.load()?;
    program.attach(Some("SSL_write"), 0, target, opt.pid.try_into()?)?;

    let fn_name = "uprobe_exit_openssl_write";
    let program: &mut UProbe = bpf.program_mut(fn_name).unwrap().try_into()?;
    program.load()?;
    program.attach(Some("SSL_write"), 0, target, opt.pid.try_into()?)?;

    let fn_name = "uprobe_enter_openssl_read";
    let program: &mut UProbe = bpf.program_mut(fn_name).unwrap().try_into()?;
    program.load()?;
    program.attach(Some("SSL_read"), 0, target, opt.pid.try_into()?)?;

    let fn_name = "uprobe_exit_openssl_read";
    let program: &mut UProbe = bpf.program_mut(fn_name).unwrap().try_into()?;
    program.load()?;
    program.attach(Some("SSL_read"), 0, target, opt.pid.try_into()?)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
