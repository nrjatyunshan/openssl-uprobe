#![no_std]
#![no_main]

use aya_bpf::{
    helpers::bpf_probe_read_user_str_bytes, macros::uprobe, macros::uretprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[uprobe(name = "uprobe_enter_openssl_write")]
pub fn uprobe_enter_openssl_write(ctx: ProbeContext) -> u32 {
    unsafe {
        match try_enter_openssl_write(ctx) {
            Ok(ret) => ret,
            Err(_) => 0,
        }
    }
}

#[uretprobe(name = "uprobe_exit_openssl_write")]
pub fn uprobe_exit_openssl_write(ctx: ProbeContext) -> u32 {
    info!(&ctx, "uprobe_exit_openssl_write");
    return 0;
}

#[uprobe(name = "uprobe_enter_openssl_read")]
pub fn uprobe_enter_openssl_read(ctx: ProbeContext) -> u32 {
    info!(&ctx, "uprobe_enter_openssl_read");
    return 0;
}

#[uretprobe(name = "uprobe_exit_openssl_read")]
pub fn uprobe_exit_openssl_read(ctx: ProbeContext) -> u32 {
    info!(&ctx, "uprobe_exit_openssl_read");
    return 0;
}

unsafe fn try_enter_openssl_write(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "uprobe_enter_openssl_write");

    let buf_ptr: *const u8 = ctx.arg(1).ok_or(0u32)?;
    let mut buf = [0u8, 32];

    let my_str = core::str::from_utf8_unchecked(bpf_probe_read_user_str_bytes(buf_ptr, &mut buf)?);

    info!(&ctx, "buffer {}", my_str);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
