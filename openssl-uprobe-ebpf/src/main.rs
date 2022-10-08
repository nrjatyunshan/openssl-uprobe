#![no_std]
#![no_main]

use aya_bpf::{
    bpf_printk,
    helpers::bpf_get_current_pid_tgid,
    macros::{map, uprobe, uretprobe},
    maps::HashMap,
    programs::ProbeContext,
};

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct SSLCtx {
    pub ssl: *const u8,
    pub buf: *const u8,
    pub num: i32,
}

#[map]
static mut SSL_CTX_MAP: HashMap<u64, SSLCtx> = HashMap::with_max_entries(1024, 0);

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
    unsafe {
        match try_exit_openssl_write(ctx) {
            Ok(ret) => ret,
            Err(_) => 0,
        }
    }
}

#[uprobe(name = "uprobe_enter_openssl_read")]
pub fn uprobe_enter_openssl_read(ctx: ProbeContext) -> u32 {
    unsafe {
        match try_enter_openssl_read(ctx) {
            Ok(ret) => ret,
            Err(_) => 0,
        }
    }
}

#[uretprobe(name = "uprobe_exit_openssl_read")]
pub fn uprobe_exit_openssl_read(ctx: ProbeContext) -> u32 {
    unsafe {
        match try_exit_openssl_read(ctx) {
            Ok(ret) => ret,
            Err(_) => 0,
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// int SSL_write(SSL *ssl, const void *buf, int num);
unsafe fn try_enter_openssl_write(ctx: ProbeContext) -> Result<u32, u32> {
    let ssl: *const u8 = ctx.arg(0).ok_or(0u32)?;
    let buf: *const u8 = ctx.arg(1).ok_or(0u32)?;
    let num: i32 = ctx.arg(2).ok_or(0u32)?;

    let id = bpf_get_current_pid_tgid();
    let ssl_ctx = SSLCtx { ssl, buf, num };
    SSL_CTX_MAP.insert(&id, &ssl_ctx, 0).ok();
    Ok(0)
}

// int SSL_write(SSL *ssl, const void *buf, int num);
unsafe fn try_exit_openssl_write(ctx: ProbeContext) -> Result<u32, u32> {
    let id = bpf_get_current_pid_tgid();
    let retval: i32 = ctx.ret().ok_or(0u32)?;
    if let Some(ssl_ctx) = SSL_CTX_MAP.get(&id) {
        bpf_printk!(
            b"write: ssl=[%p], buf=[%p], num=[%d], retval=[%d]",
            ssl_ctx.ssl,
            ssl_ctx.buf,
            ssl_ctx.num,
            retval
        );
        bpf_printk!(b"%s", ssl_ctx.buf);
    }
    Ok(0)
}

// int SSL_read(SSL *ssl, void *buf, int num);
unsafe fn try_enter_openssl_read(ctx: ProbeContext) -> Result<u32, u32> {
    let ssl: *const u8 = ctx.arg(0).ok_or(0u32)?;
    let buf: *const u8 = ctx.arg(1).ok_or(0u32)?;
    let num: i32 = ctx.arg(2).ok_or(0u32)?;

    let id = bpf_get_current_pid_tgid();
    let ssl_ctx = SSLCtx { ssl, buf, num };
    SSL_CTX_MAP.insert(&id, &ssl_ctx, 0).ok();
    Ok(0)
}

// int SSL_read(SSL *ssl, void *buf, int num);
unsafe fn try_exit_openssl_read(ctx: ProbeContext) -> Result<u32, u32> {
    let id = bpf_get_current_pid_tgid();
    let retval: i32 = ctx.ret().ok_or(0u32)?;
    if let Some(ssl_ctx) = SSL_CTX_MAP.get(&id) {
        if retval > 0 {
            bpf_printk!(
                b"read: ssl=[%p], buf=[%p], num=[%d], retval=[%d]",
                ssl_ctx.ssl,
                ssl_ctx.buf,
                ssl_ctx.num,
                retval
            );
            bpf_printk!(b"%s", ssl_ctx.buf);
        }
    }
    SSL_CTX_MAP.remove(&id).ok();
    Ok(0)
}
