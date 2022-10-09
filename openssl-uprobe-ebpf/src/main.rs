#![no_std]
#![no_main]

use aya_bpf::{
    bpf_printk,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read},
    macros::{map, uprobe, uretprobe},
    maps::HashMap,
    programs::ProbeContext,
};

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct SSLCtx {
    pub ssl: usize,
    pub buf: usize,
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
    let ssl: usize = ctx.arg(0).ok_or(0u32)?;
    let buf: usize = ctx.arg(1).ok_or(0u32)?;
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
        let rbio = bpf_probe_read((ssl_ctx.ssl + 0x10) as *const usize).unwrap();
        let fd = bpf_probe_read((rbio + 0x30) as *const i32).unwrap();
        bpf_printk!(
            b"write: ssl=[%p], buf=[%p], num=[%d], retval=[%d], fd=[%d]",
            ssl_ctx.ssl,
            ssl_ctx.buf,
            ssl_ctx.num,
            retval,
            fd
        );
    }
    Ok(0)
}

// int SSL_read(SSL *ssl, void *buf, int num);
unsafe fn try_enter_openssl_read(ctx: ProbeContext) -> Result<u32, u32> {
    let ssl: usize = ctx.arg(0).ok_or(0u32)?;
    let buf: usize = ctx.arg(1).ok_or(0u32)?;
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
            let rbio = bpf_probe_read((ssl_ctx.ssl + 0x10) as *const usize).unwrap();
            let fd = bpf_probe_read((rbio + 0x30) as *const i32).unwrap();
            bpf_printk!(
                b"read: ssl=[%p], buf=[%p], num=[%d], retval=[%d], fd=[%d]",
                ssl_ctx.ssl,
                ssl_ctx.buf,
                ssl_ctx.num,
                retval,
                fd
            );
        }
    }
    SSL_CTX_MAP.remove(&id).ok();
    Ok(0)
}
