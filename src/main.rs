#![no_std]
#![no_main]

use core::panic::PanicInfo;

use corinth::command::{CommandError, CommandResult, execute, parse_argv};
use corinth::pkg::PackageLedger;

#[global_allocator]
static HEAP: slope::memory::GlobalSlabHeap = slope::memory::GlobalSlabHeap::new();

core::arch::global_asm!(
    ".section .text._start,\"ax\"",
    ".global _start",
    ".type _start,@function",
    "_start:",
    "mov %rsp, %rdi",
    "jmp corinth_start_with_stack",
    ".size _start, .-_start",
    options(att_syntax)
);

#[unsafe(no_mangle)]
pub extern "C" fn corinth_start_with_stack(stack_ptr: *const u8) -> ! {
    HEAP.init();
    // SAFETY: Arach supplies the documented `[argc][argv][envp]` entry ABI.
    let argv = unsafe { slope::env::QuantumArgv::from_stack(stack_ptr) };
    let result = parse_argv(&argv).and_then(|command| {
        let mut ledger = PackageLedger::new();
        execute(command, &mut ledger)
    });
    match result {
        Ok(CommandResult::Search { known: true }) => {
            finish(b"corinth: package found in measured build catalog\n", 0)
        }
        Ok(CommandResult::Search { known: false }) => finish(b"corinth: package not found\n", 1),
        Ok(CommandResult::Staged(_)) => finish(
            b"corinth: transaction staged; durable artifact store is unavailable\n",
            69,
        ),
        Err(CommandError::PackageUnavailable) => finish(
            b"corinth: package is not rooted in the measured build catalog\n",
            69,
        ),
        Err(CommandError::Package(_)) => finish(b"corinth: package transaction rejected\n", 65),
        Err(_) => finish(
            b"usage: corinth <install|remove|update|search> <package>\n",
            64,
        ),
    }
}

fn finish(message: &[u8], status: i32) -> ! {
    let _ = slope::io::write(1, message);
    let _ = slope::process::request_exit(status);
    loop {
        let _ = slope::process::yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    finish(b"corinth: unrecoverable package-service panic\n", 70)
}
