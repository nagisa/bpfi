//! The implementation of the interpreter core loop.
//!
//! Due to the strong dependency on nightly features and special compilation requirements, this
//! crate is separated out from the rest of the interpreter implementation.
#![feature(rust_preserve_none_cc)]
#![feature(explicit_tail_calls)]
#![allow(unsafe_op_in_unsafe_fn)]
#![no_main]
#![no_std]

pub use bpfi_rt::{Registers, StepReturn};

mod generic_steps;

/// The cadence of the step handlers in the linker script. These steps don't *have* to be at most
/// this many bytes, provided, for example, as long as there are no collisions with the next step.
const STEP_HANDLER_SIZE: usize = 64;


type StepFn = unsafe extern "rust-preserve-none" fn(*const u8, &mut Registers, i64) -> StepReturn;

#[unsafe(export_name = "bpfi_rt_enter")]
#[unsafe(link_section = ".rt.enter")]
pub unsafe extern "C" fn enter(
    insn: *const u8,
    registers: &mut Registers,
    budget: i64,
) -> StepReturn {
    step_head(insn, registers, budget)
}

#[unsafe(link_section = ".rt.sigbudget")]
#[unsafe(no_mangle)]
#[cold]
pub unsafe extern "rust-preserve-none" fn sig_max_instructions(
    _: *const u8,
    _: &mut Registers,
    _: i64,
) -> StepReturn {
    return Err(());
}

#[unsafe(link_section = ".rt.head")]
#[inline(always)]
unsafe extern "rust-preserve-none" fn step_head(
    insn: *const u8,
    registers: &mut Registers,
    mut budget: i64,
) -> StepReturn {
    budget = budget.wrapping_sub(1);
    if budget.wrapping_sub(1) < 0 {
        become sig_max_instructions(insn, registers, budget);
    }
    // TODO: check bounds.
    let next_opcode_handler = step(core::ptr::read_unaligned(insn.cast::<u16>()));
    become next_opcode_handler(insn, registers, budget.wrapping_sub(1));
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(export_name = ".ibase")]
pub static INTERPRETER_LOAD_BASE: u8 = 0;

#[inline(always)]
fn step(opcode_dst_src: u16) -> StepFn {
    let section_base = &raw const INTERPRETER_LOAD_BASE;
    let step_function_ptr = unsafe {
        // SAFETY: Contracts from `add` are satisfied by definition of opcode being u8 and
        // `STEP_HANDLER_SIZE` being small.
        section_base.add(usize::from(opcode_dst_src) * STEP_HANDLER_SIZE)
    };
    unsafe {
        // SAFETY: we're typing a pointer to a function as a function pointer.
        core::mem::transmute(step_function_ptr)
    }
}

fn unsupported_insn(opcode: u8) -> Result<u64, ()> {
    loop {}
}

mod monosteps {
    include!(concat!(env!("OUT_DIR"), "/monosteps.rs"));
}
