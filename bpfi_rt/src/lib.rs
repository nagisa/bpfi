#![no_main]
#![no_std]
#![feature(rust_preserve_none_cc)]

pub type Registers = [u64; 11];

pub type EntryFn = unsafe extern "C" fn(*const u8, &mut Registers, i64) -> BpfResult;
pub type StepFn = unsafe extern "rust-preserve-none" fn(*const u8, i64, Registers) -> BpfResult;

#[repr(transparent)]
pub struct BpfResult(pub i64);

impl BpfResult {
    pub const TIRED: Self = Self(-9);
    pub const ILLEGAL_INSN: Self = Self(-14);
}
