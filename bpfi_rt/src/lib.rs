#![no_main]
#![no_std]

pub type Registers = [u64; 16];

pub type StepReturn = Result<i64, ()>;

pub type EntryFn = unsafe extern "C" fn(*const u8, &mut Registers, i64) -> StepReturn;
