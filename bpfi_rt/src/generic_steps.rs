use crate::{BpfResult, Registers};
use core::arch::asm;

#[inline(always)]
fn get<const REG: usize>(r0: u64, r1: u64, r2: u64, regs: Registers) -> u64 {
    let ret: u64;
    unsafe {
        match REG {
            0 => asm!("movq {}, xmm0", out(reg) ret, options(nomem, preserves_flags)),
            1 => asm!("movq {}, xmm1", out(reg) ret, options(nomem, preserves_flags)),
            2 => asm!("movq {}, xmm2", out(reg) ret, options(nomem, preserves_flags)),
            3 => asm!("movq {}, xmm3", out(reg) ret, options(nomem, preserves_flags)),
            4 => asm!("movq {}, xmm4", out(reg) ret, options(nomem, preserves_flags)),
            5 => asm!("movq {}, xmm5", out(reg) ret, options(nomem, preserves_flags)),
            6 => asm!("movq {}, xmm6", out(reg) ret, options(nomem, preserves_flags)),
            7 => asm!("movq {}, xmm7", out(reg) ret, options(nomem, preserves_flags)),
            8 => asm!("movq {}, xmm8", out(reg) ret, options(nomem, preserves_flags)),
            9 => asm!("movq {}, xmm9", out(reg) ret, options(nomem, preserves_flags)),
            10 => asm!("movq {}, xmm10", out(reg) ret, options(nomem, preserves_flags)),
            _ => loop {},
        }
    }
    ret
}

#[inline(always)]
fn set<const REG: usize>(value: u64) {
    unsafe {
        match REG {
            0 => asm!("movq xmm0, {}", in(reg) value, options(nomem, preserves_flags)),
            1 => asm!("movq xmm1, {}", in(reg) value, options(nomem, preserves_flags)),
            2 => asm!("movq xmm2, {}", in(reg) value, options(nomem, preserves_flags)),
            3 => asm!("movq xmm3, {}", in(reg) value, options(nomem, preserves_flags)),
            4 => asm!("movq xmm4, {}", in(reg) value, options(nomem, preserves_flags)),
            5 => asm!("movq xmm5, {}", in(reg) value, options(nomem, preserves_flags)),
            6 => asm!("movq xmm6, {}", in(reg) value, options(nomem, preserves_flags)),
            7 => asm!("movq xmm7, {}", in(reg) value, options(nomem, preserves_flags)),
            8 => asm!("movq xmm8, {}", in(reg) value, options(nomem, preserves_flags)),
            9 => asm!("movq xmm9, {}", in(reg) value, options(nomem, preserves_flags)),
            10 => asm!("movq xmm10, {}", in(reg) value, options(nomem, preserves_flags)),
            _ => loop {},
        }
    }
}

#[inline(always)]
pub(crate) unsafe extern "rust-preserve-none" fn step_add64_imm<const DST: usize>(
    insn: *const u8,
    budget: i64,
    mut registers: Registers,
) -> BpfResult {
    let next_insn = insn.add(8);
    let imm = u32::from_le_bytes([*insn.add(4), *insn.add(5), *insn.add(6), *insn.add(7)]);
    registers[DST] = registers[DST].wrapping_add(imm as u64);
    asm!("jmp {}", sym crate::step_head, in("r12") next_insn, in("r13") budget, in("r14") &raw mut registers, options(nostack, noreturn));
}

#[inline(always)]
pub(crate) unsafe extern "rust-preserve-none" fn step_and64_imm<const DST: usize>(
    insn: *const u8,
    budget: i64,
    mut registers: Registers,
) -> BpfResult {
    let next_insn = insn.add(8);
    let imm = u32::from_le_bytes([*insn.add(4), *insn.add(5), *insn.add(6), *insn.add(7)]);
    registers[DST] = registers[DST] & (imm as u64);
    become crate::step_head(next_insn, budget, registers);
}

#[inline(always)]
pub(crate) unsafe extern "rust-preserve-none" fn step_exit(
    _: *const u8,
    budget: i64,
    mut registers: Registers,
) -> BpfResult {
    return BpfResult(budget);
}

#[inline(always)]
pub unsafe extern "rust-preserve-none" fn step_jlt64_imm<const DST: usize>(
    insn: *const u8,
    budget: i64,
    mut registers: Registers,
) -> BpfResult {
    let imm = u32::from_le_bytes([*insn.add(4), *insn.add(5), *insn.add(6), *insn.add(7)]);
    let next_insn = if registers[DST] < imm as u64 {
        let off = i16::from_le_bytes([*insn.add(2), *insn.add(3)]);
        insn.offset(8 * off as isize).add(8)
    } else {
        insn.add(8)
    };
    become crate::step_head(next_insn, budget, registers);
}

#[inline(always)]
pub(crate) unsafe extern "rust-preserve-none" fn step_mov64_reg<
    const DST: usize,
    const SRC: usize,
>(
    insn: *const u8,
    budget: i64,
    mut registers: Registers,
) -> BpfResult {
    let next_insn = insn.add(8);
    registers[DST] = registers[SRC];
    become crate::step_head(next_insn, budget, registers);
}

#[inline(always)]
pub unsafe extern "rust-preserve-none" fn invalid_opcode(_: *const u8, _: i64) -> Result<u64, ()> {
    return Err(());
}
