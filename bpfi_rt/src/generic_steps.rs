use crate::{Registers, StepReturn};

#[inline(always)]
pub(crate) unsafe extern "rust-preserve-none" fn step_add64_imm<const DST: usize>(
    insn: *const u8,
    registers: &mut Registers,
    budget: i64,
) -> StepReturn {
    let next_insn = insn.add(8);
    let imm = u32::from_le_bytes([*insn.add(4), *insn.add(5), *insn.add(6), *insn.add(7)]);
    registers[DST] = registers[DST].wrapping_add(u64::from(imm));
    become crate::step_head(next_insn, registers, budget);
}

#[inline(always)]
pub(crate) unsafe extern "rust-preserve-none" fn step_and64_imm<const DST: usize>(
    insn: *const u8,
    registers: &mut Registers,
    budget: i64,
) -> StepReturn {
    let next_insn = insn.add(8);
    let imm = u32::from_le_bytes([*insn.add(4), *insn.add(5), *insn.add(6), *insn.add(7)]);
    registers[DST] = registers[DST] & u64::from(imm);
    become crate::step_head(next_insn, registers, budget);
}

#[inline(always)]
pub(crate) unsafe extern "rust-preserve-none" fn step_exit(
    _: *const u8,
    _: &mut Registers,
    budget: i64,
) -> StepReturn {
    return Ok(budget);
}

#[inline(always)]
pub unsafe extern "rust-preserve-none" fn step_jlt64_imm<const DST: usize>(
    insn: *const u8,
    registers: &mut Registers,
    budget: i64,
) -> StepReturn {
    let imm = u32::from_le_bytes([*insn.add(4), *insn.add(5), *insn.add(6), *insn.add(7)]);
    let next_insn = if registers[DST] < imm as u64 {
        let off = i16::from_le_bytes([*insn.add(2), *insn.add(3)]);
        insn.offset(8 * off as isize).add(8)
    } else {
        insn.add(8)
    };
    become crate::step_head(next_insn, registers, budget);
}


#[inline(always)]
pub(crate) unsafe extern "rust-preserve-none" fn step_mov64_reg<const DST: usize, const SRC: usize>(
    insn: *const u8,
    registers: &mut Registers,
    budget: i64,
) -> StepReturn {
    let next_insn = insn.add(8);
    registers[DST] = registers[SRC];
    become crate::step_head(next_insn, registers, budget);
}

#[inline(always)]
pub unsafe extern "rust-preserve-none" fn invalid_opcode(
    _: *const u8,
    _: &mut Registers,
    _: i64,
) -> Result<u64, ()> {
    return Err(());
}

