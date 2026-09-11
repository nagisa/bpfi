use crate::{template::Template, x64::ast::RegType};
pub use ast::x64_template;

pub mod ast;
mod generated;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Reg(pub u8);

#[allow(dead_code)]
impl Reg {
    pub const RAX: Self = Self(0);
    pub const RCX: Self = Self(1);
    pub const RDX: Self = Self(2);
    pub const RBX: Self = Self(3);
    pub const RSP: Self = Self(4);
    pub const RBP: Self = Self(5);
    pub const RSI: Self = Self(6);
    pub const RDI: Self = Self(7);
    pub const R8: Self = Self(8);
    pub const R9: Self = Self(9);
    pub const R10: Self = Self(10);
    pub const R11: Self = Self(11);
    pub const R12: Self = Self(12);
    pub const R13: Self = Self(13);
    pub const R14: Self = Self(14);
    pub const R15: Self = Self(15);

    // eBPF registers map to r0=RSI, r1 = RDI, r2 = R8... r9=R15, r10 = RBX
    pub const TMP: Self = Self::RAX;

    // Interpreter bytecode location is tracked in RCX.
    pub const BYTECODE: Self = Self::RCX;
    // CU budget is tracked in RDX, both across the interpreter and JIT.
    pub const BUDGET: Self = Self::RDX;
}

#[derive(Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
pub enum Flag {
    Overflow = 0x0, // JO / JNO
    NoOverflow = 0x1,
    Below = 0x2,        // JB / JC / JNAE
    AboveEqual = 0x3,   // JAE / JNC / JNB
    Equal = 0x4,        // JE / JZ
    NotEqual = 0x5,     // JNE / JNZ
    BelowEqual = 0x6,   // JBE / JNA
    Above = 0x7,        // JA / JNBE
    Sign = 0x8,         // JS
    NoSign = 0x9,       // JNS
    ParityEven = 0xA,   // JP / JPE
    ParityOdd = 0xB,    // JNP / JPO
    Less = 0xC,         // JL / JNGE
    GreaterEqual = 0xD, // JGE / JNL
    LessEqual = 0xE,    // JLE / JNG
    Greater = 0xF,      // JG / NLE
}

// #[derive(Copy, Clone)]
// #[repr(u8)]
// pub enum Size {
//     None,
//     Byte,
//     Word,
//     Long,
//     Quad,
//     /// 16 bytes
//     Octw,
// }
//
// impl Size {
//     pub const fn from_len(len: usize) -> Self {
//         match len {
//             1 => Self::Byte,
//             2 => Self::Word,
//             4 => Self::Long,
//             8 => Self::Quad,
//             16 => Self::Octw,
//             _ => panic!("byte count is not a valid instruction size"),
//         }
//     }
//
//     pub const fn is(self, other: Self) -> bool {
//         self as u8 == other as u8
//     }
//
//     pub const fn from_vds(len: usize) -> Self {
//         match len {
//             2 | 4 => Self::from_len(len),
//             _ => panic!("byte count is not 2 or 4 bytes"),
//         }
//     }
//
//     pub const fn from_vqp(len: usize) -> Self {
//         match len {
//             2 | 4 | 8 => Self::from_len(len),
//             _ => panic!("byte count is not 2, 4 or 8 bytes"),
//         }
//     }
//
//     pub const fn from_vs(len: usize) -> Self {
//         Self::from_vds(len)
//     }
//
//     pub const fn cmp(&self, other: &Self) -> i8 {
//         *self as u8 as i8 - *other as u8 as i8
//     }
// }

#[derive(Clone, Copy)]
pub enum AddressSize {
    A32,
    A64,
}

/// Prefixes that need to be emitted based on the operand sizes or values.
#[derive(Clone, Copy)]
pub struct OperandInfo {
    /// Any use of unified low byte operands in any of the operand forces the REX prefix.
    /// Using 64-bit operands sets REX.W = 1;
    /// Using registers in 8..16 range sets REX.R/X/B = 1.
    rex_byte: u8,

    /// Does the 0x66 operand size prefix need to be emitted?
    ///
    /// Usually means 16-bit register operand size.
    pub(crate) emit_operand_size_override_prefix: bool,
}

impl OperandInfo {
    // No reg or rm operands, just "other" stuff.
    pub const fn new(size_operand: ast::Operand, etc: &[ast::Operand]) -> Self {
        let sz = match size_operand {
            ast::Operand::Imm(imm) | ast::Operand::Rel(imm) => imm.len,
            ast::Operand::Reg(ast::Reg(RegType::B | RegType::H, _)) => 1,
            ast::Operand::Reg(ast::Reg(RegType::W, _)) => 2,
            ast::Operand::Reg(ast::Reg(RegType::D, _)) => 4,
            ast::Operand::Reg(ast::Reg(RegType::Q, _)) => 8,
            ast::Operand::Mem(ast::MemSize::Qword, _) => 8,
            ast::Operand::Mem(ast::MemSize::Dword, _) => 4,
            ast::Operand::Mem(ast::MemSize::Word, _) => 2,
            ast::Operand::Mem(ast::MemSize::Byte, _) => 1,
            ast::Operand::Mem(ast::MemSize::None, _) => {
                panic!(
                    "the memory operand that informs operand size must explicitily annotate the operand size"
                )
            }
        };
        let emit_operand_size_override_prefix = matches!(sz, 2);
        let rex_w = matches!(sz, 8);
        let uses_unified_byte_registers = Self::uses_unified_byte_registers(&[size_operand])
            || Self::uses_unified_byte_registers(etc);
        let rex = if rex_w || uses_unified_byte_registers {
            0x40 | (rex_w as u8) << 3
        } else {
            0
        };
        Self {
            rex_byte: rex,
            emit_operand_size_override_prefix,
        }
    }

    const fn uses_unified_byte_registers(ops: &[ast::Operand]) -> bool {
        let mut i = 0;
        while i < ops.len() {
            if let ast::Operand::Reg(ast::Reg(ast::RegType::B, 4..8)) = ops[i] {
                return true;
            }
            i += 1;
        }
        false
    }

    pub const fn unsz(ops: &[ast::Operand]) -> Self {
        let uses_unified_byte_registers = Self::uses_unified_byte_registers(ops);

        let rex = if uses_unified_byte_registers { 0x40 } else { 0 };
        Self {
            rex_byte: rex,
            emit_operand_size_override_prefix: false,
        }
    }
}

const fn opguard_szop(
    size_operand: ast::Operand,
    size_op_mask: u8,
    etc: &[ast::Operand],
    etc_masks: &[u8],
) -> bool {
    let mut i = 0;
    let mut uses_high_byte_reg = false;
    let mut uses_unified_byte_reg = false;
    let opsize: u8 = match size_operand {
        ast::Operand::Reg(ast::Reg(RegType::H, _)) => {
            uses_high_byte_reg = true;
            1
        }
        ast::Operand::Reg(ast::Reg(RegType::B, regnum)) => {
            uses_unified_byte_reg |= matches!(regnum, 4..8);
            1
        }
        ast::Operand::Reg(ast::Reg(RegType::W, _)) => 2,
        ast::Operand::Reg(ast::Reg(RegType::D, _)) => 4,
        ast::Operand::Reg(ast::Reg(RegType::Q, _)) => 8,
        ast::Operand::Mem(ast::MemSize::Byte, _) => 1,
        ast::Operand::Mem(ast::MemSize::Word, _) => 2,
        ast::Operand::Mem(ast::MemSize::Dword, _) => 4,
        ast::Operand::Mem(ast::MemSize::Qword, _) => 8,
        ast::Operand::Mem(ast::MemSize::None, _) => return false,
        ast::Operand::Imm(imm) | ast::Operand::Rel(imm) if imm.len < 256 => imm.len as u8,
        ast::Operand::Imm(_) | ast::Operand::Rel(_) => return false,
    };
    if opsize & size_op_mask == 0 {
        return false;
    }
    while i < etc.len() {
        // if mask sets just one bit, its a static operand that does not depend on the operand-size
        if etc_masks[i].count_ones() != 1 {
            let this_opsize = match etc[i] {
                ast::Operand::Reg(ast::Reg(RegType::H, _)) => {
                    uses_high_byte_reg = true;
                    1
                }
                ast::Operand::Reg(ast::Reg(RegType::B, regnum)) => {
                    uses_unified_byte_reg |= matches!(regnum, 4..8);
                    1
                }
                ast::Operand::Reg(ast::Reg(RegType::W, _)) => 2,
                ast::Operand::Reg(ast::Reg(RegType::D, _)) => 4,
                ast::Operand::Reg(ast::Reg(RegType::Q, _)) => 8,
                ast::Operand::Mem(ast::MemSize::Byte, _) => 1,
                ast::Operand::Mem(ast::MemSize::Word, _) => 2,
                ast::Operand::Mem(ast::MemSize::Dword, _) => 4,
                ast::Operand::Mem(ast::MemSize::Qword, _) => 8,
                ast::Operand::Mem(ast::MemSize::None, _) => return false,
                ast::Operand::Imm(imm) | ast::Operand::Rel(imm) if imm.len < 256 => imm.len as u8,
                ast::Operand::Imm(_) | ast::Operand::Rel(_) => return false,
            };
            if this_opsize != opsize {
                return false;
            }
        }
        i += 1;
    }
    if uses_unified_byte_reg && uses_high_byte_reg {
        return false;
    }
    return true;
}

const fn opguard(ops: &[ast::Operand], size_masks: &[u8]) -> bool {
    let mut i = 0;
    let mut uses_high_byte_reg = false;
    let mut uses_unified_byte_reg = false;
    while i < size_masks.len() {
        match ops[i] {
            ast::Operand::Imm(imm) | ast::Operand::Rel(imm)
                if imm.len < 256 && imm.len as u8 & size_masks[i] != 0 => {}
            ast::Operand::Imm(_) | ast::Operand::Rel(_) => return false,
            ast::Operand::Reg(ast::Reg(ast::RegType::H, _)) => uses_high_byte_reg = true,
            ast::Operand::Reg(ast::Reg(ast::RegType::B, 4..8)) => uses_unified_byte_reg = true,
            _ => {}
        };
        i += 1;
    }
    if uses_unified_byte_reg && uses_high_byte_reg {
        return false;
    }
    return true;
}

#[derive(Clone, Copy)]
pub struct EncodingMem {
    pub(crate) addressing_size: AddressSize,
    pub(crate) base: Option<Reg>,
    pub(crate) index: Option<(Reg, u8)>,
    pub(crate) disp: Template,
}

#[derive(Clone, Copy)]
pub enum EncodingRm {
    None,
    Reg(Reg),
    Mem(EncodingMem),
}

#[derive(Clone, Copy)]
pub struct Encoding {
    /// Prefix that always precedes instruction (including its RAX.W modifier, hence it being a
    /// separate field.) Example: crc32.
    pub(crate) pref: &'static [u8],
    pub(crate) op: &'static [u8],
    pub(crate) opi: OperandInfo,
    pub(crate) reg: Option<Reg>,
    pub(crate) rm: EncodingRm,
    pub(crate) ext: Option<u8>,
    pub(crate) tail: Option<Template>,
}

impl Encoding {
    pub const fn encode(self) -> Template {
        let mut prefixes = Template::from_slice(self.pref);
        if self.opi.emit_operand_size_override_prefix {
            prefixes = Template::bytes([0x66]).merge(&prefixes);
        }
        if let EncodingRm::Mem(EncodingMem {
            addressing_size: AddressSize::A32,
            ..
        }) = self.rm
        {
            prefixes = Template::bytes([0x67]).merge(&prefixes);
        }

        let rex_r = matches!(self.reg, Some(Reg(8..16)));
        let mut rex_x = false;
        let mut rex_b = false;
        match self.rm {
            EncodingRm::Reg(r) => rex_b = matches!(r, Reg(8..16)),
            EncodingRm::Mem(m) => {
                rex_b = matches!(m.base, Some(Reg(8..16)));
                rex_x = matches!(m.index, Some((Reg(8..16), _)));
            }
            EncodingRm::None if self.ext.is_none() => rex_b = matches!(self.reg, Some(Reg(8..16))),
            EncodingRm::None => {}
        }
        // rex (for low byte register access) or rex.w are set in `OperandInfo`.
        let rex = self.opi.rex_byte | ((rex_r as u8) << 2) | ((rex_x as u8) << 1) | (rex_b as u8);
        let rex = if rex != 0 {
            Template::bytes([0x40 | rex])
        } else {
            Template::EMPTY
        };

        let mut opcode = Template::EMPTY;
        let mut i = 0;
        while i < self.op.len() {
            opcode.bytes[i] = self.op[i];
            i += 1;
        }
        opcode.len = self.op.len();
        if let (EncodingRm::None, None, Some(reg)) = (self.rm, self.ext, self.reg) {
            opcode.bytes[opcode.len - 1] += reg.0 & 7;
        }

        let reg_bits = match (self.reg, self.ext) {
            (Some(reg), _) => reg.0 & 7,
            (_, Some(ext)) => ext,
            (_, _) => 0,
        };
        let modrm = match self.rm {
            EncodingRm::Reg(r) => {
                let modrm_byte = (0b11 << 6) | (reg_bits << 3) | (r.0 & 7);
                Template::bytes([modrm_byte])
            }
            EncodingRm::Mem(m) => {
                const SIB_MODE: u8 = 0b100;
                const NO_BASE: u8 = 0b101;
                let modbits = match m.disp.len {
                    0 if matches!(m.base, Some(Reg::RBP | Reg::R13)) => {
                        panic!("[rbp]/[r13] addressing requires displacement")
                    }
                    0 => 0b00,
                    1 => 0b01,
                    4 => 0b10,
                    _ => panic!("mem displacement must be 0, 1 or 4 bytes"),
                };

                match (m.base, m.index) {
                    (None, None) if m.disp.len == 4 => {
                        let modrm = (0b00 << 6) | 0b100 | NO_BASE;
                        Template::bytes([modrm]).merge(&m.disp)
                    }
                    (Some(Reg::RSP | Reg::R12), None) => {
                        // base = RSP/R12 require SIB byte
                        let sib = 0 << 6 | SIB_MODE << 3 | SIB_MODE;
                        let modrm = modbits << 6 | reg_bits << 3 | SIB_MODE;
                        Template::bytes([modrm, sib]).merge(&m.disp)
                    }
                    (Some(base), None) => {
                        let modrm = (modbits << 6) | (reg_bits << 3) | base.0 & 7;
                        Template::bytes([modrm]).merge(&m.disp)
                    }
                    (None, Some((index, scale))) => {
                        let sib_byte = scale << 6 | (index.0 & 7) << 3 | NO_BASE;
                        let modrm = 0b00 << 6 | reg_bits << 3 | SIB_MODE;
                        Template::bytes([modrm, sib_byte]).merge(&m.disp)
                    }
                    (Some(base), Some((index, scale))) => {
                        let sib = scale << 6 | (index.0 & 7) << 3 | base.0 & 7;
                        let modrm = modbits << 6 | reg_bits << 3 | SIB_MODE;
                        Template::bytes([modrm, sib]).merge(&m.disp)
                    }
                    _ => panic!("invalid mem operand"),
                }
            }
            EncodingRm::None if self.ext.is_some() => {
                Template::bytes([(0b11 << 6) | (reg_bits << 3)])
            }
            EncodingRm::None => Template::EMPTY,
        };

        if let Some(tail) = self.tail {
            Template::merged([prefixes, rex, opcode, modrm, tail])
        } else {
            Template::merged([prefixes, rex, opcode, modrm])
        }
    }
}
