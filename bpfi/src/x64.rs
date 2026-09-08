use crate::template::Template;
pub use ast::x64_template;

pub mod ast;
mod generated;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Gpr(pub u8);

#[allow(dead_code)]
impl Gpr {
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

#[derive(Copy, Clone)]
#[repr(u8)]
pub enum Size {
    None,
    Byte,
    Word,
    Long,
    Quad,
    /// 16 bytes
    Octw,
}

impl Size {
    pub const fn from_len(len: usize) -> Self {
        match len {
            1 => Self::Byte,
            2 => Self::Word,
            4 => Self::Long,
            8 => Self::Quad,
            16 => Self::Octw,
            _ => panic!("byte count is not a valid instruction size"),
        }
    }

    pub const fn is(self, other: Self) -> bool {
        self as u8 == other as u8
    }

    pub const fn from_vds(len: usize) -> Self {
        match len {
            2 | 4 => Self::from_len(len),
            _ => panic!("byte count is not 2 or 4 bytes"),
        }
    }

    pub const fn from_vqp(len: usize) -> Self {
        match len {
            2 | 4 | 8 => Self::from_len(len),
            _ => panic!("byte count is not 2, 4 or 8 bytes"),
        }
    }

    pub const fn from_vs(len: usize) -> Self {
        Self::from_vds(len)
    }

    pub const fn cmp(&self, other: &Self) -> i8 {
        *self as u8 as i8 - *other as u8 as i8
    }
}

#[derive(Clone, Copy)]
pub struct EncodingMem {
    pub(crate) base: Option<Gpr>,
    pub(crate) index: Option<(Gpr, u8)>,
    pub(crate) disp: Template,
}

#[derive(Clone, Copy)]
pub enum EncodingRm {
    None,
    Gpr(Gpr),
    Mem(EncodingMem),
}

#[derive(Clone, Copy)]
pub struct Encoding {
    /// Prefix that always precedes instruction (including its RAX.W modifier, hence it being a
    /// separate field.) Example: crc32.
    pub(crate) pref: &'static [u8],
    pub(crate) op: &'static [u8],
    /// Size of the register operand.
    pub(crate) sz: Size,
    /// Force REX.W prefix even if not Size::Quad
    pub(crate) rex_w: bool,
    pub(crate) reg: Option<Gpr>,
    pub(crate) rm: EncodingRm,
    pub(crate) ext: Option<u8>,
    pub(crate) tail: Option<Template>,
}

impl Encoding {
    pub const fn encode(self) -> Template {
        let mut prefixes = Template::from_slice(self.pref);
        if let Size::Word = self.sz {
            prefixes = Template::bytes([0x66]).merge(&prefixes);
        }

        let rex_w = matches!(self.sz, Size::Quad) || self.rex_w;
        let rex_r = matches!(self.reg, Some(Gpr(8..16)));
        let mut rex_x = false;
        let mut rex_b = false;
        // FIXME: ah~bh and r4b~r7b share same register number and the low byte variant is selected
        // by… slapping a rex before the instruction.
        // This seems like a wrong layer to figure these things out. And besides we don't even
        // support high registers...
        // Right now this code doesn't work right anyway because the generator does not populate
        // the `sz` field right for some of the relevant instructions.
        let mut gotta_rex_for_byte_regs = false;
        match self.rm {
            EncodingRm::Gpr(r) => {
                gotta_rex_for_byte_regs |= matches!((self.sz, r), (Size::Byte, Gpr(4..8)));
                rex_b = matches!(r, Gpr(8..16))
            }
            EncodingRm::Mem(m) => {
                gotta_rex_for_byte_regs |= matches!((self.sz, m.base), (Size::Byte, Some(Gpr(4..8))));
                gotta_rex_for_byte_regs |= matches!((self.sz, m.index), (Size::Byte, Some((Gpr(4..8), _))));
                rex_b = matches!(m.base, Some(Gpr(8..16)));
                rex_x = matches!(m.index, Some((Gpr(8..16), _)));
            }
            EncodingRm::None if self.ext.is_none() => rex_b = matches!(self.reg, Some(Gpr(8..16))),
            EncodingRm::None => {}
        }
        let rex_w = if rex_w || rex_r || rex_x || rex_b || gotta_rex_for_byte_regs {
            let rex = 0x40
                | ((rex_w as u8) << 3)
                | ((rex_r as u8) << 2)
                | ((rex_x as u8) << 1)
                | (rex_b as u8);
            Template::bytes([rex])
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
            EncodingRm::Gpr(r) => {
                let modrm_byte = (0b11 << 6) | (reg_bits << 3) | (r.0 & 7);
                Template::bytes([modrm_byte])
            }
            EncodingRm::Mem(m) => {
                const SIB_MODE: u8 = 0b100;
                const NO_BASE: u8 = 0b101;
                let modbits = match m.disp.len {
                    0 if matches!(m.base, Some(Gpr::RBP | Gpr::R13)) => {
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
                    (Some(Gpr::RSP | Gpr::R12), None) => {
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
            Template::merged([prefixes, rex_w, opcode, modrm, tail])
        } else {
            Template::merged([prefixes, rex_w, opcode, modrm])
        }
    }
}
