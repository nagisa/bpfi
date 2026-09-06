use crate::template::{PlaceholderType, Template};

mod mnemonic;
mod ast;
mod mem;
pub(crate) use mnemonic::{Mnemonic, x64_mnemonic};
pub(crate) use ast::x64_template;
use mem::Mem;

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
pub enum Size {
    None,
    Byte,
    Word,
    Long,
    Quad,
}

//
// /// A conditional jump, with opcode selected based on offset size.
// ///
// /// Only 1 byte or 4 byte offsets are supported architecturally.
// /// Don't go looking for other sorts of conditional jumps, they don't exist.
// pub const fn jcc(cond: Flag, off: Template) -> Template {
//     let op = match off.len {
//         1 => Template::bytes([0x70 | (cond as u8)]),
//         4 => Template::bytes([0x0F, 0x80 | (cond as u8)]),
//         _ => panic!("x86-64 Jcc offset must be 1 byte (short) or 4 bytes (near)"),
//     };
//     Template::merged([op, off])
// }
//
// /// 64-bit REX.W prefix.
// ///
// /// `r` is the register field (usually dst), `rm` is the r/m field (usually src or base.)
// pub(crate) const fn rex_w(r: Gpr, rm: Gpr) -> Template {
//     Template::bytes([0x48 | (r.0 >> 3) << 2 | rm.0 >> 3])
// }
//
// /// 64-bit REX.W prefix including REX.R, REX.X, and REX.B bits for SIB addressing.
// pub const fn rex_w_sib(reg: Gpr, base: Gpr, index: Gpr) -> Template {
//     let r = (reg.0 >> 3) & 1;
//     let x = (index.0 >> 3) & 1;
//     let b = (base.0 >> 3) & 1;
//     Template::bytes([0x48 | (r << 2) | (x << 1) | b])
// }
//
// pub const fn rex_w_sib_for_mem(reg: Gpr, mem: Mem) -> Template {
//     let (base, index) = match (mem.base, mem.index) {
//         (Some(b), Some((i, _))) => (b, i),
//         (Some(b), None) => (b, Gpr::RAX),
//         (None, Some((i, _))) => (Gpr::RAX, i),
//         (None, None) => (Gpr::RAX, Gpr::RAX),
//     };
//     rex_w_sib(reg, base, index)
// }
//
// pub const fn rex_b(b: Gpr) -> Template {
//     Template::bytes([0x40 | (b.0 >> 3)])
// }
//
// /// ModR/M byte for Register-to-Register operations (Mod = 11)
// pub(crate) const fn modrm_reg(r: Gpr, rm: Gpr) -> Template {
//     Template::bytes([0xC0 | (r.0 & 7) << 3 | rm.0 & 7])
// }
//
// pub(crate) const fn add_rq_id(dst: Gpr, imm: Template) -> Template {
//     let prefix = rex_w(Gpr(0), dst);
//     let opcode = if let Gpr::RAX = dst {
//         Template::bytes([0x05])
//     } else {
//         Template::bytes([0x81]).merge(&modrm_reg(Gpr(0), dst))
//     };
//     Template::merged([prefix, opcode, imm.assert_len(4)])
// }
//
// // `MOV r, imm`: Move the immediate value into register.
// //
// // Zeroes the upper bits of the register.
// pub(crate) const fn mov_reg_imm(dst: Gpr, imm: Template) -> Template {
//     let opcode = Template::bytes([0xB8 | dst.0 & 7]);
//     match imm.len {
//         // 32-bit immediate: MOV r32, imm32
//         4 if dst.0 >= 8 => Template::merged([rex_b(dst), opcode, imm]),
//         4 => Template::merged([opcode, imm]),
//         // 64-bit immediate: MOV r64, imm64
//         8 => Template::merged([rex_w(Gpr(0), dst), opcode, imm]),
//         // Moves from imm8 or imm16 could be implemented by using an additional
//         // instruction. Which makes no sense, so just extend your immediate to 4 bytes.
//         _ => panic!("MOV reg, imm immediate length must be 4, or 8 bytes"),
//     }
// }
//
// /// `MOV r, r`
// pub(crate) const fn mov_reg_reg(dst: Gpr, src: Gpr) -> Template {
//     Template::merged([
//         rex_w(src, dst),
//         Template::bytes([0x89]),
//         modrm_reg(src, dst),
//     ])
// }
//
// /// `MOV r, mem` (load from memory)
// pub(crate) const fn mov_reg_mem(bitsize: u8, dst: Gpr, src: Mem) -> Template {
//     Template::merged([
//         rex_w_sib_for_mem(dst, src),
//         Template::bytes([0x8B]),
//         src.encode(dst),
//     ])
// }
//
// /// `MOV mem, r` (store to memory)
// pub(crate) const fn mov_mem_reg(bitsize: u8, dst: Gpr, src: Mem) -> Template {
//     if bitsize == 64 {
//     }
//     Template::merged([
//         rex_w_sib_for_mem(dst, src),
//         Template::bytes([0x89]),
//         src.encode(dst),
//     ])
// }
//
// const IMM32: Template = Template::placeholder(PlaceholderType::Imm, 4);
// const RET: Template = Template::bytes([0xC3]);
//
// pub(crate) const fn gpr_for_bpf(reg: u8) -> Gpr {
//     match reg {
//         0 => Gpr::RSI,
//         1 => Gpr::RDI,
//         2 => Gpr::R8,
//         3 => Gpr::R9,
//         4 => Gpr::R10,
//         5 => Gpr::R11,
//         6 => Gpr::R12,
//         7 => Gpr::R13,
//         8 => Gpr::R14,
//         9 => Gpr::R15,
//         10 => Gpr::RBX,
//         _ => panic!("unknown bpf register"),
//     }
// }
//
pub(crate) const fn interpreter_step() -> Template {
    x64_template!{
        ; retn
        ;
        // ; retn
        // ; retn
        // ; lock rep repne retn
        // ; add -1, -1
        // ; add rax, word ptr [ rax + rdx * 8 + 2 ]
    }
    // x64_template!(lock rep repne retn);
    // x64_template!(add imm32(-1), imm32(-1));
    // //x64_instr!(add rax, word ptr [ Rq(0) + rbx * 8 + disp8(1) ]);
    // x64_template!(add rax, word ptr [ rax + rdx * 8 + 2 ]);
    // let dispatch = Template::merged([]);

    // Template::merged([
    //     add_rq_id(Gpr::BUDGET, Template::i32le(-1)),
    //     jcc(Flag::Sign, Template::bytes([0])),
    //     dispatch,
    //     RET,
    // ])
}
