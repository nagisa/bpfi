pub use super::generated::{Mnemonic, Prefix, x64_mnemonic, x64_prefixes};
use crate::{
    template::Template,
    x64::{AddressSize, EncodingMem},
};

#[derive(Clone, Copy)]
pub enum RegType {
    /// Low byte of a word register.
    ///
    /// This includes the unified low registers `spl`, `bpl`, `sil` and `dil` which conflict in
    /// encoding space with the high byte registers.
    B,
    /// High byte of a word register.
    H,
    /// Word register.
    W,
    /// Double word (32-bit) register.
    D,
    /// Quad word (64-bit) register.
    Q,
}

#[derive(Clone, Copy)]
pub struct Reg(pub RegType, pub u8);

#[derive(Clone, Copy)]
pub struct Mem {
    pub base: Option<Reg>,
    pub index: Option<(Reg, u8)>,
    pub disp: Template,
}

impl Mem {
    const fn verify_reg_is_addr(reg: Reg) -> Reg {
        if let Reg(RegType::D | RegType::Q, 0..16) = reg {
            reg
        } else {
            panic!("memory operands may only use 32-bit or 64-bit addressing in x64")
        }
    }
    const fn verify_disp_template(disp: &Template) {
        if !(disp.len == 0 || disp.len == 1 || disp.len == 4) {
            panic!("mem displacement must be 0, 1 or 4 bytes");
        }
    }

    const fn verify_scale_index(scale: u8, index: Reg) {
        if let Reg(RegType::D | RegType::Q, 4) = index {
            panic!("index register may not be ESP or RSP")
        }
        if !(scale == 1 || scale == 2 || scale == 4 || scale == 8) {
            panic!("scale may only be 1, 2, 4 or 8")
        }
    }
    /// [displacement]
    pub const fn displacement_only(disp: Template) -> Self {
        Self::verify_disp_template(&disp);
        Self {
            base: None,
            index: None,
            disp: disp,
        }
    }

    /// [base + displacement]
    pub const fn base_displacement(base: Reg, disp: Template) -> Self {
        Self::verify_disp_template(&disp);
        Self {
            base: Some(Self::verify_reg_is_addr(base)),
            index: None,
            disp: disp,
        }
    }

    /// [base]
    pub const fn base(base: Reg) -> Self {
        Self::base_displacement(base, Template::EMPTY)
    }

    /// [index * scale + base + disp] also known as SIB addressing.
    pub const fn scale_index_base(scale: u8, index: Reg, base: Reg, disp: Template) -> Self {
        Self::verify_disp_template(&disp);
        let index = Self::verify_reg_is_addr(index);
        Self::verify_scale_index(scale, index);
        Self {
            base: Some(Self::verify_reg_is_addr(base)),
            index: Some((index, scale)),
            disp,
        }
    }

    /// SIB but without base register.
    pub const fn scale_index(scale: u8, index: Reg, disp: Template) -> Self {
        Self::verify_disp_template(&disp);
        let index = Self::verify_reg_is_addr(index);
        Self::verify_scale_index(scale, index);
        Self {
            base: None,
            index: Some((index, scale)),
            disp,
        }
    }

    pub const fn encoding(self) -> EncodingMem {
        let addressing_size = match (self.base, self.index) {
            (None, None) => AddressSize::A64,
            (Some(Reg(rt1, _)), Some((Reg(rt2, _), _))) => {
                if rt1 as u8 != rt2 as u8 {
                    panic!("memory operands must use consistent register types for base and index")
                } else if matches!(rt1, RegType::Q) {
                    AddressSize::A64
                } else {
                    AddressSize::A32
                }
            }
            (Some(Reg(reg_type, _)), _) | (None, Some((Reg(reg_type, _), _))) => {
                if matches!(reg_type, RegType::Q) {
                    AddressSize::A64
                } else {
                    AddressSize::A32
                }
            }
        };

        let base = match self.base {
            Some(b) => Some(super::Reg(b.1)),
            None => None,
        };
        let index = match self.index {
            Some((i, s)) => Some((super::Reg(i.1), s.trailing_zeros() as u8)),
            None => None,
        };

        EncodingMem {
            addressing_size,
            base,
            index,
            disp: self.disp,
        }
    }
}

/// The size of the memory operand (e.g. `dword` in `dword [ ... ]`)
#[derive(Clone, Copy)]
pub enum MemSize {
    None,
    Byte,
    Word,
    Dword,
    Qword,
}

#[derive(Clone, Copy)]
pub enum Operand {
    Reg(Reg),
    Imm(Template),
    Rel(Template),
    Mem(MemSize, Mem),
}

impl Operand {
    pub const fn reg(&self) -> super::Reg {
        match self {
            Operand::Reg(Reg(_, num @ 0..16)) => super::Reg(*num),
            Operand::Reg(Reg(_, _)) => panic!("register number is invalid"),
            _ => panic!("non-register operand being used as register (this is a bug, report)"),
        }
    }

    pub const fn rm(&self) -> super::EncodingRm {
        match self {
            Operand::Reg(Reg(_, num @ 0..16)) => super::EncodingRm::Reg(super::Reg(*num)),
            Operand::Reg(Reg(_, _)) => panic!("R/M register number is invalid"),
            Operand::Mem(_, mem) => super::EncodingRm::Mem(mem.encoding()),
            _ => panic!("non-r/m operand being used as r/m (this is a bug, report)"),
        }
    }
}

#[derive(Clone, Copy)]
pub enum Operands {
    Z,
    A(Operand),
    B(Operand, Operand),
    C(Operand, Operand, Operand),
    D(Operand, Operand, Operand, Operand),
}

impl Operands {}

#[derive(Clone, Copy)]
pub struct Instruction {
    pub prefixes: &'static [Prefix],
    pub mnemonic: Mnemonic,
    pub operands: Operands,
}

impl Instruction {
    pub const fn encode_prefixes(&self) -> Template {
        let mut i = 0;
        let mut out = Template::EMPTY;
        while i < self.prefixes.len() {
            out = out.merge(&self.prefixes[i].encode());
            i += 1;
        }
        out
    }
    pub const fn encode(&self) -> Template {
        Template::merged([self.encode_prefixes(), self.encoding().encode()])
    }
}

#[macro_export]
macro_rules! x64_template {
    (@collect [$($insns:expr),*] []) => {
        Template::merged([$($insns.encode()),*])
    };
    // Semicolon rules.
    (@collect [$($insns:expr),*] [] ; ; $($rest:tt)*) => {
        compile_error!("instructions may only be preceded by a single semicolon")
    };
    (@collect [$($insns:expr),*] [] ; $($rest:tt)*) => {
        ast::x64_template!(@collect [$($insns),*] [] $($rest)*)
    };
    // Current instruction is complete
    (@collect [$($insns:expr),*] [$($cur_insn:tt)+] ; $($rest:tt)*) => {
        ast::x64_template!(@collect [
            $($insns,)*
            ast::x64_prefixes!(internal_x64_instr; $($cur_insn)+)
        ] [] ; $($rest)*)
    };
    (@collect [$($insns:expr),*] [$($cur_insn:tt)+]) => {
        ast::x64_template!(@collect [
            $($insns,)*
            ast::x64_prefixes!(internal_x64_instr; $($cur_insn)+)
        ] [])
    };
    // Otherwise keep collecting the current instruction tokens...
    (@collect [$($insns:expr),*] [$($cur_insn:tt)*] $insn_tok:tt $($rest:tt)*) => {
        ast::x64_template!(@collect
            [$($insns),*]
            [$($cur_insn)* $insn_tok]
            $($rest)*
        )
    };
    (@collect $($nomatch:tt)*) => {
        compile_error!("macro can't parse your instructions")
    };

    // Entrypoint (allowing a leading semicolon to enable consistent formatting of instructions)
    ($($tts:tt)*) => {{
        use {$crate::x64::ast, $crate::template::Template};
        ast::x64_template!(@collect [] [] $($tts)*)
    }};
}

#[macro_export]
macro_rules! internal_x64_instr {
    ([$($prefixes:ident),*]; $mnemonic:ident) => {
        ast::Instruction {
            prefixes: &[$(ast::Prefix::$prefixes),*],
            mnemonic: ast::x64_mnemonic!($mnemonic),
            operands: ast::Operands::Z,
        }
    };
    ([$($prefixes:ident),*]; $mnemonic:ident $($rest:tt)+) => {
        ast::internal_x64_instr!(@op1 [$($prefixes),*] [$mnemonic] [] $($rest)+)
    };

    (@op1 [$($prefixes:ident),*] [$mnemonic:ident] [$($cur:tt)+]) => {
        ast::Instruction {
            prefixes: &[$(ast::Prefix::$prefixes),*],
            mnemonic: ast::x64_mnemonic!($mnemonic),
            operands: ast::Operands::A(ast::x64_operand!($($cur)+)),
        }
    };
    (@op1 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] , $($rest:tt)+) => {
        ast::internal_x64_instr!(@op2 [$($prefixes),*] [$mnemonic] [$($a)*] [] $($rest)+)
    };
    (@op1 [$($prefixes:ident),*] [$mnemonic:ident] [$($cur:tt)*] $next:tt $($rest:tt)*) => {
        ast::internal_x64_instr!(@op1 [$($prefixes),*] [$mnemonic] [$($cur)* $next] $($rest)*)
    };

    (@op2 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($cur:tt)*]) => {
        ast::Instruction {
            prefixes: &[$(ast::Prefix::$prefixes),*],
            mnemonic: ast::x64_mnemonic!($mnemonic),
            operands: ast::Operands::B(ast::x64_operand!($($a)*), ast::x64_operand!($($cur)*)),
        }
    };
    (@op2 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($b:tt)*] , $($rest:tt)+) => {
        ast::internal_x64_instr!(@op3 [$($prefixes),*] [$mnemonic] [$($a)*] [$($b)*] [] $($rest)+)
    };
    (@op2 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($cur:tt)*] $next:tt $($rest:tt)*) => {
        ast::internal_x64_instr!(@op2 [$($prefixes),*] [$mnemonic] [$($a)*] [$($cur)* $next] $($rest)*)
    };

    (@op3 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($b:tt)*] [$($cur:tt)*]) => {
        ast::Instruction {
            prefixes: &[$(ast::Prefix::$prefixes),*],
            mnemonic: ast::x64_mnemonic!($mnemonic),
            operands: ast::Operands::C(ast::x64_operand!($($a)*), ast::x64_operand!($($b)*), ast::x64_operand!($($cur)*)),
        }
    };
    (@op3 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($b:tt)*] [$($cur:tt)*] , $($rest:tt)+) => {
        ast::internal_x64_instr!(@op4 [$($prefixes),*] [$mnemonic] [$($a)*] [$($b)*] [] $($rest)+)
    };
    (@op3 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($b:tt)*] [$($cur:tt)*] $next:tt $($rest:tt)*) => {
        ast::internal_x64_instr!(@op3 [$($prefixes),*] [$mnemonic] [$($a)*] [$($b)*] [$($cur)* $next] $($rest)*)
    };
    (@op4 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($b:tt)*] [$($c:tt)*] [$($cur:tt)*]) => {
        ast::Instruction {
            prefixes: &[$(ast::Prefix::$prefixes),*],
            mnemonic: ast::x64_mnemonic!($mnemonic),
            operands: ast::Operands::D(ast::x64_operand!($($a)*), ast::x64_operand!($($b)*), ast::x64_operand!($($c)*), ast::x64_operand!($($cur)*)),
        }
    };
    (@op3 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($b:tt)*] [$($c:tt)*] [$($cur:tt)*] , $($rest:tt)+) => {
        compile_error!("x64 instructions support at most 4 operands")
    };
    (@op3 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($b:tt)*] [$($c:tt)*] [$($cur:tt)*] $next:tt $($rest:tt)*) => {
        ast::internal_x64_instr!(@op4 [$($prefixes),*] [$mnemonic] [$($a)*] [$($b)*] [$($c:tt)*] [$($cur)* $next] $($rest)*)
    };
}

/// Conversion helper to produce templates for immediate literals
pub struct ImmTemplate<T = i8>(pub T);
macro_rules! impl_num_imm_template {
    ($($ty:ty),*) => {
        $(impl ImmTemplate<$ty> {
            pub const fn template(self) -> Template { Template::bytes(self.0.to_le_bytes()) }
        })*
    };
}
impl_num_imm_template!(u8, i8, u16, i16, u32, i32, u64, i64, f32, f64);

#[macro_export]
macro_rules! x64_operand {
    ($reg:ident) => {
        ast::Operand::Reg(ast::x64_operand!(@reg $reg))
    };
    // https://censoredusername.github.io/dynasm-rs/language/langref_x64.html#register style
    // register definitions. These allow for parametric registers.
    (Rb($id: expr)) => { ast::Operand::Reg(ast::x64_operand!(@reg Rb($id))) };
    (Rh($id: expr)) => { ast::Operand::Reg(ast::x64_operand!(@reg Rh($id))) };
    (Rw($id: expr)) => { ast::Operand::Reg(ast::x64_operand!(@reg Rw($id))) };
    (Rd($id: expr)) => { ast::Operand::Reg(ast::x64_operand!(@reg Rd($id))) };
    (Rq($id: expr)) => { ast::Operand::Reg(ast::x64_operand!(@reg Rq($id))) };
    (Rf($id: expr)) => { ast::Operand::Reg(ast::x64_operand!(@reg Rf($id))) };
    (Rm($id: expr)) => { ast::Operand::Reg(ast::x64_operand!(@reg Rm($id))) };
    (Rx($id: expr)) => { ast::Operand::Reg(ast::x64_operand!(@reg Rx($id))) };
    (Ry($id: expr)) => { ast::Operand::Reg(ast::x64_operand!(@reg Ry($id))) };
    (Rs($id: expr)) => { ast::Operand::Reg(ast::x64_operand!(@reg Rs($id))) };
    (RC($id: expr)) => { ast::Operand::Reg(ast::x64_operand!(@reg RC($id))) };
    (RD($id: expr)) => { ast::Operand::Reg(ast::x64_operand!(@reg RD($id))) };
    (RB($id: expr)) => { ast::Operand::Reg(ast::x64_operand!(@reg RB($id))) };

    ($value:literal) => { ast::Operand::Imm(ast::ImmTemplate($value).template()) };
    (imm($value:literal)) => { ast::Operand::Imm(ast::ImmTemplate($value).template()) };
    (imm($value:expr)) => { ast::Operand::Imm($value) };
    (rel($value:literal)) => { ast::Operand::Rel(ast::ImmTemplate($value).template()) };
    (rel($value:expr)) => { ast::Operand::Rel($value) };

    (byte [$($mem:tt)+]) => { ast::Operand::Mem(ast::MemSize::Byte, ast::x64_operand!(@mem [$($mem)+])) };
    (word [$($mem:tt)+]) => { ast::Operand::Mem(ast::MemSize::Word, ast::x64_operand!(@mem [$($mem)+])) };
    (dword [$($mem:tt)+]) => { ast::Operand::Mem(ast::MemSize::Dword, ast::x64_operand!(@mem [$($mem)+])) };
    (qword [$($mem:tt)+]) => { ast::Operand::Mem(ast::MemSize::Qword, ast::x64_operand!(@mem [$($mem)+])) };
    ([$($mem:tt)+]) => { ast::Operand::Mem(ast::MemSize::None, ast::x64_operand!(@mem [$($mem)+])) };

    (@mem [$($mem:tt)+]) => { ast::x64_operand!(@mem_parse
            [base = None] [index = None] [scale = 1] [disp = Template::EMPTY] $($mem)+
    ) };

    (@mem_parse [base = None] [index = None] [scale = $s:expr] [disp = $disp:expr]) => {
        ast::Mem::displacement_only($disp)
    };
    (@mem_parse [base = Some($base:expr)] [index = None] [scale = $scale:expr] [disp = $disp:expr]) => {
        ast::Mem::base_displacement($base, $disp)
    };
    (@mem_parse [base = None] [index = Some($index:expr)] [scale = $scale:expr] [disp = $disp:expr]) => {
        ast::Mem::scale_index($scale, $index, $disp)
    };
    (@mem_parse [base = Some($base:expr)] [index = Some($index:expr)] [scale = $scale:expr] [disp = $disp:expr]) => {
        ast::Mem::scale_index_base($scale, $index, $base, $disp)
    };

    // Parse disp8/disp32 operand (possibly followed by a plus and other operands)
    (@mem_parse
        [base = $($base:tt)*] [index = $($index:tt)*] [scale = $scale:expr] [disp = $old:expr]
        $disp:literal $(+ $($rest:tt)+)?
    ) => {
        ast::x64_operand!(@mem_parse
            [base = $($base)*] [index = $($index)*] [scale = $scale] [disp = ast::x64_operand!(@disp $disp)]
            $($($rest)+)?
        )
    };
    (@mem_parse
        [base = $($base:tt)*] [index = $($index:tt)*] [scale = $scale:expr] [disp = $old:expr]
        disp8($($disp:tt)+) $(+ $($rest:tt)+)?
    ) => {
        x64_operand!(@mem_parse
            [base = $($base)*] [index = $($index)*] [scale = $scale] [disp = ast::x64_operand!(@disp disp8($($disp)+))]
            $($($rest)+)?
        )
    };
    (@mem_parse
        [base = $($base:tt)*] [index = $($index:tt)*] [scale = $scale:expr] [disp = $old:expr]
        disp32($($disp:tt)+) $(+ $($rest:tt)+)?
    ) => {
        x64_operand!(@mem_parse
            [base = $($base)*] [index = $($index)*] [scale = $scale] [disp = ast::x64_operand!(@disp disp32($($disp)+))]
            $($($rest)+)?
        )
    };

    // Parse scale * index, or index * scale
    (@mem_parse
        [base = $($base:tt)*] [index = $($_:tt)*] [scale = $scale:expr] [disp = $disp:expr]
        $n:literal * $reg:tt $(($($ra:tt)+))? $(+ $($rest:tt)+)?
    ) => {
        ast::x64_operand!(@mem_parse
            [base = $($base)*] [index = Some(ast::x64_operand!(@reg $reg $(($($ra)+))?))] [scale = $n] [disp = $disp]
            $($($rest)+)?
        )
    };
    (@mem_parse
        [base = $($base:tt)*] [index = $($_:tt)*] [scale = $scale:expr] [disp = $disp:expr]
        $reg:tt $(($($ra:tt)+))? * $n:literal $(+ $($rest:tt)*)?
    ) => {
        ast::x64_operand!(@mem_parse
            [base = $($base)*] [index = Some(ast::x64_operand!(@reg $reg $(($($ra)+))?))] [scale = $n] [disp = $disp]
            $($($rest)+)?
        )
    };

    // The base register operand.
    (@mem_parse
        [base = $($_:tt)*] [index = $($index:tt)*] [scale = $scale:expr] [disp = $disp:expr]
        $reg:tt $(($($ra:tt)+))? $(+ $($rest:tt)+)?
    ) => {
        ast::x64_operand!(@mem_parse
            [base = Some(ast::x64_operand!(@reg $reg $(($($ra)+))?))] [index = $($index)*] [scale = $scale] [disp = $disp]
            $($($rest)+)?
        )
    };

    (@disp $value:literal) => { ast::ImmTemplate($value).template() };
    (@disp disp8($value:literal)) => { ast::ImmTemplate::<i8>($value).template() };
    (@disp disp8($value:expr)) => { $value };
    (@disp disp32($value:literal)) => { ast::ImmTemplate::<i32>($value).template() };
    (@disp disp32($value:expr)) => { $value };

    (@reg Rb($id: expr)) => { ast::Reg(ast::RegType::B, $id) };
    (@reg Rh($id: expr)) => { ast::Reg(ast::RegType::H, $id) };
    (@reg Rw($id: expr)) => { ast::Reg(ast::RegType::W, $id) };
    (@reg Rd($id: expr)) => { ast::Reg(ast::RegType::D, $id) };
    (@reg Rq($id: expr)) => { ast::Reg(ast::RegType::Q, $id) };
    (@reg Rf($id: expr)) => { compile_error!("x87 registers not supported") };
    (@reg Rm($id: expr)) => { compile_error!("MMX registers not supported") };
    (@reg Rx($id: expr)) => { compile_error!("XMM registers not supported") };
    (@reg Ry($id: expr)) => { compile_error!("YMM registers not supported") };
    (@reg Rs($id: expr)) => { compile_error!("segment registers not supported") };
    (@reg RC($id: expr)) => { compile_error!("control registers not supported") };
    (@reg RD($id: expr)) => { compile_error!("debug registers not supported") };
    (@reg RB($id: expr)) => { compile_error!("bound registers not supported") };


    (@reg al) => { ast::x64_operand!(@reg Rb(0)) };
    (@reg cl) => { ast::x64_operand!(@reg Rb(1)) };
    (@reg dl) => { ast::x64_operand!(@reg Rb(2)) };
    (@reg bl) => { ast::x64_operand!(@reg Rb(3)) };
    (@reg spl) => { ast::x64_operand!(@reg Rb(4)) };
    (@reg bpl) => { ast::x64_operand!(@reg Rb(5)) };
    (@reg sil) => { ast::x64_operand!(@reg Rb(6)) };
    (@reg dil) => { ast::x64_operand!(@reg Rb(7)) };
    (@reg r0b) => { ast::x64_operand!(@reg Rb(0)) };
    (@reg r1b) => { ast::x64_operand!(@reg Rb(1)) };
    (@reg r2b) => { ast::x64_operand!(@reg Rb(2)) };
    (@reg r3b) => { ast::x64_operand!(@reg Rb(3)) };
    (@reg r4b) => { ast::x64_operand!(@reg Rb(4)) };
    (@reg r5b) => { ast::x64_operand!(@reg Rb(5)) };
    (@reg r6b) => { ast::x64_operand!(@reg Rb(6)) };
    (@reg r7b) => { ast::x64_operand!(@reg Rb(7)) };
    (@reg r8b) => { ast::x64_operand!(@reg Rb(8)) };
    (@reg r9b) => { ast::x64_operand!(@reg Rb(9)) };
    (@reg r10b) => { ast::x64_operand!(@reg Rb(10)) };
    (@reg r11b) => { ast::x64_operand!(@reg Rb(11)) };
    (@reg r12b) => { ast::x64_operand!(@reg Rb(12)) };
    (@reg r13b) => { ast::x64_operand!(@reg Rb(13)) };
    (@reg r14b) => { ast::x64_operand!(@reg Rb(14)) };
    (@reg r15b) => { ast::x64_operand!(@reg Rb(15)) };

    (@reg ah) => { ast::x64_operand!(@reg Rh(4)) };
    (@reg ch) => { ast::x64_operand!(@reg Rh(5)) };
    (@reg dh) => { ast::x64_operand!(@reg Rh(6)) };
    (@reg bh) => { ast::x64_operand!(@reg Rh(7)) };

    (@reg ax) => { ast::x64_operand!(@reg Rw(0)) };
    (@reg cx) => { ast::x64_operand!(@reg Rw(1)) };
    (@reg dx) => { ast::x64_operand!(@reg Rw(2)) };
    (@reg bx) => { ast::x64_operand!(@reg Rw(3)) };
    (@reg sp) => { ast::x64_operand!(@reg Rw(4)) };
    (@reg bp) => { ast::x64_operand!(@reg Rw(5)) };
    (@reg si) => { ast::x64_operand!(@reg Rw(6)) };
    (@reg di) => { ast::x64_operand!(@reg Rw(7)) };
    (@reg r0w) => { ast::x64_operand!(@reg Rw(0)) };
    (@reg r1w) => { ast::x64_operand!(@reg Rw(1)) };
    (@reg r2w) => { ast::x64_operand!(@reg Rw(2)) };
    (@reg r3w) => { ast::x64_operand!(@reg Rw(3)) };
    (@reg r4w) => { ast::x64_operand!(@reg Rw(4)) };
    (@reg r5w) => { ast::x64_operand!(@reg Rw(5)) };
    (@reg r6w) => { ast::x64_operand!(@reg Rw(6)) };
    (@reg r7w) => { ast::x64_operand!(@reg Rw(7)) };
    (@reg r8w) => { ast::x64_operand!(@reg Rw(8)) };
    (@reg r9w) => { ast::x64_operand!(@reg Rw(9)) };
    (@reg r10w) => { ast::x64_operand!(@reg Rw(10)) };
    (@reg r11w) => { ast::x64_operand!(@reg Rw(11)) };
    (@reg r12w) => { ast::x64_operand!(@reg Rw(12)) };
    (@reg r13w) => { ast::x64_operand!(@reg Rw(13)) };
    (@reg r14w) => { ast::x64_operand!(@reg Rw(14)) };
    (@reg r15w) => { ast::x64_operand!(@reg Rw(15)) };

    (@reg eax) => { ast::x64_operand!(@reg Rd(0)) };
    (@reg ecx) => { ast::x64_operand!(@reg Rd(1)) };
    (@reg edx) => { ast::x64_operand!(@reg Rd(2)) };
    (@reg ebx) => { ast::x64_operand!(@reg Rd(3)) };
    (@reg esp) => { ast::x64_operand!(@reg Rd(4)) };
    (@reg ebp) => { ast::x64_operand!(@reg Rd(5)) };
    (@reg esi) => { ast::x64_operand!(@reg Rd(6)) };
    (@reg edi) => { ast::x64_operand!(@reg Rd(7)) };
    (@reg r0d) => { ast::x64_operand!(@reg Rd(0)) };
    (@reg r1d) => { ast::x64_operand!(@reg Rd(1)) };
    (@reg r2d) => { ast::x64_operand!(@reg Rd(2)) };
    (@reg r3d) => { ast::x64_operand!(@reg Rd(3)) };
    (@reg r4d) => { ast::x64_operand!(@reg Rd(4)) };
    (@reg r5d) => { ast::x64_operand!(@reg Rd(5)) };
    (@reg r6d) => { ast::x64_operand!(@reg Rd(6)) };
    (@reg r7d) => { ast::x64_operand!(@reg Rd(7)) };
    (@reg r8d) => { ast::x64_operand!(@reg Rd(8)) };
    (@reg r9d) => { ast::x64_operand!(@reg Rd(9)) };
    (@reg r10d) => { ast::x64_operand!(@reg Rd(10)) };
    (@reg r11d) => { ast::x64_operand!(@reg Rd(11)) };
    (@reg r12d) => { ast::x64_operand!(@reg Rd(12)) };
    (@reg r13d) => { ast::x64_operand!(@reg Rd(13)) };
    (@reg r14d) => { ast::x64_operand!(@reg Rd(14)) };
    (@reg r15d) => { ast::x64_operand!(@reg Rd(15)) };

    (@reg rax) => { ast::x64_operand!(@reg Rq(0)) };
    (@reg rcx) => { ast::x64_operand!(@reg Rq(1)) };
    (@reg rdx) => { ast::x64_operand!(@reg Rq(2)) };
    (@reg rbx) => { ast::x64_operand!(@reg Rq(3)) };
    (@reg rsp) => { ast::x64_operand!(@reg Rq(4)) };
    (@reg rbp) => { ast::x64_operand!(@reg Rq(5)) };
    (@reg rsi) => { ast::x64_operand!(@reg Rq(6)) };
    (@reg rdi) => { ast::x64_operand!(@reg Rq(7)) };
    (@reg r0) => { ast::x64_operand!(@reg Rq(0)) };
    (@reg r1) => { ast::x64_operand!(@reg Rq(1)) };
    (@reg r2) => { ast::x64_operand!(@reg Rq(2)) };
    (@reg r3) => { ast::x64_operand!(@reg Rq(3)) };
    (@reg r4) => { ast::x64_operand!(@reg Rq(4)) };
    (@reg r5) => { ast::x64_operand!(@reg Rq(5)) };
    (@reg r6) => { ast::x64_operand!(@reg Rq(6)) };
    (@reg r7) => { ast::x64_operand!(@reg Rq(7)) };
    (@reg r8) => { ast::x64_operand!(@reg Rq(8)) };
    (@reg r9) => { ast::x64_operand!(@reg Rq(9)) };
    (@reg r10) => { ast::x64_operand!(@reg Rq(10)) };
    (@reg r11) => { ast::x64_operand!(@reg Rq(11)) };
    (@reg r12) => { ast::x64_operand!(@reg Rq(12)) };
    (@reg r13) => { ast::x64_operand!(@reg Rq(13)) };
    (@reg r14) => { ast::x64_operand!(@reg Rq(14)) };
    (@reg r15) => { ast::x64_operand!(@reg Rq(15)) };
}

pub use {internal_x64_instr, x64_operand, x64_template};
