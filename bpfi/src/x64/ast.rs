pub use super::generated::{Mnemonic, Prefix, x64_mnemonic, x64_prefixes};
use crate::{template::Template, x64::{EncodingMem, Gpr, Size}};

#[derive(Clone, Copy)]
pub enum Reg {
    Gpr(Size, u8),
}

impl Reg {
    pub const fn encode_gpr(self) -> Gpr {
        match self {
            Reg::Gpr(Size::Byte | Size::Word | Size::Long | Size::Quad, idx@0..16) => Gpr(idx),
            Reg::Gpr(_, _) => panic!("register is invalid"),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Mem {
    pub base: Option<Reg>,
    pub index: Option<(Reg, u8)>,
    pub disp: Template,
}

impl Mem {
    const fn verify_reg_is_gpr(reg: Reg) -> Reg {
        match reg {
            Reg::Gpr(_, _) => reg,
            // _ => panic!("memory reference registers must be in GPR class"),
        }
    }
    const fn verify_disp_template(disp: &Template) {
        if !(disp.len == 0 || disp.len == 1 || disp.len == 4) {
            panic!("mem displacement must be 0, 1 or 4 bytes");
        }
    }

    const fn verify_scale_index(scale: u8, index: Reg) {
        if let Reg::Gpr(_, 4) = index {
            panic!("index register may not be SP")
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
            base: Some(Self::verify_reg_is_gpr(base)),
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
        let index = Self::verify_reg_is_gpr(index);
        Self::verify_scale_index(scale, index);
        Self {
            base: Some(Self::verify_reg_is_gpr(base)),
            index: Some((index, scale)),
            disp,
        }
    }

    /// SIB but without base register.
    pub const fn scale_index(scale: u8, index: Reg, disp: Template) -> Self {
        Self::verify_disp_template(&disp);
        let index = Self::verify_reg_is_gpr(index);
        Self::verify_scale_index(scale, index);
        Self {
            base: None,
            index: Some((index, scale)),
            disp,
        }
    }

    pub const fn encoding(self) -> EncodingMem {
        let base = match self.base {
            Some(b) => Some(b.encode_gpr()),
            None => None,
        };
        let index = match self.index {
            Some((i, s)) => Some((i.encode_gpr(), s)),
            None => None
        };
        EncodingMem { base, index, disp: self.disp }
    }
}

#[derive(Clone, Copy)]
pub enum Operand {
    Reg(Reg),
    Imm(Template),
    Mem(Size, Mem),
}

#[derive(Clone, Copy)]
pub enum Operands {
    Z,
    A(Operand),
    B(Operand, Operand),
    C(Operand, Operand, Operand),
    D(Operand, Operand, Operand, Operand),
}

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
        $crate::template::Template::merged([$($insns.encode()),*])
    };
    // Semicolon rules.
    (@collect [$($insns:expr),*] [] ; ; $($rest:tt)*) => {
        compile_error!("instructions may only be preceded by a single semicolon")
    };
    (@collect [$($insns:expr),*] [] ; $($rest:tt)*) => {
        $crate::x64::ast::x64_template!(@collect [$($insns),*] [] $($rest)*)
    };
    // Current instruction is complete
    (@collect [$($insns:expr),*] [$($cur_insn:tt)+] ; $($rest:tt)*) => {
        $crate::x64::ast::x64_template!(@collect [
            $($insns,)*
            $crate::x64::ast::x64_prefixes!(internal_x64_instr; $($cur_insn)+)
        ] [] ; $($rest)*)
    };
    (@collect [$($insns:expr),*] [$($cur_insn:tt)+]) => {
        $crate::x64::ast::x64_template!(@collect [
            $($insns,)*
            $crate::x64::ast::x64_prefixes!(internal_x64_instr; $($cur_insn)+)
        ] [])
    };
    // Otherwise keep collecting the current instruction tokens...
    (@collect [$($insns:expr),*] [$($cur_insn:tt)*] $insn_tok:tt $($rest:tt)*) => {
        $crate::x64::ast::x64_template!(@collect
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
        use $crate::x64::ast::*;
        $crate::x64::ast::x64_template!(@collect [] [] $($tts)*)
    }};
}

#[macro_export]
macro_rules! internal_x64_instr {
    ([$($prefixes:ident),*]; $mnemonic:ident) => {
        $crate::x64::ast::Instruction {
            prefixes: &[$($crate::x64::ast::Prefix::$prefixes),*],
            mnemonic: $crate::x64::ast::x64_mnemonic!($mnemonic),
            operands: Operands::Z,
        }
    };
    ([$($prefixes:ident),*]; $mnemonic:ident $($rest:tt)+) => {
        $crate::x64::ast::internal_x64_instr!(@op1 [$($prefixes),*] [$mnemonic] [] $($rest)+)
    };

    (@op1 [$($prefixes:ident),*] [$mnemonic:ident] [$($cur:tt)+]) => {
        Instruction {
            prefixes: &[$($crate::x64::ast::Prefix::$prefixes),*],
            mnemonic: $crate::x64::ast::x64_mnemonic!($mnemonic),
            operands: Operands::A($crate::x64::ast::x64_operand!($($cur)+)),
        }
    };
    (@op1 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] , $($rest:tt)+) => {
        $crate::x64::ast::internal_x64_instr!(@op2 [$($prefixes),*] [$mnemonic] [$($a)*] [] $($rest)+)
    };
    (@op1 [$($prefixes:ident),*] [$mnemonic:ident] [$($cur:tt)*] $next:tt $($rest:tt)*) => {
        $crate::x64::ast::internal_x64_instr!(@op1 [$($prefixes),*] [$mnemonic] [$($cur)* $next] $($rest)*)
    };

    (@op2 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($cur:tt)*]) => {
        Instruction {
            prefixes: &[$($crate::x64::ast::Prefix::$prefixes),*],
            mnemonic: $crate::x64::ast::x64_mnemonic!($mnemonic),
            operands: Operands::B($crate::x64::ast::x64_operand!($($a)*), $crate::x64::ast::x64_operand!($($cur)*)),
        }
    };
    (@op2 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($b:tt)*] , $($rest:tt)+) => {
        $crate::x64::ast::internal_x64_instr!(@op3 [$($prefixes),*] [$mnemonic] [$($a)*] [$($b)*] [] $($rest)+)
    };
    (@op2 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($cur:tt)*] $next:tt $($rest:tt)*) => {
        $crate::x64::ast::internal_x64_instr!(@op2 [$($prefixes),*] [$mnemonic] [$($a)*] [$($cur)* $next] $($rest)*)
    };

    (@op3 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($b:tt)*] [$($cur:tt)*]) => {
        Instruction {
            prefixes: &[$($crate::x64::ast::Prefix::$prefixes),*],
            mnemonic: $crate::x64::ast::x64_mnemonic!($mnemonic),
            operands: Operands::C($crate::x64::ast::x64_operand!($($a)*), $crate::x64::ast::x64_operand!($($b)*), $crate::x64::ast::x64_operand!($($cur)*)),
        }
    };
    (@op3 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($b:tt)*] [$($cur:tt)*] , $($rest:tt)+) => {
        $crate::x64::ast::internal_x64_instr!(@op4 [$($prefixes),*] [$mnemonic] [$($a)*] [$($b)*] [] $($rest)+)
    };
    (@op3 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($b:tt)*] [$($cur:tt)*] $next:tt $($rest:tt)*) => {
        $crate::x64::ast::internal_x64_instr!(@op3 [$($prefixes),*] [$mnemonic] [$($a)*] [$($b)*] [$($cur)* $next] $($rest)*)
    };
    (@op4 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($b:tt)*] [$($c:tt)*] [$($cur:tt)*]) => {
        Instruction {
            prefixes: &[$($crate::x64::ast::Prefix::$prefixes),*],
            mnemonic: $crate::x64::ast::x64_mnemonic!($mnemonic),
            operands: Operands::D($crate::x64::ast::x64_operand!($($a)*), $crate::x64::ast::x64_operand!($($b)*), $crate::x64::ast::x64_operand!($($c)*), $crate::x64::ast::x64_operand!($($cur)*)),
        }
    };
    (@op3 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($b:tt)*] [$($c:tt)*] [$($cur:tt)*] , $($rest:tt)+) => {
        compile_error!("x64 instructions support at most 4 operands")
    };
    (@op3 [$($prefixes:ident),*] [$mnemonic:ident] [$($a:tt)*] [$($b:tt)*] [$($c:tt)*] [$($cur:tt)*] $next:tt $($rest:tt)*) => {
        $crate::x64::ast::internal_x64_instr!(@op4 [$($prefixes),*] [$mnemonic] [$($a)*] [$($b)*] [$($c:tt)*] [$($cur)* $next] $($rest)*)
    };
}

/// Conversion helper to produce templates for immediate literals
pub struct ImmTemplate<T>(pub T);
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
        $crate::x64::ast::Operand::Reg($crate::x64::ast::x64_operand!(@reg $reg))
    };
    // https://censoredusername.github.io/dynasm-rs/language/langref_x64.html#register style
    // register definitions. These allow for parametric registers.
    (Rb($id: expr)) => { $crate::x64::ast::Operand::Reg($crate::x64::ast::x64_operand!(@reg Rb($id))) };
    (Rh($id: expr)) => { $crate::x64::ast::Operand::Reg($crate::x64::ast::x64_operand!(@reg Rh($id))) };
    (Rw($id: expr)) => { $crate::x64::ast::Operand::Reg($crate::x64::ast::x64_operand!(@reg Rw($id))) };
    (Rd($id: expr)) => { $crate::x64::ast::Operand::Reg($crate::x64::ast::x64_operand!(@reg Rd($id))) };
    (Rq($id: expr)) => { $crate::x64::ast::Operand::Reg($crate::x64::ast::x64_operand!(@reg Rq($id))) };
    (Rf($id: expr)) => { $crate::x64::ast::Operand::Reg($crate::x64::ast::x64_operand!(@reg Rf($id))) };
    (Rm($id: expr)) => { $crate::x64::ast::Operand::Reg($crate::x64::ast::x64_operand!(@reg Rm($id))) };
    (Rx($id: expr)) => { $crate::x64::ast::Operand::Reg($crate::x64::ast::x64_operand!(@reg Rx($id))) };
    (Ry($id: expr)) => { $crate::x64::ast::Operand::Reg($crate::x64::ast::x64_operand!(@reg Ry($id))) };
    (Rs($id: expr)) => { $crate::x64::ast::Operand::Reg($crate::x64::ast::x64_operand!(@reg Rs($id))) };
    (RC($id: expr)) => { $crate::x64::ast::Operand::Reg($crate::x64::ast::x64_operand!(@reg RC($id))) };
    (RD($id: expr)) => { $crate::x64::ast::Operand::Reg($crate::x64::ast::x64_operand!(@reg RD($id))) };
    (RB($id: expr)) => { $crate::x64::ast::Operand::Reg($crate::x64::ast::x64_operand!(@reg RB($id))) };

    ($value:literal) => {
        Operand::Imm($crate::x64::ast::ImmTemplate($value).template())
    };
    (imm($value:literal)) => {
        Operand::Imm($crate::x64::ast::ImmTemplate($value).template())
    };
    (imm($value:expr)) => {
        Operand::Imm($value)
    };
    (rel($value:literal)) => {
        Operand::Imm($crate::x64::ast::ImmTemplate($value).template())
    };
    (rel($value:expr)) => {
        Operand::Imm($value)
    };

    (byte ptr[$($mem:tt)+]) => {
        Operand::Mem($crate::x64::Size::Byte, $crate::x64::ast::x64_operand!(@mem [$($mem)+]))
    };
    (word ptr[$($mem:tt)+]) => {
        Operand::Mem($crate::x64::Size::Word, $crate::x64::ast::x64_operand!(@mem [$($mem)+]))
    };
    (dword ptr[$($mem:tt)+]) => {
        Operand::Mem($crate::x64::Size::Long, $crate::x64::ast::x64_operand!(@mem [$($mem)+]))
    };
    (qword ptr[$($mem:tt)+]) => {
        Operand::Mem($crate::x64::Size::Quad, $crate::x64::ast::x64_operand!(@mem [$($mem)+]))
    };
    ([$($mem:tt)+]) => {
        Operand::Mem($crate::x64::Size::None, $crate::x64::ast::x64_operand!(@mem [$($mem)+]))
    };

    (@mem [$($mem:tt)+]) => { $crate::x64::ast::x64_operand!(@mem_parse [base = None] [index = None] [scale = 1] [disp = Template::EMPTY] $($mem)+) };

    (@mem_parse [base = None] [index = None] [scale = $s:expr] [disp = $disp:expr]) => {
        Mem::displacement_only($disp)
    };
    (@mem_parse [base = Some($base:expr)] [index = None] [scale = $scale:expr] [disp = $disp:expr]) => {
        Mem::base_displacement($base, $disp)
    };
    (@mem_parse [base = None] [index = Some($index:expr)] [scale = $scale:expr] [disp = $disp:expr]) => {
        Mem::scale_index($scale, $index, $disp)
    };
    (@mem_parse [base = Some($base:expr)] [index = Some($index:expr)] [scale = $scale:expr] [disp = $disp:expr]) => {
        Mem::scale_index_base($scale, $index, $base, $disp)
    };

    // Parse disp8/disp32 operand (possibly followed by a plus and other operands)
    (@mem_parse
        [base = $($base:tt)*] [index = $($index:tt)*] [scale = $scale:expr] [disp = $old:expr]
        $disp:literal $(+ $($rest:tt)+)?
    ) => {
        x64_operand!(@mem_parse
            [base = $($base)*] [index = $($index)*] [scale = $scale] [disp = $crate::x64::ast::x64_operand!(@disp $disp)]
            $($($rest)+)?
        )
    };
    (@mem_parse
        [base = $($base:tt)*] [index = $($index:tt)*] [scale = $scale:expr] [disp = $old:expr]
        disp8($($disp:tt)+) $(+ $($rest:tt)+)?
    ) => {
        x64_operand!(@mem_parse
            [base = $($base)*] [index = $($index)*] [scale = $scale] [disp = $crate::x64::ast::x64_operand!(@disp disp8($($disp)+))]
            $($($rest)+)?
        )
    };
    (@mem_parse
        [base = $($base:tt)*] [index = $($index:tt)*] [scale = $scale:expr] [disp = $old:expr]
        disp32($($disp:tt)+) $(+ $($rest:tt)+)?
    ) => {
        x64_operand!(@mem_parse
            [base = $($base)*] [index = $($index)*] [scale = $scale] [disp = $crate::x64::ast::x64_operand!(@disp disp32($($disp)+))]
            $($($rest)+)?
        )
    };

    // Parse scale * index, or index * scale
    (@mem_parse
        [base = $($base:tt)*] [index = $($_:tt)*] [scale = $scale:expr] [disp = $disp:expr]
        $n:literal * $reg:tt $(($($ra:tt)+))? $(+ $($rest:tt)+)?
    ) => {
        $crate::x64::ast::x64_operand!(@mem_parse
            [base = $($base)*] [index = Some($crate::x64::ast::x64_operand!(@reg $reg $(($($ra)+))?))] [scale = $n] [disp = $disp]
            $($($rest)+)?
        )
    };
    (@mem_parse
        [base = $($base:tt)*] [index = $($_:tt)*] [scale = $scale:expr] [disp = $disp:expr]
        $reg:tt $(($($ra:tt)+))? * $n:literal $(+ $($rest:tt)*)?
    ) => {
        $crate::x64::ast::x64_operand!(@mem_parse
            [base = $($base)*] [index = Some($crate::x64::ast::x64_operand!(@reg $reg $(($($ra)+))?))] [scale = $n] [disp = $disp]
            $($($rest)+)?
        )
    };

    // The base register operand.
    (@mem_parse
        [base = $($_:tt)*] [index = $($index:tt)*] [scale = $scale:expr] [disp = $disp:expr]
        $reg:tt $(($($ra:tt)+))? $(+ $($rest:tt)+)?
    ) => {
        $crate::x64::ast::x64_operand!(@mem_parse
            [base = Some($crate::x64::ast::x64_operand!(@reg $reg $(($($ra)+))?))] [index = $($index)*] [scale = $scale] [disp = $disp]
            $($($rest)+)?
        )
    };

    (@disp $value:literal) => {
        if let -128..128 = $value {
            $crate::x64::ast::x64_operand!(@disp disp8($value))
        } else {
            $crate::x64::ast::x64_operand!(@disp disp32($value))
        }
    };
    (@disp disp8($value:literal)) => { $crate::x64::ast::ImmTemplate::<i8>($value).template() };
    (@disp disp8($value:expr)) => { $value };
    (@disp disp32($value:literal)) => { $crate::x64::ast::ImmTemplate::<i32>($value).template() };
    (@disp disp32($value:expr)) => { $value };

    (@reg Rb($id: expr)) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, $id) };
    (@reg Rh($id: expr)) => { compile_error!("high byte registers not supported") };
    (@reg Rw($id: expr)) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, $id) };
    (@reg Rd($id: expr)) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, $id) };
    (@reg Rq($id: expr)) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, $id) };
    (@reg Rf($id: expr)) => { compile_error!("x87 registers not supported") };
    (@reg Rm($id: expr)) => { compile_error!("MMX registers not supported") };
    (@reg Rx($id: expr)) => { compile_error!("XMM registers not supported") };
    (@reg Ry($id: expr)) => { compile_error!("YMM registers not supported") };
    (@reg Rs($id: expr)) => { compile_error!("segment registers not supported") };
    (@reg RC($id: expr)) => { compile_error!("control registers not supported") };
    (@reg RD($id: expr)) => { compile_error!("debug registers not supported") };
    (@reg RB($id: expr)) => { compile_error!("bound registers not supported") };


    (@reg al) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 0) };
    (@reg cl) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 1) };
    (@reg dl) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 2) };
    (@reg bl) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 3) };
    (@reg spl) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 4) };
    (@reg bpl) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 5) };
    (@reg sil) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 6) };
    (@reg dil) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 7) };
    (@reg r8b) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 8) };
    (@reg r9b) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 9) };
    (@reg r10b) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 10) };
    (@reg r11b) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 11) };
    (@reg r12b) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 12) };
    (@reg r13b) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 13) };
    (@reg r14b) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 14) };
    (@reg r15b) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Byte, 15) };

    (@reg ax) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 0) };
    (@reg cx) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 1) };
    (@reg dx) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 2) };
    (@reg bx) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 3) };
    (@reg sp) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 4) };
    (@reg bp) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 5) };
    (@reg si) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 6) };
    (@reg di) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 7) };
    (@reg r8w) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 8) };
    (@reg r9w) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 9) };
    (@reg r10w) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 10) };
    (@reg r11w) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 11) };
    (@reg r12w) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 12) };
    (@reg r13w) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 13) };
    (@reg r14w) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 14) };
    (@reg r15w) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Word, 15) };

    (@reg eax) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 0) };
    (@reg ecx) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 1) };
    (@reg edx) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 2) };
    (@reg ebx) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 3) };
    (@reg esp) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 4) };
    (@reg ebp) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 5) };
    (@reg esi) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 6) };
    (@reg edi) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 7) };
    (@reg r8d) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 8) };
    (@reg r9d) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 9) };
    (@reg r10d) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 10) };
    (@reg r11d) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 11) };
    (@reg r12d) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 12) };
    (@reg r13d) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 13) };
    (@reg r14d) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 14) };
    (@reg r15d) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Long, 15) };

    (@reg rax) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 0) };
    (@reg rcx) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 1) };
    (@reg rdx) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 2) };
    (@reg rbx) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 3) };
    (@reg rsp) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 4) };
    (@reg rbp) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 5) };
    (@reg rsi) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 6) };
    (@reg rdi) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 7) };
    (@reg r8) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 8) };
    (@reg r9) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 9) };
    (@reg r10) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 10) };
    (@reg r11) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 11) };
    (@reg r12) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 12) };
    (@reg r13) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 13) };
    (@reg r14) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 14) };
    (@reg r15) => { $crate::x64::ast::Reg::Gpr($crate::x64::Size::Quad, 15) };
}

pub use {internal_x64_instr, x64_operand, x64_template};
