pub use super::generated::{Mnemonic, Prefix, x64_mnemonic, x64_prefixes};
use super::{Gpr, Mem};
use crate::{template::Template, x64::Size};

#[derive(Clone, Copy)]
pub(super) struct Prefixes {
    pub lock: bool,
    pub rep: Option<RepPrefix>,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum RepPrefix {
    Rep,
    Repne,
}

impl Prefixes {
    pub const NONE: Self = Self {
        lock: false,
        rep: None,
    };
}

#[derive(Clone, Copy)]
pub(super) enum Reg {
    Gpr(Size, u8),
}

#[derive(Clone, Copy)]
pub(super) enum Operand {
    Reg(Reg),
    Imm(Template),
    Mem(Size, Mem),
    Rel(Template),
}

#[derive(Clone, Copy)]
pub(super) enum Operands {
    Z,
    A(Operand),
    B(Operand, Operand),
    C(Operand, Operand, Operand),
    D(Operand, Operand, Operand, Operand),
}

#[derive(Clone, Copy)]
pub(super) struct Instruction {
    pub prefixes: &'static [Prefix],
    pub mnemonic: Mnemonic,
    pub operands: Operands,
}

impl Instruction {
    pub const fn encode_prefixes(&self) -> Template {
        let mut i = 0;
        let mut out = Template::EMPTY;
        while i <self.prefixes.len() {
            out = out.merge(&self.prefixes[i].encode());
            i+= 1;
        }
        out
    }
    pub const fn encode(&self) -> Template {
        Template::merged([
            self.encode_prefixes(),
            self.encoding().encode(),
        ])
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
        Instruction {
            prefixes: &[$($crate::x64::ast::Prefix::$prefixes),*],
            mnemonic: $crate::x64::ast::x64_mnemonic!($mnemonic),
            operands: Operands::Z,
        }
    };
    ([$($prefixes:ident),*]; $mnemonic:ident $($rest:tt)+) => {
        $crate::x64::ast::internal_x64_instr!(@op1 [$($prefixes),*] [$mnemonic] [] $($rest)+)
    };

    (@op1 [$($prefixes:ident),*] [$mnemonic:ident] [$($cur:tt)*]) => {
        Instruction {
            prefixes: &[$($crate::x64::ast::Prefix::$prefixes),*],
            mnemonic: $crate::x64::ast::x64_mnemonic!($mnemonic),
            operands: Operands::A(x64_operand!($($cur)*)),
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
            operands: Operands::B(x64_operand!($($a)*), x64_operand!($($cur)*)),
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
            operands: Operands::C(x64_operand!($($a)*), x64_operand!($($b)*), x64_operand!($($cur)*)),
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
            operands: Operands::D(x64_operand!($($a)*), x64_operand!($($b)*), x64_operand!($($c)*), x64_operand!($($cur)*)),
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
        Operand::Reg(x64_operand!(@reg $reg))
    };

    ($value:literal) => {
        Operand::Imm($crate::x64::ast::ImmTemplate($value).template())
    };
    (imm8($value:literal)) => {
        Operand::Imm($crate::x64::ast::ImmTemplate::<i8>($value).template())
    };
    (imm8($value:expr)) => {
        Operand::Imm($value)
    };
    (imm16($value:literal)) => {
        Operand::Imm($crate::x64::ast::ImmTemplate::<i16>($value).template())
    };
    (imm16($value:expr)) => {
        Operand::Imm($value)
    };
    (imm32($value:literal)) => {
        Operand::Imm($crate::x64::ast::ImmTemplate::<i32>($value).template())
    };
    (imm32($value:expr)) => {
        Operand::Imm($value)
    };
    (imm64($value:literal)) => {
        Operand::Imm($crate::x64::ast::ImmTemplate::<i64>($value).template())
    };
    (imm64($value:expr)) => {
        Operand::Imm($value)
    };

    (rel8($value:literal)) => {
        Operand::Rel($crate::x64::ast::ImmTemplate::<i8>($value).template())
    };
    (rel8($value:expr)) => {
        Operand::Rel($value)
    };
    (rel16($value:literal)) => {
        Operand::Rel($crate::x64::ast::ImmTemplate::<i16>($value).template())
    };
    (rel16($value:expr)) => {
        Operand::Rel($value)
    };
    (rel32($value:literal)) => {
        Operand::Rel($crate::x64::ast::ImmTemplate::<i32>($value).template())
    };
    (rel32($value:expr)) => {
        Operand::Rel($value)
    };

    (byte ptr[$($mem:tt)+]) => {
        Operand::Mem(Size::Byte, x64_operand!(@mem [$($mem)+]))
    };
    (word ptr[$($mem:tt)+]) => {
        Operand::Mem(Size::Word, x64_operand!(@mem [$($mem)+]))
    };
    (dword ptr[$($mem:tt)+]) => {
        Operand::Mem(Size::Long, x64_operand!(@mem [$($mem)+]))
    };
    (qword ptr[$($mem:tt)+]) => {
        Operand::Mem(Size::Quad, x64_operand!(@mem [$($mem)+]))
    };

    (@mem [$($mem:tt)+]) => { x64_operand!(@mem_parse [base = None] [index = None] [scale = 1] [disp = Template::EMPTY] $($mem)+) };

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
            [base = $($base)*] [index = $($index)*] [scale = $scale] [disp = x64_operand!(@disp $disp)]
            $($($rest)+)?
        )
    };
    (@mem_parse
        [base = $($base:tt)*] [index = $($index:tt)*] [scale = $scale:expr] [disp = $old:expr]
        disp8($($disp:tt)+) $(+ $($rest:tt)+)?
    ) => {
        x64_operand!(@mem_parse
            [base = $($base)*] [index = $($index)*] [scale = $scale] [disp = x64_operand!(@disp disp8($($disp)+))]
            $($($rest)+)?
        )
    };
    (@mem_parse
        [base = $($base:tt)*] [index = $($index:tt)*] [scale = $scale:expr] [disp = $old:expr]
        disp32($($disp:tt)+) $(+ $($rest:tt)+)?
    ) => {
        x64_operand!(@mem_parse
            [base = $($base)*] [index = $($index)*] [scale = $scale] [disp = x64_operand!(@disp disp32($($disp)+))]
            $($($rest)+)?
        )
    };

    // Parse scale * index, or index * scale
    (@mem_parse
        [base = $($base:tt)*] [index = $($_:tt)*] [scale = $scale:expr] [disp = $disp:expr]
        $n:literal * $reg:tt $(($($ra:tt)+))? $(+ $($rest:tt)+)?
    ) => {
        x64_operand!(@mem_parse
            [base = $($base)*] [index = Some(x64_operand!(@reg $reg $(($($ra)+))?))] [scale = $n] [disp = $disp]
            $($($rest)+)?
        )
    };
    (@mem_parse
        [base = $($base:tt)*] [index = $($_:tt)*] [scale = $scale:expr] [disp = $disp:expr]
        $reg:tt $(($($ra:tt)+))? * $n:literal $(+ $($rest:tt)*)?
    ) => {
        x64_operand!(@mem_parse
            [base = $($base)*] [index = Some(x64_operand!(@reg $reg $(($($ra)+))?))] [scale = $n] [disp = $disp]
            $($($rest)+)?
        )
    };

    // The base register operand.
    (@mem_parse
        [base = $($_:tt)*] [index = $($index:tt)*] [scale = $scale:expr] [disp = $disp:expr]
        $reg:tt $(($($ra:tt)+))? $(+ $($rest:tt)+)?
    ) => {
        x64_operand!(@mem_parse
            [base = Some(x64_operand!(@reg $reg $(($($ra)+))?))] [index = $($index)*] [scale = $scale] [disp = $disp]
            $($($rest)+)?
        )
    };

    (@disp $value:literal) => {
        if let -128..128 = $value {
            x64_operand!(@disp disp8($value))
        } else {
            x64_operand!(@disp disp32($value))
        }
    };
    (@disp disp8($value:literal)) => { $crate::x64::ast::ImmTemplate::<i8>($value).template() };
    (@disp disp8($value:expr)) => { $value };
    (@disp disp32($value:literal)) => { $crate::x64::ast::ImmTemplate::<i32>($value).template() };
    (@disp disp32($value:expr)) => { $value };

    // https://censoredusername.github.io/dynasm-rs/language/langref_x64.html#register style
    // register definitions. These allow for parametric registers.
    (@reg Rb($id: expr)) => { Reg::Gpr(Size::Byte, $id) };
    (@reg Rw($id: expr)) => { Reg::Gpr(Size::Word, $id) };
    (@reg Rd($id: expr)) => { Reg::Gpr(Size::Long, $id) };
    (@reg Rq($id: expr)) => { Reg::Gpr(Size::Quad, $id) };

    (@reg al) => { Reg::Gpr(Size::Byte, 0) };
    (@reg cl) => { Reg::Gpr(Size::Byte, 1) };
    (@reg dl) => { Reg::Gpr(Size::Byte, 2) };
    (@reg bl) => { Reg::Gpr(Size::Byte, 3) };
    (@reg spl) => { Reg::Gpr(Size::Byte, 4) };
    (@reg bpl) => { Reg::Gpr(Size::Byte, 5) };
    (@reg sil) => { Reg::Gpr(Size::Byte, 6) };
    (@reg dil) => { Reg::Gpr(Size::Byte, 7) };
    (@reg r8b) => { Reg::Gpr(Size::Byte, 8) };
    (@reg r9b) => { Reg::Gpr(Size::Byte, 9) };
    (@reg r10b) => { Reg::Gpr(Size::Byte, 10) };
    (@reg r11b) => { Reg::Gpr(Size::Byte, 11) };
    (@reg r12b) => { Reg::Gpr(Size::Byte, 12) };
    (@reg r13b) => { Reg::Gpr(Size::Byte, 13) };
    (@reg r14b) => { Reg::Gpr(Size::Byte, 14) };
    (@reg r15b) => { Reg::Gpr(Size::Byte, 15) };

    (@reg ax) => { Reg::Gpr(Size::Word, 0) };
    (@reg cx) => { Reg::Gpr(Size::Word, 1) };
    (@reg dx) => { Reg::Gpr(Size::Word, 2) };
    (@reg bx) => { Reg::Gpr(Size::Word, 3) };
    (@reg sp) => { Reg::Gpr(Size::Word, 4) };
    (@reg bp) => { Reg::Gpr(Size::Word, 5) };
    (@reg si) => { Reg::Gpr(Size::Word, 6) };
    (@reg di) => { Reg::Gpr(Size::Word, 7) };
    (@reg r8w) => { Reg::Gpr(Size::Word, 8) };
    (@reg r9w) => { Reg::Gpr(Size::Word, 9) };
    (@reg r10w) => { Reg::Gpr(Size::Word, 10) };
    (@reg r11w) => { Reg::Gpr(Size::Word, 11) };
    (@reg r12w) => { Reg::Gpr(Size::Word, 12) };
    (@reg r13w) => { Reg::Gpr(Size::Word, 13) };
    (@reg r14w) => { Reg::Gpr(Size::Word, 14) };
    (@reg r15w) => { Reg::Gpr(Size::Word, 15) };

    (@reg eax) => { Reg::Gpr(Size::Long, 0) };
    (@reg ecx) => { Reg::Gpr(Size::Long, 1) };
    (@reg edx) => { Reg::Gpr(Size::Long, 2) };
    (@reg ebx) => { Reg::Gpr(Size::Long, 3) };
    (@reg esp) => { Reg::Gpr(Size::Long, 4) };
    (@reg ebp) => { Reg::Gpr(Size::Long, 5) };
    (@reg esi) => { Reg::Gpr(Size::Long, 6) };
    (@reg edi) => { Reg::Gpr(Size::Long, 7) };
    (@reg r8d) => { Reg::Gpr(Size::Long, 8) };
    (@reg r9d) => { Reg::Gpr(Size::Long, 9) };
    (@reg r10d) => { Reg::Gpr(Size::Long, 10) };
    (@reg r11d) => { Reg::Gpr(Size::Long, 11) };
    (@reg r12d) => { Reg::Gpr(Size::Long, 12) };
    (@reg r13d) => { Reg::Gpr(Size::Long, 13) };
    (@reg r14d) => { Reg::Gpr(Size::Long, 14) };
    (@reg r15d) => { Reg::Gpr(Size::Long, 15) };

    (@reg rax) => { Reg::Gpr(Size::Quad, 0) };
    (@reg rcx) => { Reg::Gpr(Size::Quad, 1) };
    (@reg rdx) => { Reg::Gpr(Size::Quad, 2) };
    (@reg rbx) => { Reg::Gpr(Size::Quad, 3) };
    (@reg rsp) => { Reg::Gpr(Size::Quad, 4) };
    (@reg rbp) => { Reg::Gpr(Size::Quad, 5) };
    (@reg rsi) => { Reg::Gpr(Size::Quad, 6) };
    (@reg rdi) => { Reg::Gpr(Size::Quad, 7) };
    (@reg r8) => { Reg::Gpr(Size::Quad, 8) };
    (@reg r9) => { Reg::Gpr(Size::Quad, 9) };
    (@reg r10) => { Reg::Gpr(Size::Quad, 10) };
    (@reg r11) => { Reg::Gpr(Size::Quad, 11) };
    (@reg r12) => { Reg::Gpr(Size::Quad, 12) };
    (@reg r13) => { Reg::Gpr(Size::Quad, 13) };
    (@reg r14) => { Reg::Gpr(Size::Quad, 14) };
    (@reg r15) => { Reg::Gpr(Size::Quad, 15) };
}

pub use {internal_x64_instr, x64_operand, x64_template};
