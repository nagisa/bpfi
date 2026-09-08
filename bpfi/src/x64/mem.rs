use super::Gpr;
use crate::{template::Template, x64::ast::Reg};

#[derive(Clone, Copy)]
pub struct Mem {
    pub(crate) base: Option<Reg>,
    pub(crate) index: Option<(Reg, u8)>,
    pub(crate) disp: Template,
}

impl Mem {
    const fn verify_reg_is_gpr(reg: Reg) -> Reg {
        match reg {
            Reg::Gpr(_, idx) => reg,
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
}
