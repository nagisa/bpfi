use super::Gpr;
use crate::{template::Template, x64::ast::Reg};

#[derive(Clone, Copy)]
pub struct Mem {
    // TODO: this can be plain Gpr after validation of inputs...
    pub(crate) base: Option<Gpr>,
    pub(crate) index: Option<(Gpr, u8)>,
    pub(crate) disp: Template,
}

impl Mem {
    const fn verify_reg_is_gpr(reg: Reg) -> Gpr {
        match reg {
            Reg::Gpr(_, idx) => Gpr(idx),
            // _ => panic!("memory reference registers must be in GPR class"),
        }
    }
    const fn verify_disp_template(disp: &Template) {
        if !(disp.len == 0 || disp.len == 1 || disp.len == 4) {
            panic!("mem displacement must be 0, 1 or 4 bytes");
        }
    }

    const fn verify_scale_index(scale: u8, index: Gpr) {
        if let Gpr::RSP = index {
            panic!("index register may not be RSP")
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

    pub const fn encode(&self, other_op_bits: u8) -> Template {
        const fn calc_mod(base: Gpr, disp: &Template) -> u8 {
            match disp.len {
                0 if (base.0 & 7) != 5 => 0x00,
                1 => 0x40,
                _ => 0x80,
            }
        }
        match (self.base, self.index) {
            (Some(base), Some((index, scale))) => {
                let sib = (scale as u8) << 6 | (index.0 & 7) << 3 | base.0 & 7;
                let modrm = calc_mod(base, &self.disp) | other_op_bits | 4 /* SIB encoding */;
                Template::bytes([modrm, sib]).merge(&self.disp)
            }
            // base = RSP/R12 require SIB byte
            (Some(base), None) if (base.0 & 7) == 4 => {
                let modrm = calc_mod(base, &self.disp) | other_op_bits | 4 /* SIB encoding */;
                Template::bytes([modrm, 0x24]).merge(&self.disp)
            }
            (Some(base), None) => {
                let modrm = calc_mod(base, &self.disp) | other_op_bits;
                Template::bytes([modrm]).merge(&self.disp)
            }
            (None, Some((index, scale))) => {
                let index_code = (index.0 & 7) << 3;
                let scale_bits = (scale as u8) << 6;
                let sib_byte = scale_bits | index_code | 0b101; // Base = 5 (no base)
                Template::bytes([0x00 | other_op_bits | 4, sib_byte]).merge(&self.disp)
            }
            (None, None) => panic!("Mem operand must have a base or an index"),
        }
    }
}
