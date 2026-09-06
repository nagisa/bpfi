/// Placeholders that need to be filled into the template
#[derive(Debug, Clone, Copy)]
pub(crate) enum PlaceholderType {
    /// 16-bit signed eBPF offset field (`off`)
    Offset,
    /// 32-bit signed eBPF immediate field (`imm`)
    Imm,
    /// The imm field of the next eBPF instruction.
    ///
    /// Used for the 64-bit immediate instructions.
    NextImm,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Placeholder {
    location: usize,
    size: usize,
    r#type: PlaceholderType,
}

const MAX_TEMPLATE_SIZE: usize = 64;

/// Templates for representing a single "instruction" in machine code.
///
/// The instruction does not have to be strictly an eBPF instruction, these can also be pseudo
/// instructions such as CU accounting, or they can be supporting templates as well.
///
/// All of these functions must be `const fn` so that later a table of these templates can be built
/// up at bpfi's compile time.
///
/// Each template can have a number of placeholders that may need to be filled in.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Template {
    pub(crate) bytes: [u8; 64],
    pub(crate) len: usize,
    pub(crate) placeholders: [Placeholder; 4],
    pub(crate) placeholder_count: usize,
}

impl Template {
    pub const EMPTY: Self = Template {
        bytes: [0; _],
        len: 0,
        placeholders: [Placeholder {
            location: usize::MAX,
            size: usize::MAX,
            r#type: PlaceholderType::Offset,
        }; _],
        placeholder_count: 0,
    };

    pub(crate) const fn bytes<const N: usize>(bytes: [u8; N]) -> Self {
        let (mut i, mut new) = (0, Template::EMPTY);
        while i < N {
            new.bytes[i] = bytes[i];
            i += 1;
        }
        new.len = N;
        new
    }

    pub(crate) const fn value<const N: usize>(&self) -> Option<[u8; N]> {
        if self.placeholder_count > 0 || self.len != N {
            return None;
        }
        let (mut i, mut out) = (0, [0; N]);
        while i < N {
            out[i] = self.bytes[i];
            i += 1;
        }
        Some(out)
    }

    pub(crate) const fn placeholder(r#type: PlaceholderType, size: usize) -> Self {
        let mut new = Self::EMPTY;
        new.placeholders[0] = Placeholder {
            location: 0,
            size,
            r#type,
        };
        new.len = size;
        new.placeholder_count = 1;
        new
    }

    pub(crate) const fn assert_len(self, expected: usize) -> Self {
        if self.len == expected {
            self
        } else {
            panic!("template length is not as expected");
        }
    }

    pub(crate) const fn merge(mut self, other: &Self) -> Self {
        let mut i = 0;
        while i < other.placeholder_count {
            let mut placeholder = other.placeholders[i];
            placeholder.location += self.len;
            self.placeholders[self.placeholder_count + i] = placeholder;
            i += 1;
        }
        self.placeholder_count += other.placeholder_count;
        let mut i = 0;
        while i < other.len {
            self.bytes[self.len + i] = other.bytes[i];
            i += 1;
        }
        self.len += other.len;
        self
    }

    pub(crate) const fn merged<const N: usize>(templates: [Self; N]) -> Self {
        let mut out = Self::EMPTY;
        let mut i = 0;
        while i < N {
            out = out.merge(&templates[i]);
            i += 1;
        }
        out
    }

    // /// Produce a new template with placeholders for eBPF instruction populated.
    // pub(crate) const fn populate_ebpf_placeholders(mut self, off: i16, imm: i32) -> Self {
    //     let mut i = 0;
    //     let placeholder_count = self.placeholder_count;
    //     self.placeholder_count = 0;
    //     while i < placeholder_count {
    //         let Placeholder { location, r#type } = self.placeholders[i];
    //         match r#type {
    //             PlaceholderType::Offset => {
    //                 self.bytes[location] = off as u8;
    //                 self.bytes[location + 1] = (off >> 8) as u8;
    //             }
    //             PlaceholderType::Imm => {
    //                 self.bytes[location] = imm as u8;
    //                 self.bytes[location + 1] = (imm >> 8) as u8;
    //                 self.bytes[location + 2] = (imm >> 16) as u8;
    //                 self.bytes[location + 3] = (imm >> 24) as u8;
    //             }
    //             _ => {
    //                 self.placeholders[self.placeholder_count] = Placeholder { location, r#type };
    //                 self.placeholder_count += 1;
    //             }
    //         };
    //         i += 1;
    //     }
    //     self
    // }

    // /// Produce a new template with placeholders for next eBPF instruction populated.
    // pub(crate) const fn populate_next_ebpf_insn_placeholders(mut self, imm: i32) -> Self {
    //     let mut i = 0;
    //     let placeholder_count = self.placeholder_count;
    //     self.placeholder_count = 0;
    //     while i < placeholder_count {
    //         let Placeholder { location, r#type } = self.placeholders[i];
    //         match r#type {
    //             PlaceholderType::NextImm => {
    //                 self.bytes[location] = imm as u8;
    //                 self.bytes[location + 1] = (imm >> 8) as u8;
    //                 self.bytes[location + 2] = (imm >> 16) as u8;
    //                 self.bytes[location + 3] = (imm >> 24) as u8;
    //             }
    //             _ => {
    //                 self.placeholders[self.placeholder_count] = Placeholder { location, r#type };
    //                 self.placeholder_count += 1;
    //             }
    //         };
    //         i += 1;
    //     }
    //     self
    // }
}
