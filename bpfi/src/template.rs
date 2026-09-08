#[derive(Debug, Clone, Copy)]
pub struct Placeholder {
    pub location: usize,
    pub size: usize,
}

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
pub struct Template {
    // TODO: privatize
    pub bytes: [u8; 64],
    pub len: usize,
    pub placeholders: [Placeholder; 4],
    pub placeholder_count: usize,
}

impl Template {
    pub const EMPTY: Self = Template {
        bytes: [0; _],
        len: 0,
        placeholders: [Placeholder {
            location: usize::MAX,
            size: usize::MAX,
        }; _],
        placeholder_count: 0,
    };

    pub const fn bytes<const N: usize>(bytes: [u8; N]) -> Self {
        Self::from_slice(&bytes)
    }

    pub const fn from_slice(bytes: &[u8]) -> Self {
        let (mut i, mut new) = (0, Template::EMPTY);
        while i < bytes.len() {
            new.bytes[i] = bytes[i];
            i += 1;
        }
        new.len = bytes.len();
        new
    }


    pub const fn placeholder(size: usize) -> Self {
        let mut new = Self::EMPTY;
        new.placeholders[0] = Placeholder { location: 0, size };
        new.len = size;
        new.placeholder_count = 1;
        new
    }

    pub const fn merge(mut self, other: &Self) -> Self {
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

    pub const fn merged<const N: usize>(templates: [Self; N]) -> Self {
        let mut out = Self::EMPTY;
        let mut i = 0;
        while i < N {
            out = out.merge(&templates[i]);
            i += 1;
        }
        out
    }

    pub const fn assert_len(self, expected: usize) -> Self {
        if self.len == expected {
            self
        } else {
            panic!("template length is not as expected");
        }
    }

    /// Returns the buffer, but only if all the placeholders are resolved.
    pub const fn buffer<const N: usize>(&self) -> Option<[u8; N]> {
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

    /// Is the template (if interpreted as a number of any usual size) this value?
    pub const fn is_le_int(&self, expected: i64) -> bool {
        if self.placeholder_count > 0 {
            return false;
        }
        match (self.len, &self.bytes) {
            (1, &[b, ..]) => b as i8 == expected as i8,
            (2, &[b1, b2, ..]) => i16::from_le_bytes([b1, b2]) == expected as i16,
            (4, &[b1, b2, b3, b4, ..]) => i32::from_le_bytes([b1, b2, b3, b4]) == expected as i32,
            (8, &[b1, b2, b3, b4, b5, b6, b7, b8, ..]) => {
                i64::from_le_bytes([b1, b2, b3, b4, b5, b6, b7, b8]) == expected as i64
            }
            _ => false,
        }
    }
}
