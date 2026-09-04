use bpfi_rt::{EntryFn, Registers};
use object::{
    Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionIndex, SymbolIndex, elf,
};
use std::collections::{HashMap, VecDeque};

const STEP_STRIDE: usize = 64;
const TOTAL_SLOTS: usize = u16::MAX as usize;
const DISPATCH_TABLE_SIZE: usize = TOTAL_SLOTS * STEP_STRIDE;
const SUPPORT_CODE_SPACE: usize = 4 * 1024 * 1024;

static RT_BIN: &'static [u8] = include_bytes!(env!("BPFI_RT_IMG"));

const INT3_TRAP: u8 = 0xCC; // x86_64 int3 trap opcode for padding

pub struct LoadedRt {
    pub base_ptr: *mut u8,
    pub total_size: usize,
    pub enter_fn: EntryFn,
}

impl LoadedRt {
    /// Gets a function pointer to a specific step handler slot
    pub unsafe fn get_step<F>(&self, opcode: u8, dst: u8, src: u8) -> F {
        let idx = ((opcode as usize) << 8) | ((dst as usize) << 4) | (src as usize);
        let ptr = self.base_ptr.add(idx * STEP_STRIDE);
        std::mem::transmute_copy(&ptr)
    }
}

impl Drop for LoadedRt {
    fn drop(&mut self) {
        if !self.base_ptr.is_null() {
            unsafe {
                libc::munmap(self.base_ptr as *mut libc::c_void, self.total_size);
            }
        }
    }
}

struct RelocSite {
    patch_vaddr: u64,
    target_sym_idx: SymbolIndex,
    reloc_flags: object::RelocationFlags,
    addend: i64,
}

pub unsafe fn load_bpfi_rt(supported_opcodes: &[u8]) -> Result<LoadedRt, String> {
    let file = object::File::parse(RT_BIN).map_err(|e| format!("Failed to parse ELF: {e}"))?;

    let mmap_size = DISPATCH_TABLE_SIZE + SUPPORT_CODE_SPACE;

    let mmap_ptr = libc::mmap(
        std::ptr::null_mut(),
        mmap_size,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_32BIT,
        -1,
        0,
    );
    if mmap_ptr == libc::MAP_FAILED {
        return Err("libc::mmap with MAP_32BIT failed".to_string());
    }
    let base_ptr = mmap_ptr as *mut u8;
    std::ptr::write_bytes(base_ptr, INT3_TRAP, DISPATCH_TABLE_SIZE);

    // TODO: build a nicer map of available sections here. Might need e.g. for relocation lookup.
    let mut step_sections: HashMap<(u8, u8, u8), SectionIndex> = HashMap::new();
    let mut sigill_sec_idx: Option<SectionIndex> = None;
    let mut enter_sec_idx: Option<SectionIndex> = None;

    for sec in file.sections() {
        if let Ok(name) = sec.name() {
            if name == ".rt.sigill" {
                sigill_sec_idx = Some(sec.index());
            } else if name == ".rt.enter" {
                enter_sec_idx = Some(sec.index());
            } else if let Some((op, dst, src)) = parse_step_name(name) {
                step_sections.insert((op, dst, src), sec.index());
            }
        }
    }

    let mut opcode_enabled = [false; 256];
    for &op in supported_opcodes {
        opcode_enabled[op as usize] = true;
    }

    let mut reloc_sites: Vec<RelocSite> = Vec::new();
    let mut pending_support_queue: VecDeque<SectionIndex> = VecDeque::new();
    pending_support_queue.push_back(enter_sec_idx.ok_or("rt does not have .rt.enter section")?);

    for slot_idx in 0..TOTAL_SLOTS {
        let opcode = slot_idx as u8;
        let dstsrc = slot_idx >> 8;
        let src = (dstsrc >> 4) as u8;
        let dst = (dstsrc & 0x0F) as u8;

        // FIXME: quick hack for now to allow selecting what to load. In complete implementation
        // the implementations for each slot would be determined based on some sort of configuration
        // object perhaps that allows enabling, disabling and selecting specific implementations to
        // load. In particular we might be interested in being able to switch between
        // implementations that trace execution and those that just go as fast as possible.
        let target_sec_idx = if opcode_enabled[opcode as usize] {
            step_sections
                .get(&(opcode, dst, src))
                .copied()
                .or(sigill_sec_idx)
        } else {
            sigill_sec_idx
        };

        if let Some(sec_idx) = target_sec_idx {
            let sec = file
                .section_by_index(sec_idx)
                .map_err(|_| "Invalid section index")?;
            let data = sec.data().map_err(|e| e.to_string())?;

            if data.len() > STEP_STRIDE {
                return Err(format!("Section exceeds 64-byte stride ({})", data.len()));
            }

            let slot_vaddr = (base_ptr as u64) + (slot_idx * STEP_STRIDE) as u64;

            std::ptr::copy_nonoverlapping(data.as_ptr(), slot_vaddr as *mut u8, data.len());

            for (rel_offset, reloc) in sec.relocations() {
                if let RelocationTarget::Symbol(sym_idx) = reloc.target() {
                    reloc_sites.push(RelocSite {
                        patch_vaddr: slot_vaddr + rel_offset,
                        target_sym_idx: sym_idx,
                        reloc_flags: reloc.flags(),
                        addend: reloc.addend(),
                    });

                    if let Ok(sym) = file.symbol_by_index(sym_idx) {
                        if let Some(supp_sec_idx) = sym.section_index() {
                            pending_support_queue.push_back(supp_sec_idx);
                        }
                    }
                }
            }
        }
    }

    let mut heap_offset = DISPATCH_TABLE_SIZE;
    let mut loaded_support_sections: HashMap<SectionIndex, u64> = HashMap::new();

    while let Some(sec_idx) = pending_support_queue.pop_front() {
        if loaded_support_sections.contains_key(&sec_idx) {
            continue;
        }

        let sec = file
            .section_by_index(sec_idx)
            .map_err(|_| "Invalid section index")?;
        let data = sec.data().map_err(|e| e.to_string())?;

        let align = sec.align().max(8) as usize;
        heap_offset = (heap_offset + align - 1) & !(align - 1);

        if heap_offset + data.len() > mmap_size {
            return Err("Secondary heap overflow for supporting .rt sections".to_string());
        }

        let dest_vaddr = (base_ptr as u64) + heap_offset as u64;
        std::ptr::copy_nonoverlapping(data.as_ptr(), dest_vaddr as *mut u8, data.len());

        heap_offset += data.len();
        loaded_support_sections.insert(sec_idx, dest_vaddr);

        for (rel_offset, reloc) in sec.relocations() {
            if let RelocationTarget::Symbol(sym_idx) = reloc.target() {
                reloc_sites.push(RelocSite {
                    patch_vaddr: dest_vaddr + rel_offset,
                    target_sym_idx: sym_idx,
                    reloc_flags: reloc.flags(),
                    addend: reloc.addend(),
                });

                if let Ok(sym) = file.symbol_by_index(sym_idx) {
                    if let Some(next_sec_idx) = sym.section_index() {
                        if !loaded_support_sections.contains_key(&next_sec_idx) {
                            pending_support_queue.push_back(next_sec_idx);
                        }
                    }
                }
            }
        }
    }

    for site in reloc_sites {
        let p_addr = site.patch_vaddr;
        let sym = file
            .symbol_by_index(site.target_sym_idx)
            .map_err(|_| "Symbol resolution error")?;
        let sym_name = sym.name().unwrap_or("");

        let symbol_addr = if sym_name == ".ibase" {
            // .ibase is provided by the loader here...
            base_ptr as u64
        } else if let Some(sec_idx) = sym.section_index() {
            if let Some(&supp_vaddr) = loaded_support_sections.get(&sec_idx) {
                supp_vaddr + sym.address()
            } else {
                return Err(format!("Symbol '{sym_name}' in unmapped section"));
            }
        } else {
            sym.address()
        };

        let a = site.addend;

        match site.reloc_flags {
            object::RelocationFlags::Elf {
                r_type: elf::R_X86_64_PLT32 | elf::R_X86_64_PC32,
            } => {
                let rel_val = (symbol_addr as i64 + a - p_addr as i64) as i32;
                std::ptr::write_unaligned((p_addr as *mut i32), rel_val);
            }
            object::RelocationFlags::Elf {
                r_type: elf::R_X86_64_32S,
            } => {
                let abs_val = (symbol_addr as i64 + a) as i32;
                std::ptr::write_unaligned((p_addr as *mut i32), abs_val);
            }
            object::RelocationFlags::Elf {
                r_type: elf::R_X86_64_64,
            } => {
                let abs_val = (symbol_addr as i64 + a) as u64;
                std::ptr::write_unaligned((p_addr as *mut u64), abs_val);
            }
            unhandled => return Err(format!("Unhandled relocation type: {unhandled:?}")),
        }
    }

    let enter_sym = file
        .symbols()
        .find(|s| s.name() == Ok("bpfi_rt_enter"))
        .ok_or_else(|| "Symbol 'bpfi_rt_enter' not found".to_string())?;

    let enter_vaddr = if let Some(sec_idx) = enter_sym.section_index() {
        let sec_vaddr = loaded_support_sections
            .get(&sec_idx)
            .ok_or_else(|| "Section for 'bpfi_rt_enter' was not loaded".to_string())?;
        sec_vaddr + enter_sym.address()
    } else {
        enter_sym.address()
    };

    let enter_fn: EntryFn = std::mem::transmute(enter_vaddr as *const ());

    Ok(LoadedRt {
        base_ptr,
        total_size: heap_offset,
        enter_fn,
    })
}

fn parse_step_name(sec_name: &str) -> Option<(u8, u8, u8)> {
    let parts: Vec<&str> = sec_name.split('.').collect();
    match parts.as_slice() {
        ["", "rt", op, dst, src] => {
            let opcode = parse_u8(op)?;
            let dst_reg = parse_u8(dst)?;
            let src_reg = parse_u8(src)?;
            Some((opcode, dst_reg, src_reg))
        }
        _ => None,
    }
}

fn parse_u8(s: &str) -> Option<u8> {
    parse_num(s).and_then(|v| u8::try_from(v).ok())
}

fn parse_num(s: &str) -> Option<usize> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<usize>().ok()
    }
}
