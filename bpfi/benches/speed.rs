#![feature(test)]

use bpfi_rt::{EntryFn, Registers};
use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget, elf};
extern crate test;

/// Loads the `.bpfi_rt` section into executable memory, applies static relocations,
/// and returns a function pointer to `bpfi_rt_enter`.
pub unsafe fn load_bpfi_rt(elf_bytes: &[u8]) -> Result<EntryFn, String> {
    let file = object::File::parse(elf_bytes).map_err(|e| format!("Failed to parse ELF: {e}"))?;

    let section = file
        .section_by_name(".bpfi_rt")
        .or_else(|| file.section_by_name("bpfi_rt"))
        .ok_or_else(|| "Section .bpfi_rt not found in ELF".to_string())?;

    let section_data = section.data().map_err(|e| e.to_string())?;
    let section_size = section_data.len();

    let mmap_ptr = libc::mmap(
        std::ptr::null_mut(),
        section_size,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_32BIT,
        -1,
        0,
    );
    if mmap_ptr == libc::MAP_FAILED {
        return Err("libc::mmap failed to allocate executable memory".to_string());
    }

    let base_ptr = mmap_ptr as *mut u8;

    std::ptr::copy_nonoverlapping(section_data.as_ptr(), base_ptr, section_size);

    for (rel_offset, reloc) in section.relocations() {
        let p_addr = (base_ptr as u64) + rel_offset;

        let symbol_addr = match reloc.target() {
            RelocationTarget::Symbol(sym_idx) => {
                let sym = file
                    .symbol_by_index(sym_idx)
                    .map_err(|_| "Symbol index out of bounds")?;

                (base_ptr as u64) + sym.address()
            }
            RelocationTarget::Absolute => 0,
            _ => return Err("Unsupported relocation target type".into()),
        };

        let a = reloc.addend();

        match reloc.flags() {
            object::RelocationFlags::Elf {
                r_type: elf::R_X86_64_PLT32,
            } => {
                let relative_offset = (symbol_addr as i64 + a - p_addr as i64) as i32;
                std::ptr::write_unaligned(p_addr as *mut i32, relative_offset);
            }

            object::RelocationFlags::Elf {
                r_type: elf::R_X86_64_32S,
            } => {
                let absolute_val = (symbol_addr as i64 + a) as i32;
                std::ptr::write_unaligned(p_addr as *mut i32, absolute_val);
            }

            unhandled => {
                return Err(format!("Unhandled relocation type: {unhandled:?}"));
            }
        }
    }

    let entry_sym = file
        .symbols()
        .find(|s| s.name() == Ok("bpfi_rt_enter"))
        .ok_or_else(|| "Entry symbol 'bpfi_rt_enter' not found".to_string())?;

    let entry_ptr = base_ptr.add(entry_sym.address() as usize);
    let entry_fn: EntryFn = std::mem::transmute(entry_ptr);

    Ok(entry_fn)
}

#[bench]
fn speed(bencher: &mut test::Bencher) {
    let data = include_bytes!("../../target/release/bpfi_rt");
    let entry = dbg!(unsafe { load_bpfi_rt(data).unwrap() });
    let bpf = [
        191, 33, 0, 0, 0, 0, 0, 0,
        87, 1, 0, 0, 255, 3, 0, 0,
        7, 2, 0, 0, 1, 0, 0, 0,
        165, 2, 252, 255, 0, 0, 32, 0,
        149, 0, 0, 0, 0, 0, 0, 0,
    ];
    // bencher.iter(|| {
    let mut duration = std::time::Duration::new(0, 0);
    for i in 0..200 {
        let mut registers: Registers = [0; 16];
        unsafe {
            let start = std::time::Instant::now();
            std::hint::black_box(entry(bpf.as_ptr(), &mut registers, 26214600));
            duration += start.elapsed();
        }
    }
    // });
    println!("{:?}", duration / 200);
}
