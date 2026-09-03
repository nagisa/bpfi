use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

#[derive(Copy, Clone)]
struct Opcode {
    function: &'static str,
    generic_opcode: bool,
    generic_src: bool,
    generic_dst: bool,
}

fn main() {
    let mut opcodes: [Option<Opcode>; 256] = [None; 256];

    opcodes[7] = Some(Opcode {
        function: "crate::generic_steps::step_add64_imm",
        generic_opcode: false,
        generic_dst: true,
        generic_src: false,
    });

    opcodes[87] = Some(Opcode {
        function: "crate::generic_steps::step_and64_imm",
        generic_opcode: false,
        generic_dst: true,
        generic_src: false,
    });

    opcodes[149] = Some(Opcode {
        function: "crate::generic_steps::step_exit",
        generic_opcode: false,
        generic_dst: false,
        generic_src: false,
    });

    opcodes[165] = Some(Opcode {
        function: "crate::generic_steps::step_jlt64_imm",
        generic_opcode: false,
        generic_dst: true,
        generic_src: false,
    });

    opcodes[191] = Some(Opcode {
        function: "crate::generic_steps::step_mov64_reg",
        generic_opcode: false,
        generic_dst: true,
        generic_src: true,
    });

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let ld_dest_path = Path::new(&out_dir).join("bpfi_rt.ld");
    let mut ld = BufWriter::new(File::create(&ld_dest_path).unwrap());
    let rs_dest_path = Path::new(&out_dir).join("monosteps.rs");
    let mut rs = BufWriter::new(File::create(&rs_dest_path).unwrap());

    let step_size = 64;
    writeln!(
        ld,
        r##"
        HANDLER_STRIDE = {step_size};
        TABLE_SIZE = 256*16*16*HANDLER_STRIDE;
        SECTIONS {{
            .bpfi_rt : {{
                PROVIDE(__bpfi_rt_start = .);
    "##
    )
    .expect("to write linker script successfully");

    for src in 0..11 {
        for dst in 0..11 {
            for (opcode, op_desc) in opcodes.iter().enumerate() {
                let Some(op_desc) = op_desc else {
                    continue;
                };
                if (!op_desc.generic_src && src != 0) || (!op_desc.generic_dst && dst != 0) {
                    continue;
                }
                writeln!(
                    rs,
                    r##"
                    #[unsafe(export_name = "s{opcode:03}.{dst:02}.{src:02}")]
                    #[unsafe(link_section = ".s.{opcode:03}.{dst:02}.{src:02}")]
                    pub unsafe extern "rust-preserve-none" fn s{opcode:03}_{dst:02}_{src:02}(i: *const u8, r: &mut crate::Registers, b: i64) -> crate::StepReturn {{
                    "##
                ).unwrap();
                write!(rs, r##"become {}::<"##, op_desc.function).unwrap();
                if op_desc.generic_opcode {
                    write!(rs, r##"{opcode},"##).unwrap();
                }
                if op_desc.generic_dst {
                    write!(rs, r##"{dst},"##).unwrap();
                }
                if op_desc.generic_src {
                    write!(rs, r##"{src}"##).unwrap();
                }
                writeln!(rs, ">(i, r, b); }}").unwrap();

                writeln!(
                    ld,
                    r##"
                        . = __bpfi_rt_steps_start + (256 * ({src} * 16 + {dst}) + {opcode}) * HANDLER_STRIDE;
                        KEEP(*(.s.{opcode:03}.{dst:02}.{src:02}));
                    "##
                ).unwrap();
            }
        }
    }

    writeln!(
        ld,
        r##"
                KEEP(*(SORT_BY_NAME(.s.*)))
                . = __bpfi_rt_start + TABLE_SIZE;
                PROVIDE(__bpfi_rt_end = .);
                KEEP(*(SORT_BY_NAME(.bpfi_rt.*)))
            }}
        }}
    "##
    )
    .expect("to write linker script successfully");

    println!("cargo:rustc-link-arg=-T{}", ld_dest_path.display());
    println!("cargo:rustc-link-arg=-Wl,-r");
    println!("cargo:rustc-link-arg=-Wl,-e,0");
    println!("cargo:rustc-link-arg=-Wl,-q");
    println!("cargo:rustc-link-arg=-Wl,-Map=/tmp/link_map.txt");
    println!("cargo:rustc-link-arg=-fuse-ld=lld");
}
