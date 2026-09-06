mod template;
mod x64;

fn main() {
    let tpl = x64::interpreter_step();

    for byte in &tpl.bytes[..tpl.len] {
        print!("{:02X?}", byte);
    }
    println!();

    // let mut buffer = [0; 1024];
    // let mut interpreter = bpfi::x64::InterpreterAssembly {
    //     out: SliceAssembler::new(&mut buffer, 0x10_0000),
    // };

    // add64_imm::<0>(&mut interpreter);
    // add64_imm::<1>(&mut interpreter);
    // add64_imm::<2>(&mut interpreter);
    // and64_imm::<0>(&mut interpreter);
    // and64_imm::<1>(&mut interpreter);
    // and64_imm::<2>(&mut interpreter);
    // jlt64_imm::<0>(&mut interpreter);
    // jlt64_imm::<1>(&mut interpreter);
    // jlt64_imm::<2>(&mut interpreter);

    // interpreter.out.commit().unwrap();
    // std::fs::write("interpreter.bin", buffer).unwrap();

    // let interp = unsafe { bpfi::load_bpfi_rt(&[7, 87, 149, 165, 191]).unwrap() };
    // let bpf = [
    //     191, 33, 0, 0, 0, 0, 0, 0, 87, 1, 0, 0, 255, 3, 0, 0, 7, 2, 0, 0, 1, 0, 0, 0, 165, 2, 252,
    //     255, 0, 0, 32, 0, 149, 0, 0, 0, 0, 0, 0, 0,
    // ];
    // let mut duration = std::time::Duration::new(0, 0);
    // let iters = 5;
    // for i in 0..iters {
    //     let mut registers: bpfi_rt::Registers = [0; _];
    //     unsafe {
    //         let start = std::time::Instant::now();
    //         std::hint::black_box((interp.enter_fn)(bpf.as_ptr(), &mut registers, 26214600));
    //         duration += start.elapsed();
    //     }
    // }
    // println!("{:?}", duration / iters);
}
