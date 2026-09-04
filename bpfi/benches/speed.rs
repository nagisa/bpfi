#![feature(test)]
extern crate test;

#[bench]
fn speed(bencher: &mut test::Bencher) {
    let data = include_bytes!("../../target/release/bpfi_rt");
    let interp = unsafe { bpfi::load_bpfi_rt(data, &[7, 87, 149, 165, 191]).unwrap() };
    let bpf = [
        191, 33, 0, 0, 0, 0, 0, 0, 87, 1, 0, 0, 255, 3, 0, 0, 7, 2, 0, 0, 1, 0, 0, 0, 165, 2, 252,
        255, 0, 0, 32, 0, 149, 0, 0, 0, 0, 0, 0, 0,
    ];
    // bencher.iter(|| {
    let mut duration = std::time::Duration::new(0, 0);
    for i in 0..200 {
        let mut registers: bpfi_rt::Registers = [0; 16];
        unsafe {
            let start = std::time::Instant::now();
            std::hint::black_box((interp.enter_fn)(bpf.as_ptr(), &mut registers, 26214600));
            duration += start.elapsed();
        }
    }
    // });
    println!("{:?}", duration / 200);
}
