use bpfi::template::Template;

pub(crate) const fn interpreter_step() -> Template {
    let placeholder = Template::placeholder(1);
    let register = 5;
    let number = Template::placeholder(4);

    bpfi::x64::x64_template! {
        ; add al, spl
        ; add al, r8b
        ; hlt
        ; retn
        ; lock repnz retn
        ; lock repne retn
        ; add rax, 32i32
        ; add rax, 32i32
        ; add Rd(register), imm(number)
        ; js rel(-8i32)
        ; jo rel(placeholder)
        ; movbe eax, dword [ Rq(register) + rax * 8 + 32i8 ]
        ; movbe eax, dword [ ecx * 8 + 32i32 ]
        ; crc32 eax, bx
    }
}

fn main() {
    let tpl = interpreter_step();

    for byte in &tpl.bytes[..tpl.len] {
        print!("{:02X?}", byte);
    }
    println!();
}
