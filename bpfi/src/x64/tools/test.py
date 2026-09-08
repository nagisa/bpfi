"""
Compile-time nature of this code makes it hard to test it using conventional means.

Doing an exhaustive space check by testing all different options is the best I could think of.

This means invoking nasm and rustc a crapton of times.
"""

from __future__ import annotations
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen
import xml.etree.ElementTree as ET
from typing import Iterator
import itertools
import tempfile
import shutil
import subprocess
from elftools.elf.elffile import ELFFile


def register_operands(*, allow_high8: bool = False) -> Iterator[tuple[str, str]]:
    low8 = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"]
    if allow_high8:
        low8 += ["ah", "ch", "dh", "bh"]
    low8 += [f"r{i}b" for i in range(8, 16)]

    word = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"] + [f"r{i}w" for i in range(8, 16)]
    dword = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"] + [f"r{i}d" for i in range(8, 16)]
    qword = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] + [f"r{i}" for i in range(8, 16)]

    for reg in low8:
        yield reg, reg
    for reg in word:
        yield reg, reg
    for reg in dword:
        yield reg, reg
    for reg in qword:
        yield reg, reg


def immediate_operands() -> Iterator[tuple[str, str]]:
    i8s = [-128, -1, 0, 1, 127]
    i16s = [-32768, -129, -1, 0, 1, 32767]
    i32s = [-2147483648, -32769, -129, -1, 0, 1, 128, 0x12345678]
    i64s = [0, 1, 0x7FFFFFFF, 0x80000000, 0x123456789ABCDEF0]

    for v in i8s:
        yield f"imm(i8({v}))", str(v)
    for v in i16s:
        yield f"imm(i16({v}))", str(v)
    for v in i32s:
        yield f"imm(i32({v}))", str(v)
    for v in i64s:
        yield f"imm(i64({v}))", str(v)

RUSTC = ["--edition=2024", "--crate-type", "bin", "-C", "embed-bitcode=no", "-C",
         "incremental=/home/nagisa/d/bpfi/target/debug/incremental", "-L",
         "dependency=/home/nagisa/d/bpfi/target/debug/deps",  "--extern",
         "bpfi=/home/nagisa/d/bpfi/target/debug/deps/libbpfi-569b046995ea4868.rlib",
         "--error-format", "json" ]

def test_rust(input: str) -> Option[bytes]:
    code = f"""
    #![no_main]
    pub const FOO: bpfi::template::Template = bpfi::x64::x64_template!({input});
    #[unsafe(link_section="len")]
    pub static LEN: u8 = FOO.len as u8;
    #[unsafe(link_section="code")]
    pub static CODE: [u8; 64] = FOO.bytes;
    """
    td_path = Path(TEMP)
    obj_path = td_path / "assembler"
    proc = subprocess.run(
        RUSTC + ["-", "--emit=obj", "-o", obj_path],
        input=code,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        return None

    try:
        with obj_path.open("rb") as f:
            elf = ELFFile(f)
            len = elf.get_section_by_name("len")
            code = elf.get_section_by_name("code")
            if len is None:
                return None
            if code is None:
                return None
            return code.data()[:len.data()[0]]
    except FileNotFoundError:
        return None




NASM = []
def test_nasm(input: str) -> Option[bytes]:
    td_path = Path(TEMP)
    asm_path = td_path / "test.asm"
    bin_path = td_path / "test.bin"
    asm_path.write_text(input, encoding="utf-8")
    proc = subprocess.run(
        NASM + ["-f", "bin", str(asm_path), "-o", str(bin_path), "--bits", "64"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        return None

    try:
        return bin_path.read_bytes()
    except FileNotFoundError:
        return None


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <x86reference.xml>", file=sys.stderr)
        return 2
    NASM.append(shutil.which("nasm"))
    if NASM[0] is None:
        print("need nasm")
        return None
    RUSTC.insert(0, shutil.which("rustc"))
    if RUSTC[0] is None:
        print("need rustc")
        return None

    xml_path = sys.argv[1]
    tree = ET.parse(xml_path)
    forms, prefixes = gen.parse_xml(tree.getroot())
    all_operands = list(register_operands())
    for form in sorted([form for forms in forms.values() for form in forms], key=lambda x: x.opcode):
        operands = [op for op in form.operands if op.displayed]
        for operand_count in range(0, len(operands) + 1):
            for ops in itertools.product(*([all_operands] * operand_count)):
                nasm = test_nasm(f"{form.mnemonic} {",".join(op[1] for op in ops)}")
                rust = test_rust(f"{form.mnemonic} {",".join(op[1] for op in ops)}")
                if nasm != rust:
                    print(f"FAULTY? {form.mnemonic} {",".join(op[1] for op in ops)} | {nasm} | {rust}")


    #




if __name__ == "__main__":

    with tempfile.TemporaryDirectory(prefix="bpfi-x64-test") as TEMP:
        sys.exit(main())
