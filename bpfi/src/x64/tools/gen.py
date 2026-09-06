#!/usr/bin/env python3

import os
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from collections import defaultdict
import textwrap

@dataclass
class XmlOperand:
    role: str
    a: str | None
    t: str | None

@dataclass
class Form:
    opcode: list[str]
    mnemonic: str
    operands: list[XmlOperand]

@dataclass
class Prefix:
    opcode: str

def rust_variant_name(mnemonic: str) -> str:
    s = mnemonic.strip().replace(" ", "_")
    result = "".join(part.capitalize() for part in s.split("_"))
    return f"_{result}" if result[0].isdigit() else result

def rust_size_from_t(t: str) -> str | None:
    return {"b": "Size::Byte", "w": "Size::Word", "d": "Size::Long", "q": "Size::Quad"}.get(t.lower())

def operand_patterns(op: XmlOperand) -> list[str]:
    a, t = (op.a or "").lower(), (op.t or "").lower()
    size = rust_size_from_t(t)

    if a in ("g", "r"):
        return [f"Operand::Reg(Reg::Gpr({size}, _))"] if size else ["Operand::Reg(_)"]
    if a == "e":
        return [f"Operand::Reg(Reg::Gpr({size}, _))", f"Operand::Mem({size}, _)"] if size else ["Operand::Reg(_)", "Operand::Mem(_, _)"]
    if a == "m":
        return [f"Operand::Mem({size}, _)"] if size else ["Operand::Mem(_, _)"]
    if a == "i":
        return ["Operand::Imm(_)"]
    if a == "j":
        return ["Operand::Rel(_)"]
    return ["_"]

def expand_operand_variants(form: Form) -> list[list[str]]:
    variants = [[]]
    for op in form.operands:
        next_variants = []
        for acc in variants:
            for pat in operand_patterns(op):
                next_variants.append(acc + [pat])
        variants = next_variants
    return variants or [[]]

def match_tuple(patterns: list[str]) -> str:
    match len(patterns):
        case 0: return "Operands::None"
        case 1: return f"Operands::One({patterns[0]})"
        case 2: return f"Operands::Two({patterns[0]}, {patterns[1]})"
        case 3: return f"Operands::Three({patterns[0]}, {patterns[1]}, {patterns[2]})"
        case _: return "_"

def parse_xml(root: ET.Element) -> tuple[dict[str, list[Form]], dict[str, Prefix]]:
    mnemonics = defaultdict(list)
    prefixes = {}
    is_rexlike = lambda mnem: mnem.text.startswith("REX")

    for section_name in ("one-byte", "two-byte"):
        section = root.find(section_name)
        if section is None: continue

        opcode_prefix = ["0F"] if section_name == "two-byte" else []

        for pri_opcd in section.findall("pri_opcd"):
            opcode = opcode_prefix + [pri_opcd.get("value", "").upper()]

            for entry in pri_opcd.findall("entry"):
                sec_opcd = entry.findall("sec_opcd")
                final_opcode = opcode + ([sec_opcd[0].text] if sec_opcd else [])

                is_prefix = any(g.text and "prefix" in g.text.strip().lower() for g in entry.findall("grp1"))
                if is_prefix:
                    for syntax in entry.findall("syntax"):
                        mnem = syntax.find("mnem")
                        if mnem is not None and mnem.text and not is_rexlike(mnem):
                            prefixes[mnem.text] = Prefix(opcode)
                    continue

                for syntax in entry.findall("syntax"):
                    mnem_node = syntax.find("mnem")
                    if mnem_node is None or not mnem_node.text or is_rexlike(mnem_node): continue
                    mnem = mnem_node.text.strip().lower()

                    operands = []
                    for role in ("dst", "src"):
                        for op_node in syntax.findall(role):
                            if op_node.get("displayed", "yes") == "no":
                                # implied inputs/outputs in instructions are displayed="no"
                                continue
                            a = op_node.find("a").text if op_node.find("a") is not None else None
                            t = op_node.find("t").text if op_node.find("t") is not None else None
                            operands.append(XmlOperand(role, a, t))

                    mnemonics[mnem].append(Form(
                        opcode=final_opcode, mnemonic=mnem, operands=operands
                    ))

    return mnemonics, prefixes

def gen_mnemonics(mnemonics: dict[str, list[Form]]) -> str:
    sorted_mnems = sorted(mnemonics.keys())
    enum_variants = [f"""
            {rust_variant_name(m)},""" for m in sorted_mnems]
    macro_arms = [f"""
            ({m}) => {{ $crate::x64::ast::Mnemonic::{rust_variant_name(m)} }};""" for m in sorted_mnems]

    return textwrap.dedent(f"""\
        #[derive(Clone, Copy)]
        pub enum Mnemonic {{
            {"".join(enum_variants)}
        }}

        #[macro_export]
        macro_rules! x64_mnemonic {{
            {"".join(macro_arms)}
            ($m:tt) => {{ compile_error!(concat!("unknown x64 instruction mnemonic: ", stringify!($m))) }};
        }}
        pub use x64_mnemonic;
    """)

def gen_prefixes(prefixes: dict[str, PrefixGroup]) -> str:
    macro_arms = []
    encode_arms = []
    for (name, info) in prefixes.items():
        macro_arms.append(f"""
             (@prefixes [$next: ident] [$($prefixes:ident),*] {name.lower()} $($rest:tt)*) => {{
                $crate::x64::ast::x64_prefixes!(@prefixes [$next] [$($prefixes,)* {rust_variant_name(name)}] $($rest)*)
             }};
        """)
        encode_arms.append(f"""
                    {rust_variant_name(name)} => Template::bytes(*{opcode_bytes_expr(info)}),""")

    return textwrap.dedent(f"""
        use crate::template::Template;

        #[derive(Clone, Copy)]
        pub enum Prefix {{ {", ".join(rust_variant_name(name) for name in prefixes.keys())} }}

        impl Prefix {{
            pub(crate) const fn encode(self) -> Template {{
                use Prefix::*;
                match self {{
                    {"".join(encode_arms)}
                }}
            }}
        }}

        #[macro_export]
        macro_rules! x64_prefixes {{
            ( $next:ident; $($tts:tt)* ) => {{
                $crate::x64::ast::x64_prefixes!( @prefixes [$next] [] $($tts)* )
            }};

            {"".join(macro_arms)}

            ( @prefixes [$next:ident] [$($prefixes:ident),*] $($rest:tt)*) => {{
                $crate::x64::ast::$next!( [$($prefixes),*]; $($rest)* )
            }};
        }}
        pub use x64_prefixes;
    """)


def opcode_bytes_expr(form: Form) -> str:
    return f"""b"{"".join(f'\\x{byte}' for byte in form.opcode)}" """


def form_match_arm(form: Form) -> str:
    op_patterns: list[str] = []
    guards: list[str] = []
    meta: list[dict[str, str]] = []

    if form.operands:
        return "" # for now skip anything with operands

    # for idx, op in enumerate(form.operands):
    #     pat, op_guards, m = emit_ast_operand_pattern(op, idx)
    #     op_patterns.append(pat)
    #     guards.extend(op_guards)
    #     meta.append(m)
    # guards = combine_size_constraints(meta, guards)
    # tuple_pat = operand_tuple_pattern(op_patterns)

    operand_pat = "Os::Z"
    opcode_expr = opcode_bytes_expr(form)
    guard_clause = ""
    sz_expr = "Sz::None"
    reg_expr = "None"
    rm_expr = "Erm::None"
    ext_expr = "None"
    tail = "None"
    # sz_expr, reg_expr, rm_expr, ext_expr = deduce_encoding_fields(form, meta)

    tail_expr = "None"
    # for m in meta:
    #     if "imm_var" in m:
    #         tail_expr = f'Some({m["imm_var"]})'
    #         break
    #     if "rel_var" in m:
    #         tail_expr = f'Some({m["rel_var"]})'
    #         break
    # guard_clause = ""
    # if guards:
    #     guard_clause = " if " + " && ".join(dict.fromkeys(guards))

            # {emit_operand_rebindings(len(form.operands))}
    return textwrap.indent(textwrap.dedent(f"""
        (M::{rust_variant_name(form.mnemonic)}, {operand_pat}){guard_clause} => {{
            Enc {{ op: {opcode_expr}, sz: {sz_expr}, rex_w: false, reg: {reg_expr}, rm: {rm_expr}, ext: {ext_expr}, tail: {tail_expr}, }}
        }},
    """), " " * 20)



def gen_encoder(forms: dict[str, list[Form]]) -> str:
    match_arms = []

    for form in sorted([form for forms in forms.values() for form in forms], key=lambda x: x.opcode):
        print(form)
        match_arms.append(form_match_arm(form))

    return textwrap.dedent(f"""\
        impl crate::x64::ast::Instruction {{
            pub const fn encoding(&self) -> crate::x64::Encoding {{
                use crate::x64::ast::{{Mnemonic as M, Operands as Os, Operand as O}};
                use crate::x64::{{Size as Sz, Encoding as Enc, EncodingRm as Erm}};

                match (self.mnemonic, self.operands) {{
                    {"".join(match_arms)}
                    (_, _) => panic!("unsupported instruction type"),
                }}
            }}
        }}
    """)

def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <x86reference.xml> <output_file.rs>", file=sys.stderr)
        return 2

    xml_path, out_file = sys.argv[1], sys.argv[2]
    tree = ET.parse(xml_path)
    mnemonics, prefixes = parse_xml(tree.getroot())

    os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join([
            "// AUTO-GENERATED BY generate_x86.py - DO NOT EDIT\n",
            gen_mnemonics(mnemonics),
            gen_prefixes(prefixes),
            gen_encoder(mnemonics)
        ]))

    return 0

if __name__ == "__main__":
    sys.exit(main())
