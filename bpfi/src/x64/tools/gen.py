#!/usr/bin/env python3

import os
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, replace
from collections import defaultdict
import textwrap
import itertools

@dataclass
class XmlOperand:
    role: str
    a: Optional[str] = None         # Addressing method code (e.g. "G", "E", "I", "Z")
    t: Optional[str] = None         # Operand type code (e.g. "b", "v", "vqp")
    group: Optional[str] = None     # e.g. "gen", "seg", "ctrl"
    nr: Optional[str] = None        # Register number (0-15)
    displayed: bool = True          # Is this operand explicitly written in assembly syntax?
    text: Optional[str] = None      # Inner text representing a constant register?

@dataclass
class Form:
    pref: list[str]
    opcode: list[str]
    mnemonic: str
    operands: list[XmlOperand]
    modrm_r: bool = False              # entry@r == "yes"  => /r form
    opcd_ext: Optional[int] = None     # entry/opcd_ext    => /0../7
    direction: Optional[int] = None    # entry@direction   => d bit present/fixed here
    sign_ext: Optional[int] = None     # entry@sign-ext
    op_size: Optional[int] = None      # entry@op_size     => w bit present/fixed here
    mod: Optional[str] = None          # entry@mod or syntax@mod
    attr: Optional[str] = None         # entry@attr

@dataclass
class Prefix:
    opcode: str

def rust_variant_name(mnemonic: str) -> str:
    s = mnemonic.strip().replace(" ", "_")
    result = "".join(part.capitalize() for part in s.split("_"))
    return f"_{result}" if result[0].isdigit() else result

def is_rexlike(mnem: ET.Element):
    return mnem.text.startswith("REX")

def parse_syntax(syntax_node: ET.Element):
    mnem = None
    operands = []

    for child in syntax_node:
        match child.tag:
            case "mnem":
                text = (child.text or "").strip().lower()
                if not text or is_rexlike(child):
                    break
                mnem = text

            case "dst" | "src":
                # Extract attributes
                displayed = child.get("displayed", "yes") != "no"
                group = child.get("group")
                nr = child.get("nr")

                # Addressing method (a) and type (t) can be elements or attributes
                a_node = child.find("a")
                t_node = child.find("t")

                a = a_node.text if a_node is not None else child.get("address")
                t = t_node.text if t_node is not None else child.get("type")
                text = child.text.strip() if child.text and child.text.strip() else None

                operands.append(XmlOperand(
                    role=child.tag,
                    a=a,
                    t=t,
                    group=group,
                    nr=nr,
                    displayed=displayed,
                    text=text
                ))

    if not mnem:
        return None, [], None

    return mnem, operands, syntax_node.get("mod")

def parse_xml(root: ET.Element) -> tuple[dict[str, list[Form]], dict[str, Prefix]]:
    mnemonics = defaultdict(list)
    prefixes = {}
    for section_name in ("one-byte", "two-byte"):
        section = root.find(section_name)
        if section is None: continue


        opcode_prefix = ["0F"] if section_name == "two-byte" else []

        for pri_opcd in section.findall("pri_opcd"):
            opcode = opcode_prefix + [pri_opcd.get("value", "").upper()]

            entries = pri_opcd.findall("entry")
            e_entries = [e for e in entries]
            selected_entries = e_entries if e_entries else entries
            invalid_in_64_bit = any(entry.get("attr") == "invd" for entry in selected_entries)

            for entry in selected_entries:
                sec_opcd = entry.findall("sec_opcd")
                pref = [pref.text for pref in entry.findall("pref")]
                final_opcode = opcode + ([sec_opcd[0].text] if sec_opcd else [])


                is_prefix = any(g.text and "prefix" in g.text.strip().lower() for g in entry.findall("grp1"))
                if is_prefix:
                    for syntax in entry.findall("syntax"):
                        mnem = syntax.find("mnem")
                        if mnem is not None and mnem.text and not is_rexlike(mnem):
                            prefixes[mnem.text] = Prefix(opcode)
                    continue

                for syntax in entry.findall("syntax"):
                    mnem, operands, syntax_mod = parse_syntax(syntax)
                    if mnem and not invalid_in_64_bit:
                        opcd_ext_node = entry.find("opcd_ext")
                        mnemonics[mnem].append(Form(
                            pref=pref,
                            opcode=final_opcode,
                            mnemonic=mnem,
                            operands=operands,
                            modrm_r=(entry.get("r") == "yes"),
                            opcd_ext=(int(opcd_ext_node.text, 16) if opcd_ext_node is not None else None),
                            direction=(int(entry.get("direction")) if entry.get("direction") is not None else None),
                            sign_ext=(int(entry.get("sign-ext")) if entry.get("sign-ext") is not None else None),
                            op_size=(int(entry.get("op_size")) if entry.get("op_size") is not None else None),
                            mod=(syntax_mod or entry.get("mod")),
                            attr=entry.get("attr"),
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
                    {rust_variant_name(name)} => Template::bytes(*{bytes_expr(info.opcode)}),""")

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


def bytes_expr(hexes: list[str]) -> str:
    return f"""b"{"".join(f'\\x{byte}' for byte in hexes)}" """

def operand_implies_operand_size(o: XmlOperand) -> bool:
    return o.t in ["ptp", "p", "v", "vds", "vq", "vqp", "vs"]

def operand_sz_pattern(o: XmlOperand) -> str:
    match o.t:
        case "b" | "bs" | "bss": return "Sz::Byte"
        case "w" | "wi" | "wo": return "Sz::Word"
        case "d" | "di" | "ds" | "da" | "do" | "sr": return "Sz::Long"
        case "q" | "qi" | "qp" | "psq" | "dr" | "pi" | "qa" | "qs": return "Sz::Quad"
        case "v" | "vs" | "vds": return "Sz::Word | Sz::Long"
        case "vqp" | "ptp": return "Sz::Word | Sz::Long | Sz::Quad"
        case "dqa" | "dqp": return "Sz::Long | Sz::Quad"
        case "vq": return "Sz::Word | Sz::Quad"
        case "ps" | "pd" | "dq": return "Sz::Octw"
        # Weird cases that don't need syntactic or encoding annotation
        case None | "stx" | "e" | "er" | "bcd" | "st" | "s": return "Sz::None"
        case "sd" | "ss" | "ws" | "va" | "wa" : return "Sz::None"
        case _: assert False, f"{o.t} size code not handled"

@dataclass
class EncoderArmContext:
    form: Form

    # The authoritative instruction operand-size.
    insn_size: str | None = None
    # expressions for each operand's size
    size_exprs: [(str, int)] = field(default_factory=list)
    size_authority: str | None = None

    rex_w: bool = False
    reg_expr: str | None = None
    tail_vars: [str] = field(default_factory=list)
    rm_variant: str | None = None
    guards: list[str] = field(default_factory=list)
    operand_patterns: list[str] = field(default_factory=list)
    variable_count: int = 0

    def new_var(self) -> str:
        """Allocates a unique variable name (e.g., r0, rm_op1, imm0)."""
        var_name = f"_{self.variable_count}"
        self.variable_count += 1
        return var_name

    def register_name_filter(self, reg: str | None) -> None | (str, int):
        if not isinstance(reg, str):
            return None

        if "XMM" in reg or "MMX" in reg:
            # TODO: unimplemented yet
            return None

        names = ["AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"] + [str(i) for i in range(8, 16)]
        bytenames = ["AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"]
        try:
            return ("Sz::Byte", bytenames.index(reg))
        except:
            pass
        name_match = [i for i, n in enumerate(names) if reg.endswith(n)]
        if name_match:
            match reg[0]:
                case "E": pat = "Sz::Long"
                case "e": pat = "Sz::Word | Sz::Long"
                case "R": pat = "Sz::Quad"
                case "r": pat = "Sz::Word | Sz::Long | Sz::Quad"
                case _ if reg == names[name_match[0]]: pat = "Sz::Word"
            return (pat, name_match[0])

    def determine_static_insn_size(self):
        if not self.form.operands:
            return self.set_insn_size("Sz::None")

        # First, only select operands that can imply an operand size
        opsize_operands = [(i, o) for i, o in enumerate(self.form.operands) if operand_implies_operand_size(o)]
        # We want to first select the register operand, if there is one (and first the one that
        # goes into the reg field) and only then go for memory, immediates etc.
        def take(seq, pred):
            taken = [x for x in seq if pred(*x)]
            seq[:] = [x for x in seq if not pred(*x)]
            return taken

        # don't consider operands that can't be specified in the syntax. This only concerns enter,
        # leave, int (3/Ib) and icebp, none of which need any size specific handling anyway.
        take(opsize_operands, lambda i, o: not o.displayed)

        candidates = take(opsize_operands, lambda i, o: o.a in ["G", "Z"]) + \
            take(opsize_operands, lambda i, o: o.a in ["R", "H"]) + \
            take(opsize_operands, lambda i, o: o.group == "gen") + \
            take(opsize_operands, lambda i, o: o.a in ["EM", "M"]) + \
            take(opsize_operands, lambda i, o: o.a in ["I", "A", "J", "O"]) + \
            take(opsize_operands, lambda i, o: o.a == "X") + \
            take(opsize_operands, lambda i, o: o.a == "Y") + \
            opsize_operands

        if candidates:
            self.size_authority = candidates[0][0]
            return

        # consider cases like crc32, movsxd that only have one variable-sized operand
        # (generally Gdqp.) crc32 specifically is a good example of why dqp-likes must be explored
        # separately.
        non_static_ops = [i for i, op in enumerate(self.form.operands) if op.displayed and "|" in operand_sz_pattern(op)]
        assert len(non_static_ops) < 2 or self.form.mnemonic == "movnti", "double check if newly found form is correct for assumptions here"
        if non_static_ops:
            self.size_authority = non_static_ops[0]


    def set_insn_size(self, to):
        self.insn_size = to

    def add_operand(self, op_index, op):
        # For now we don't support any of these constructs
        if op.group == "x87fpu":
            nr = op.nr if op.nr is not None else "_"
            return None # f"Operand::Reg(Reg::X87({nr}))"
        if op.group == "seg":
            return None # "Operand::Reg(Reg::Seg(_))"
        if op.group == "ctrl" or op.group == "msr":
            return None

        if op_index == self.size_authority:
            size = "sz"
            self.set_insn_size(size) # may be overwritten by certain branches
        else:
            size = self.new_var()

        match op.a:
            case "I" | "A" | "J":
                imm = self.new_var()
                self.tail_vars.append(imm)
                pat = f"O::Rel({imm})" if op.a == "J" else f"O::Imm({imm})"
                if op_index == self.size_authority:
                    # This is one of the variable-sized `op imm` encodings. We have to determine
                    # the opcode size from the immediate template length.
                    self.set_insn_size(f"Sz::from_len({imm}.len)")
                    sz_pat = operand_sz_pattern(op)
                    return (pat, f"matches!({self.insn_size}, {sz_pat})")
                try:
                    # variants with a constant immediate value
                    # this an example where templating might not work quite right. We can only
                    # select CC encoding for int 3 here if we know that the operand is statically
                    # 3 and not a placeholder output later.
                    out = (pat, f"{imm}.is_le_int({int(op.text)})")
                    return out
                except:
                    pass
                if operand_implies_operand_size(op):
                    assert self.insn_size == "sz", f"{self.form}"
                    return (pat, f"Sz::from_{op.t}({imm}.len).cmp(&sz) <= 0")
                elif op.t:
                    imm_size = { "b": "1", "bs": "1", "bss": "1", "w": "2" }
                    return (pat, f"{imm}.len == {imm_size[op.t]}")
                else:
                    assert False, f"immediate handling for {self.form} not right"

            case "G" | "Z" | "R" | "H":
                assert self.reg_expr is None or op.a not in ["G", "Z"], f"{self.form} does not uniquely identify reg"
                assert self.rm_variant is None or op.a not in ["R", "H"], f"{self.form} does not uniquely identify rm_variant"
                name_filter = self.register_name_filter(op.text)
                regnum = self.new_var() if op.text is None else name_filter[1]
                if op.a in ["G", "Z"]:
                    self.reg_expr = f"Some(Gpr({regnum}))"
                else:
                    self.rm_variant = f"Gpr(Gpr({regnum}))"
                sz_pat = operand_sz_pattern(op)
                self.size_exprs.append((size, op_index))
                assert op.text is None or sz_pat == name_filter[0], f"{self.form}, {name_filter}"
                return f"O::Reg(R::Gpr({size}@({sz_pat}), {regnum}))"
            case "E":
                assert False, "E must have been expanded into (EM, H)"
            case "EM" | "M":
                assert self.rm_variant is None, f"{self.form} does not uniquely identify rm_variant"
                mem = self.new_var()
                sz_pat = operand_sz_pattern(op)
                self.size_exprs.append((size, op_index))
                self.rm_variant = f"Mem({mem}.encoding())"
                return f"O::Mem({size}@({sz_pat}), {mem})"

            case "EST" | "ES" | "S" | "SC" | "BA" | "BB" | "BC" | "BD" | "O" | "Y" | "X" | "F" | "V" | "W" | "C" | "D" | "T" | "P" | "U" | "N" | "Q":
                return # not implemented yet
            case None:
                filter = self.register_name_filter(op.text)
                if filter:
                    self.size_exprs.append((size, op_index))
                    return f"O::Reg(R::Gpr({size}@({filter[0]}), {filter[1]}))"
                else:
                    # unimplemented register
                    return None
            case _:
                assert False, f"{op.a} opcode type not handled"

    def operands(self) -> bool:
        operands_pat = []
        for idx, op in enumerate(self.form.operands):
            result = self.add_operand(idx, op)
            if not op.displayed:
                continue

            match result:
                case None:
                    print(f"generation for {"".join(self.form.opcode)} {self.form.mnemonic} not supported (op patterns)")
                    return False
                case (pat, guard):
                    operands_pat.append((pat, guard))
                case pat:
                    operands_pat.append(pat)

        # gotta verify guard them sizes
        if len(self.size_exprs) >= 2 and self.size_authority is not None:
            size_authority_pat = operand_sz_pattern(self.form.operands[self.size_authority])
            # only need to verify the dynamic operands:
            for s, i in self.size_exprs:
                op = self.form.operands[i]
                if i == self.size_authority or not op.displayed:
                    continue
                this_sz_pat = operand_sz_pattern(op)
                if "|" not in this_sz_pat or this_sz_pat != size_authority_pat:
                    continue
                if "sz" in (s for s,i in self.size_exprs):
                    self.guards.append(f"{s}.is(sz)")

        if operands_pat:
            self.guards += [x[1] for x in operands_pat if isinstance(x, tuple)]
            self.operand_patterns = [x[0] if isinstance(x, tuple) else x for x in operands_pat]

        return True


    def finalize(self) -> str:
        mnemonic = rust_variant_name(self.form.mnemonic)
        opcode_expr = bytes_expr(self.form.opcode)
        pref_expr = bytes_expr(self.form.pref)
        operand_pat = ["Os::Z", "Os::A", "Os::B", "Os::C", "Os::D"][len(self.operand_patterns)]
        if self.operand_patterns:
            operand_pat += f"({",".join(self.operand_patterns)})"""
        guard_clause = f""" if {"&&".join(self.guards)}""" if self.guards else ""
        rex_w = "true" if self.rex_w else "false"

        if self.form.modrm_r:
            assert self.form.opcd_ext is None
        if self.form.opcd_ext is not None:
            ext_expr = f"Some({self.form.opcd_ext})"
            assert self.reg_expr is None, f"{self.form} collides reg_expr with ext_expr"
            reg_expr = "None"
        else:
            ext_expr = "None"

        tail_expr = None if len(self.tail_vars) == 0 else (
            f"Some({self.tail_vars[0]})" if len(self.tail_vars) == 1 else
               f"Some(Template::merged([{",".join(self.tail_vars)}]))")

        return textwrap.indent(textwrap.dedent(f"""
            (M::{mnemonic}, {operand_pat}){guard_clause} => {{
                Enc {{ pref: {pref_expr}, op: {opcode_expr}, sz: {self.insn_size if self.insn_size else "Sz::None"}, rex_w: {rex_w}, reg: {self.reg_expr}, rm: Erm::{self.rm_variant}, ext: {ext_expr}, tail: {tail_expr} }}
            }},
        """), " " * 20)

def expand_operand_variants(form: Form):
    operand_choices = [
        [op] if op.a != "E" else [replace(op, a="H"), replace(op, a="EM")]
        for op in form.operands
    ]
    for ops in itertools.product(*operand_choices):
        yield replace(form, operands=list(ops))

def gen_encoder(forms: dict[str, list[Form]]) -> str:
    match_arms = []

    for form in sorted([form for forms in forms.values() for form in forms], key=lambda x: x.opcode):
        for expform in expand_operand_variants(form):
            arm = EncoderArmContext(expform)
            arm.determine_static_insn_size();
            if arm.operands():
                finalized = arm.finalize()
                if finalized not in match_arms:
                    match_arms.append(finalized)

    return textwrap.dedent(f"""\
        impl crate::x64::ast::Instruction {{
            #[track_caller]
            pub const fn encoding(&self) -> crate::x64::Encoding {{
                use crate::x64::ast::{{Mnemonic as M, Operands as Os, Operand as O, Reg as R}};
                use crate::x64::{{Size as Sz, Encoding as Enc, EncodingRm as Erm, Gpr }};

                #[allow(unused_parens, unreachable_patterns)]
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
            "// AUTO-GENERATED BY gen.py",
            gen_mnemonics(mnemonics),
            gen_prefixes(prefixes),
            gen_encoder(mnemonics)
        ]))

    return 0

if __name__ == "__main__":
    sys.exit(main())
