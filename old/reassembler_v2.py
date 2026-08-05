#!/usr/bin/env python3
"""
PE Disassembly Reassembler v2.

Pipeline:
    disasm -> assembler -> linker -> builder
"""

import argparse
import re
from pathlib import Path

from pebuilder.assembler import X86Assembler, Instruction
from pebuilder.linker import Linker

try:
    from pebuilder.imports import ImportBuilder
except Exception:
    ImportBuilder = None

try:
    from pebuilder.exports import ExportBuilder
except Exception:
    ExportBuilder = None

try:
    from pebuilder.reloc import RelocationBuilder
except Exception:
    RelocationBuilder = None

try:
    from pebuilder.tls import TLSBuilder
except Exception:
    TLSBuilder = None

try:
    from pebuilder.pdata import PDataBuilder
except Exception:
    PDataBuilder = None

try:
    from pebuilder.resources import ResourceBuilder
except Exception:
    ResourceBuilder = None

try:
    from pebuilder.debug import DebugBuilder
except Exception:
    DebugBuilder = None

try:
    from pebuilder.loadconfig import LoadConfigBuilder
except Exception:
    LoadConfigBuilder = None

try:
    from pebuilder.bound_imports import BoundImportBuilder
except Exception:
    BoundImportBuilder = None


class DisassemblyV2:
    def __init__(self):
        self.instructions = []

    def load(self, filename):
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue

                if line_str.startswith(";"):
                    continue

                if ":" not in line_str:
                    continue

                parts = line_str.split(":", 1)
                addr_str = parts[0].strip().replace("0x", "")
                try:
                    address = int(addr_str, 16)
                except ValueError:
                    continue

                text = parts[1].strip()
                if not text:
                    continue

                self.instructions.append((address, text))
        return self


class ReassemblerV2:
    def __init__(self, bits=64, dll=False):
        self.bits = bits
        self.dll = dll
        self.imports = []
        self.exports = []
        self.resources = None
        self.debug = None
        self.tls = None
        self.load_config = None
        self.bound_imports = None

    def add_import(self, dll, function):
        self.imports.append((dll, function))

    def add_export(self, name, rva):
        self.exports.append((name, rva))

    def build(self, disasm, output):
        listing = DisassemblyV2().load(disasm)
        assembler = X86Assembler(bits=self.bits)

        # Fix invocation logic: assemble_listing or assemble per instruction
        code, relocations = assembler.assemble_listing(listing.instructions)

        linker = Linker(bits=self.bits, dll=self.dll)
        linker.add_text(code, entry=0)

        if self.imports and ImportBuilder:
            imp = ImportBuilder(bits=self.bits)
            for dll, fn in self.imports:
                imp.add(dll, fn)
            linker.register("imports", imp)

        if self.exports and ExportBuilder:
            exp = ExportBuilder(bits=self.bits)
            for name, rva in self.exports:
                exp.add(name, rva)
            linker.register("exports", exp)

        if relocations and RelocationBuilder:
            reloc = RelocationBuilder(bits=self.bits)
            for r in relocations:
                r_rva = r.rva if hasattr(r, "rva") else r
                reloc.add(r_rva)
            linker.register("reloc", reloc)

        if self.tls and TLSBuilder:
            linker.register("tls", self.tls)

        if self.bits == 64 and PDataBuilder:
            pdata = PDataBuilder()
            linker.register("pdata", pdata)

        if self.resources and ResourceBuilder:
            linker.register("resources", self.resources)

        if self.debug and DebugBuilder:
            linker.register("debug", self.debug)

        if self.load_config and LoadConfigBuilder:
            linker.register("load_config", self.load_config)

        if self.bound_imports and BoundImportBuilder:
            linker.register("bound_import", self.bound_imports)

        return linker.link(output)


def main():
    parser = argparse.ArgumentParser(description="PE Disassembly Reassembler v2")
    parser.add_argument("--disasm", required=True, help="Input disassembly file")
    parser.add_argument("--output", required=True, help="Output PE executable file")
    parser.add_argument("--bits", type=int, default=64, help="Target architecture bits (32 or 64)")
    parser.add_argument("--dll", action="store_true", help="Build as DLL")

    args = parser.parse_args()

    r = ReassemblerV2(bits=args.bits, dll=args.dll)
    r.build(args.disasm, args.output)
    print("created", args.output)


if __name__ == "__main__":
    main()
