#!/usr/bin/env python3
"""
PE Standalone Reassembler with Perfect Section Flags & VirtualSize Fidelity.
"""

import argparse
from pathlib import Path

from pebuilder.assembler import X86Assembler
from pebuilder.linker import Linker
from pebuilder.pe import IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ
from pebuilder.sections import PESection, data_section_flags


class DisassemblySection:
    def __init__(self, name=".text", virtual_size=0, characteristics=0):
        self.name = name
        self.virtual_size = virtual_size
        self.characteristics = characteristics
        self.instructions = []


class Disassembly:
    def __init__(self):
        self.sections = []
        self.meta = {"entry_point": 0, "image_base": 0x140000000, "subsystem": 2, "arch": "x64"}
        self.directories = {}
        self.overlay = b""
        self.dos_stub = b""

    def load(self, filename):
        current_section = DisassemblySection(".text")
        self.sections.append(current_section)

        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                if line.startswith("; PE_DOS_STUB"):
                    parts = line.split(maxsplit=2)
                    if len(parts) >= 3:
                        self.dos_stub = bytes.fromhex(parts[2])
                    continue

                if line.startswith("; PE_META"):
                    parts = line.split()
                    for p in parts[2:]:
                        if "=" in p:
                            k, v = p.split("=", 1)
                            if k in ("entry_point", "image_base", "timestamp", "checksum", "file_char", "code_size", "init_data", "uninit_data", "image_size", "dll_char"):
                                self.meta[k] = int(v, 16)
                            elif k == "subsystem":
                                self.meta[k] = int(v)
                            elif k in ("os_ver", "linker_ver"):
                                self.meta[k] = tuple(map(int, v.split(",")))
                            else:
                                self.meta[k] = v
                    continue

                if line.startswith("; PE_DIR"):
                    parts = line.split()
                    if len(parts) >= 4:
                        name = parts[2]
                        rva = int(parts[3].split("=")[1], 16)
                        size = int(parts[4].split("=")[1], 16)
                        self.directories[name] = (rva, size)
                    continue

                if line.startswith("; PE_OVERLAY"):
                    parts = line.split(maxsplit=2)
                    if len(parts) >= 3:
                        self.overlay = bytes.fromhex(parts[2])
                    continue

                if line.startswith("; SECTION"):
                    parts = line.split()
                    if len(parts) >= 3:
                        sec_name = parts[2]
                        sec_vsize = 0
                        sec_flags = 0
                        for p in parts[3:]:
                            if p.startswith("vsize="):
                                sec_vsize = int(p.split("=")[1], 16)
                            elif p.startswith("flags="):
                                sec_flags = int(p.split("=")[1], 16)

                        if current_section.name == sec_name and not current_section.instructions:
                            current_section.virtual_size = sec_vsize
                            current_section.characteristics = sec_flags
                        else:
                            current_section = DisassemblySection(sec_name, sec_vsize, sec_flags)
                            self.sections.append(current_section)
                    continue

                if ":" not in line:
                    continue

                address, text = line.split(":", 1)
                try:
                    address = int(address.strip().replace("0x", ""), 16)
                except ValueError:
                    continue

                text = text.strip()
                if text:
                    current_section.instructions.append((address, text))

        self.sections = [s for s in self.sections if s.instructions]
        return self


class Reassembler:
    def __init__(self, bits=64, dll=False):
        self.bits = bits
        self.dll = dll

    def build(self, disasm, output):
        disasm_data = Disassembly().load(disasm)

        bits = 32 if disasm_data.meta.get("arch") == "x86" else self.bits
        assembler = X86Assembler(bits=bits)
        linker = Linker(bits=bits, dll=self.dll, image_base=disasm_data.meta.get("image_base"))
        linker.subsystem = disasm_data.meta.get("subsystem", 2)
        linker.dos_stub = disasm_data.dos_stub

        linker.timestamp = disasm_data.meta.get("timestamp", 0)
        linker.checksum = disasm_data.meta.get("checksum", 0)
        linker.os_ver = disasm_data.meta.get("os_ver", (6, 0, 0, 0, 6, 0))
        linker.file_characteristics = disasm_data.meta.get("file_char", 0x0002)
        linker.linker_ver = disasm_data.meta.get("linker_ver", (0, 0))
        linker.size_of_init_data = disasm_data.meta.get("init_data", None)
        linker.size_of_uninit_data = disasm_data.meta.get("uninit_data", None)
        linker.size_of_image_override = disasm_data.meta.get("image_size", None)
        linker.dll_characteristics = disasm_data.meta.get("dll_char", 0x8140)
        linker.size_of_code_override = disasm_data.meta.get("code_size", None)

        for sec in disasm_data.sections:
            if not sec.instructions:
                continue

            code, _ = assembler.assemble_listing(sec.instructions)
            flags = sec.characteristics if sec.characteristics > 0 else data_section_flags()

            sec_obj = PESection(sec.name, bytearray(code), flags)
            sec_obj.virtual_size = sec.virtual_size
            linker.add_section(sec_obj)

        ep = disasm_data.meta.get("entry_point", 0)
        if ep > 0:
            linker.entry = ep

        if not hasattr(linker, "directories") or linker.directories is None:
            linker.directories = {}

        dir_map = {
            "EXPORT": 0, "IMPORT": 1, "RESOURCE": 2, "EXCEPTION": 3,
            "SECURITY": 4, "BASERELOC": 5, "DEBUG": 6, "ARCHITECTURE": 7,
            "GLOBALPTR": 8, "TLS": 9, "LOAD_CONFIG": 10, "BOUND_IMPORT": 11,
            "IAT": 12, "DELAY_IMPORT": 13, "CLR": 14
        }
        for dname, (rva, size) in disasm_data.directories.items():
            if dname in dir_map:
                linker.directories[dir_map[dname]] = (rva, size)

        result_path = linker.link(output)

        if disasm_data.dos_stub:
            with open(output, "r+b") as f:
                f.write(disasm_data.dos_stub)

        if disasm_data.overlay:
            with open(output, "ab") as f:
                f.write(disasm_data.overlay)

        return result_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--disasm", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--bits", type=int, default=64)
    parser.add_argument("--dll", action="store_true")

    args = parser.parse_args()

    r = Reassembler(bits=args.bits, dll=args.dll)
    r.build(args.disasm, args.output)
    print("Successfully built standalone executable:", args.output)


if __name__ == "__main__":
    main()