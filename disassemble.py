#!/usr/bin/env python3
"""
Universal Standalone PE Disassembler with Full Header Metadata Export.
"""

import argparse
import os
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
except ImportError:
    print("capstone is required. Install with:\n    pip install capstone")
    sys.exit(1)

IMAGE_DOS_SIGNATURE = b"MZ"
IMAGE_NT_SIGNATURE = b"PE\x00\x00"
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_SIZEOF_SECTION_HEADER = 40


def read_struct(fmt, data, offset):
    size = struct.calcsize(fmt)
    return struct.unpack_from(fmt, data, offset), offset + size


def parse_pe(data):
    if len(data) < 0x40 or data[:2] != IMAGE_DOS_SIGNATURE:
        raise ValueError("Not a valid PE file.")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    dos_stub = data[:e_lfanew]
    file_header_offset = e_lfanew + 4

    time_date_stamp = struct.unpack_from("<I", data, file_header_offset + 4)[0]
    file_characteristics = struct.unpack_from("<H", data, file_header_offset + 18)[0]

    (Machine, NumberOfSections, _, _, _, SizeOfOptionalHeader, _), _ = read_struct(
        "<HHIIIHH", data, file_header_offset
    )

    optional_header_offset = file_header_offset + 20
    (Magic,), _ = read_struct("<H", data, optional_header_offset)

    linker_ver = struct.unpack_from("<BB", data, optional_header_offset + 2)
    size_of_code = struct.unpack_from("<I", data, optional_header_offset + 4)[0]
    size_of_init_data = struct.unpack_from("<I", data, optional_header_offset + 8)[0]
    size_of_uninit_data = struct.unpack_from("<I", data, optional_header_offset + 12)[0]
    os_ver = struct.unpack_from("<HHHHHH", data, optional_header_offset + 40)
    size_of_image = struct.unpack_from("<I", data, optional_header_offset + 56)[0]
    checksum = struct.unpack_from("<I", data, optional_header_offset + 64)[0]
    dll_characteristics = struct.unpack_from("<H", data, optional_header_offset + 70)[0]

    if Machine == IMAGE_FILE_MACHINE_I386:
        mode = CS_MODE_32
        entry_point = struct.unpack_from("<I", data, optional_header_offset + 16)[0]
        image_base = struct.unpack_from("<I", data, optional_header_offset + 28)[0]
        subsystem = struct.unpack_from("<H", data, optional_header_offset + 68)[0]
        arch = "x86"
        dir_base = optional_header_offset + 96
        num_dirs = struct.unpack_from("<I", data, optional_header_offset + 92)[0]
    elif Machine == IMAGE_FILE_MACHINE_AMD64:
        mode = CS_MODE_64
        entry_point = struct.unpack_from("<I", data, optional_header_offset + 16)[0]
        image_base = struct.unpack_from("<Q", data, optional_header_offset + 24)[0]
        subsystem = struct.unpack_from("<H", data, optional_header_offset + 68)[0]
        arch = "x64"
        dir_base = optional_header_offset + 112
        num_dirs = struct.unpack_from("<I", data, optional_header_offset + 108)[0]

    directories = {}
    dir_names = [
        "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY",
        "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS",
        "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "CLR"
    ]
    for i in range(min(num_dirs, 15)):
        rva, size = struct.unpack_from("<II", data, dir_base + i * 8)
        if rva > 0 or size > 0:
            directories[dir_names[i]] = (rva, size)

    section_table = optional_header_offset + SizeOfOptionalHeader
    sections = []
    end_of_sections = 0

    for i in range(NumberOfSections):
        off = section_table + i * IMAGE_SIZEOF_SECTION_HEADER
        name = data[off:off + 8].rstrip(b"\x00").decode("ascii", "ignore")
        (VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, _, _, _, _, Characteristics), _ = read_struct(
            "<IIIIIIHHI", data, off + 8
        )
        sections.append({
            "name": name,
            "virtual_size": VirtualSize,
            "virtual_address": VirtualAddress,
            "raw_size": SizeOfRawData,
            "raw_ptr": PointerToRawData,
            "characteristics": Characteristics,
        })
        end_of_sections = max(end_of_sections, PointerToRawData + SizeOfRawData)

    overlay = data[end_of_sections:]

    return {
        "arch": arch,
        "mode": mode,
        "image_base": image_base,
        "entry_point": entry_point,
        "subsystem": subsystem,
        "directories": directories,
        "sections": sections,
        "overlay": overlay,
        "dos_stub": dos_stub,
        "time_date_stamp": time_date_stamp,
        "checksum": checksum,
        "os_ver": os_ver,
        "file_characteristics": file_characteristics,
        "linker_ver": linker_ver,
        "size_of_code": size_of_code,
        "size_of_init_data": size_of_init_data,
        "size_of_uninit_data": size_of_uninit_data,
        "size_of_image": size_of_image,
        "dll_characteristics": dll_characteristics,
    }


def format_db(buf):
    return ", ".join(f"0x{b:02X}" for b in buf)


def disassemble_section(data, section, image_base, mode):
    start = section["raw_ptr"]
    size = section["raw_size"]

    if size == 0 or start >= len(data):
        return [f"; empty section {section['name']}"]

    end = min(start + size, len(data))
    code = data[start:end]
    base = image_base + section["virtual_address"]

    md = Cs(CS_ARCH_X86, mode)
    md.detail = False
    md.skipdata = False

    lines = []
    cursor = 0

    for insn in md.disasm(code, base):
        offset = insn.address - base
        if offset > cursor:
            gap = code[cursor:offset]
            lines.append(f"0x{base + cursor:016X}: db {format_db(gap)}")

        text = f"{insn.mnemonic} {insn.op_str}".rstrip()
        raw = code[offset:offset + insn.size]
        raw_hex = " ".join(f"{b:02X}" for b in raw)
        lines.append(f"0x{insn.address:016X}: {text:<40} ; {raw_hex}")
        cursor = offset + insn.size

    if cursor < len(code):
        remain = code[cursor:]
        lines.append(f"0x{base + cursor:016X}: db {format_db(remain)}")

    return lines


def main():
    parser = argparse.ArgumentParser(description="Universal Standalone PE Disassembler")
    parser.add_argument("input", help="Input PE executable or DLL")
    parser.add_argument("-o", "--output", help="Output text file")
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        data = f.read()

    pe = parse_pe(data)

    output = [
        f"; PE_DOS_STUB {pe['dos_stub'].hex()}",
        f"; PE_META entry_point=0x{pe['entry_point']:X} image_base=0x{pe['image_base']:X} subsystem={pe['subsystem']} arch={pe['arch']} timestamp=0x{pe['time_date_stamp']:X} checksum=0x{pe['checksum']:X} os_ver={','.join(map(str, pe['os_ver']))} file_char=0x{pe['file_characteristics']:X} linker_ver={pe['linker_ver'][0]},{pe['linker_ver'][1]} code_size=0x{pe['size_of_code']:X} init_data=0x{pe['size_of_init_data']:X} uninit_data=0x{pe['size_of_uninit_data']:X} image_size=0x{pe['size_of_image']:X} dll_char=0x{pe['dll_characteristics']:X}"
    ]

    for name, (rva, size) in pe["directories"].items():
        output.append(f"; PE_DIR {name} rva=0x{rva:X} size=0x{size:X}")

    if pe["overlay"]:
        output.append(f"; PE_OVERLAY {pe['overlay'].hex()}")

    output.append("")

    for sec in pe["sections"]:
        output.append(
            f"; SECTION {sec['name']} raw=0x{sec['raw_ptr']:X} size=0x{sec['raw_size']:X} va=0x{sec['virtual_address']:X} vsize=0x{sec['virtual_size']:X} flags=0x{sec['characteristics']:X}"
        )
        output.extend(disassemble_section(data, sec, pe["image_base"], pe["mode"]))
        output.append("")

    text = "\n".join(output)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Standalone Disassembly written to {args.output}")
    else:
        print(text)


if __name__ == "__main__":
    main()