#!/usr/bin/env python3
"""
Portable Executable (PE) format helpers.
"""

import struct

IMAGE_DOS_SIGNATURE = b"MZ"
IMAGE_NT_SIGNATURE = b"PE\x00\x00"

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664

IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B

IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_DLL = 0x2000

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

IMAGE_SIZEOF_SECTION_HEADER = 40
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16


def align(value, alignment):
    return ((value + alignment - 1) // alignment) * alignment


def code_section_flags():
    return IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ


def data_section_flags():
    return IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE


def rdata_section_flags():
    return IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ


class PEFormat:
    def __init__(self, bits=64):
        if bits not in (32, 64):
            raise ValueError("bits must be 32 or 64")

        self.bits = bits
        if bits == 32:
            self.machine = IMAGE_FILE_MACHINE_I386
            self.optional_magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC
            self.optional_size = 0xE0
            self.image_base_default = 0x400000
        else:
            self.machine = IMAGE_FILE_MACHINE_AMD64
            self.optional_magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC
            self.optional_size = 0xF0
            self.image_base_default = 0x140000000


def build_dos_header(e_lfanew=0x80):
    hdr = bytearray(e_lfanew)
    hdr[0:2] = IMAGE_DOS_SIGNATURE
    struct.pack_into("<I", hdr, 0x3C, e_lfanew)
    return bytes(hdr)


def build_section_header(
    name,
    virtual_size,
    virtual_address,
    raw_size,
    raw_pointer,
    characteristics,
):
    if isinstance(name, str):
        name = name.encode("ascii")

    name = name[:8].ljust(8, b"\0")

    return struct.pack(
        "<8sIIIIIIHHI",
        name,
        virtual_size,
        virtual_address,
        raw_size,
        raw_pointer,
        0, 0, 0, 0,
        characteristics,
    )


def build_nt_headers(
    fmt,
    number_sections,
    dll,
    image_base,
    entry_point,
    base_of_code,
    size_of_code,
    size_of_data,
    size_of_image,
    size_of_headers,
    section_alignment,
    file_alignment,
    directories=None,
    subsystem=2,
    timestamp=0,
    checksum=0,
    os_ver=(6, 0, 0, 0, 6, 0),
    file_characteristics=IMAGE_FILE_EXECUTABLE_IMAGE,
    linker_ver=(0, 0),
    size_of_init_data=None,
    size_of_uninit_data=None,
    size_of_image_override=None,
    dll_characteristics=0x8140,    
    size_of_code_override=None,
):
    if directories is None:
        directories = {}

    nt = bytearray()
    nt.extend(IMAGE_NT_SIGNATURE)

    characteristics = file_characteristics
    if dll:
        characteristics |= IMAGE_FILE_DLL

    file_header = struct.pack(
        "<HHIIIHH",
        fmt.machine,
        number_sections,
        timestamp,
        0, 0,
        fmt.optional_size,
        characteristics,
    )
    nt.extend(file_header)

    optional = bytearray(fmt.optional_size)

    struct.pack_into("<HBB", optional, 0, fmt.optional_magic, linker_ver[0], linker_ver[1])
    code_sz = size_of_code_override if size_of_code_override is not None else size_of_code
    init_sz = size_of_init_data if size_of_init_data is not None else size_of_data
    uninit_sz = size_of_uninit_data if size_of_uninit_data is not None else 0

    struct.pack_into("<III", optional, 4, size_of_code, init_sz, uninit_sz)
    struct.pack_into("<II", optional, 16, entry_point, base_of_code)

    if fmt.bits == 32:
        struct.pack_into("<I", optional, 24, 0)
        struct.pack_into("<I", optional, 28, image_base)
        data_directory_offset = 96
        number_rva_offset = 92
    else:
        struct.pack_into("<Q", optional, 24, image_base)
        data_directory_offset = 112
        number_rva_offset = 108

    struct.pack_into("<II", optional, 32, section_alignment, file_alignment)
    struct.pack_into("<HHHHHH", optional, 40, *os_ver)
    struct.pack_into("<III", optional, 56, size_of_image, size_of_headers, checksum)
    struct.pack_into("<H", optional, 68, subsystem)
    struct.pack_into("<H", optional, 70, 0x8140)

    if fmt.bits == 32:
        struct.pack_into("<IIII", optional, 72, 0x100000, 0x1000, 0x100000, 0x1000)
    else:
        struct.pack_into("<QQQQ", optional, 72, 0x100000, 0x1000, 0x100000, 0x1000)

    struct.pack_into("<I", optional, number_rva_offset, IMAGE_NUMBEROF_DIRECTORY_ENTRIES)

    for index, value in directories.items():
        if isinstance(value, dict):
            rva = value["rva"]
            size = value["size"]
        else:
            rva, size = value

        if index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES:
            continue

        struct.pack_into(
            "<II",
            optional,
            data_directory_offset + index * 8,
            rva,
            size,
        )

        img_sz = size_of_image_override if size_of_image_override is not None else size_of_image
        struct.pack_into("<III", optional, 56, img_sz, size_of_headers, checksum)
        struct.pack_into("<H", optional, 68, subsystem)
        struct.pack_into("<H", optional, 70, dll_characteristics)

    nt.extend(optional)
    return bytes(nt)