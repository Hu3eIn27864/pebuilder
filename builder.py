#!/usr/bin/env python3
"""
PE executable/DLL builder with full header customization.
"""

from pathlib import Path

from pebuilder.pe import (
    PEFormat,
    align,
    build_dos_header,
    build_nt_headers,
    IMAGE_FILE_EXECUTABLE_IMAGE,
)

from pebuilder.sections import (
    PESection,
    SectionTable,
    IMAGE_SIZEOF_SECTION_HEADER,
)

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_IAT = 12


class PEBuilder:

    def __init__(
            self,
            bits=64,
            dll=False,
            image_base=None,
            section_alignment=0x1000,
            file_alignment=0x200,
            subsystem=2,
            dos_stub=None,
            timestamp=0,
            checksum=0,
            os_ver=(6, 0, 0, 0, 6, 0),
            file_characteristics=IMAGE_FILE_EXECUTABLE_IMAGE,
            linker_ver=(0, 0),
            size_of_init_data=None,
            size_of_uninit_data=None,
            size_of_image_override=None,
            dll_characteristics=0x8140,
            size_of_code_override=None
    ):
        self.format = PEFormat(bits)
        self.bits = bits
        self.dll = dll
        self.image_base = (
            image_base
            if image_base is not None
            else self.format.image_base_default
        )
        self.section_alignment = section_alignment
        self.file_alignment = file_alignment
        self.subsystem = subsystem
        self.dos_stub = dos_stub
        self.timestamp = timestamp
        self.checksum = checksum
        self.os_ver = os_ver
        self.file_characteristics = file_characteristics
        self.linker_ver = linker_ver
        self.size_of_init_data = size_of_init_data
        self.size_of_uninit_data = size_of_uninit_data
        self.sections = []
        self.entry_point = 0
        self.directories = {}
        self.size_of_image_override = size_of_image_override
        self.dll_characteristics = dll_characteristics
        self.size_of_code_override = size_of_code_override


    def add_section(
            self,
            section,
            data=None,
            characteristics=None,
            virtual_address=None,
            raw_pointer=None
    ):
        if isinstance(section, PESection):
            self.sections.append(section)
            return

        if data is None:
            raise TypeError("section data missing")

        sec = PESection(
            section,
            characteristics=(characteristics or 0)
        )
        sec.set_data(data)

        if virtual_address is not None:
            sec.virtual_address = virtual_address
        if raw_pointer is not None:
            sec.raw_pointer = raw_pointer

        self.sections.append(sec)

    def set_directory(self, index, rva, size):
        self.directories[index] = (rva, size)

    def headers_size(self):
        dos_len = len(self.dos_stub) if self.dos_stub else 0x80
        size = (
            dos_len
            + 4
            + 20
            + self.format.optional_size
            + len(self.sections) * IMAGE_SIZEOF_SECTION_HEADER
        )
        return align(size, self.file_alignment)

    def size_of_code(self):
        total = 0
        for sec in self.sections:
            if sec.characteristics & 0x20:
                total += align(len(sec.data), self.file_alignment)
        return total

    def size_of_data(self):
        total = 0
        for sec in self.sections:
            if not (sec.characteristics & 0x20):
                total += align(len(sec.data), self.file_alignment)
        return total

    def build(self, filename):
        table = SectionTable(
            section_alignment=self.section_alignment,
            file_alignment=self.file_alignment
        )

        for sec in self.sections:
            table.add(sec)

        headers_size = self.headers_size()
        table.layout(headers_size)

        dos = self.dos_stub if self.dos_stub else build_dos_header()

        nt = build_nt_headers(
            self.format,
            len(table.sections),
            self.dll,
            self.image_base,
            self.entry_point
            if self.entry_point
            else (
                table.sections[0].virtual_address
                if table.sections
                else 0
            ),
            (
                table.sections[0].virtual_address
                if table.sections
                else 0
            ),
            self.size_of_code(),
            self.size_of_data(),
            table.size_of_image(),
            headers_size,
            self.section_alignment,
            self.file_alignment,
            self.directories,
            subsystem=self.subsystem,
            timestamp=self.timestamp,
            checksum=self.checksum,
            os_ver=self.os_ver,
            file_characteristics=self.file_characteristics,
            linker_ver=self.linker_ver,
            size_of_init_data=self.size_of_init_data,
            size_of_uninit_data=self.size_of_uninit_data,
            size_of_image_override=self.size_of_image_override,
            dll_characteristics=self.dll_characteristics,
            size_of_code_override=self.size_of_code_override
        )

        header_bytes = bytearray()
        header_bytes.extend(dos)
        header_bytes.extend(nt)
        header_bytes.extend(table.headers())

        image = bytearray(table.raw_data())
        image[:len(header_bytes)] = header_bytes

        Path(filename).write_bytes(image)
        return filename

    def write(self, filename):
        return self.build(filename)