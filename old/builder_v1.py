#!/usr/bin/env python3
"""
PE executable/DLL builder.

Supports:

    PE32
    PE32+

    EXE
    DLL

Features:

    - section layout
    - PE headers
    - data directory patching
    - imports
    - exports
    - relocations
"""


from pathlib import Path
import struct


from pebuilder.pe import (
    PEFormat,
    align,
    build_dos_header,
    build_nt_headers,
)


from pebuilder.sections import (
    SectionTable,
    PESection,
    IMAGE_SIZEOF_SECTION_HEADER,
)



# ------------------------------------------------------------
# Data Directory indexes
# ------------------------------------------------------------

IMAGE_DIRECTORY_ENTRY_EXPORT = 0

IMAGE_DIRECTORY_ENTRY_import = 1

IMAGE_DIRECTORY_ENTRY_BASERELOC = 5

IMAGE_DIRECTORY_ENTRY_IAT = 12



# ------------------------------------------------------------
# Builder
# ------------------------------------------------------------

class PEBuilder:


    def __init__(
            self,
            bits=64,
            dll=False,
            image_base=None,
            section_alignment=0x1000,
            file_alignment=0x200
    ):


        self.format = PEFormat(
            bits
        )


        self.bits = bits

        self.dll = dll


        self.image_base = (
            image_base
            if image_base
            else self.format.image_base_default
        )


        self.section_alignment = (
            section_alignment
        )


        self.file_alignment = (
            file_alignment
        )


        self.sections = []


        self.entry_point = 0


        #
        # PE data directories
        #

        self.directories = {}



    # --------------------------------------------------------
    # Sections
    # --------------------------------------------------------

    def add_section(
            self,
            section
    ):


        if not isinstance(
            section,
            PESection
        ):

            raise TypeError(
                "Expected PESection"
            )


        self.sections.append(
            section
        )



    # --------------------------------------------------------
    # Directory registration
    # --------------------------------------------------------

    def set_directory(
            self,
            index,
            rva,
            size
    ):


        self.directories[index] = (

            rva,
            size

        )



    def add_import_directory(
            self,
            section
    ):


        self.set_directory(

            IMAGE_DIRECTORY_ENTRY_IMPORT,

            section.virtual_address,

            len(section.data)

        )



    def add_export_directory(
            self,
            section
    ):


        self.set_directory(

            IMAGE_DIRECTORY_ENTRY_EXPORT,

            section.virtual_address,

            len(section.data)

        )



    def add_reloc_directory(
            self,
            section
    ):


        self.set_directory(

            IMAGE_DIRECTORY_ENTRY_BASERELOC,

            section.virtual_address,

            len(section.data)

        )



    def add_iat_directory(
            self,
            rva,
            size
    ):


        self.set_directory(

            IMAGE_DIRECTORY_ENTRY_IAT,

            rva,

            size

        )



    # --------------------------------------------------------
    # Header size
    # --------------------------------------------------------

    def headers_size(self):


        size = (

            0x80

            +
            4

            +
            20

            +
            self.format.optional_size

            +
            len(self.sections)
            *
            IMAGE_SIZEOF_SECTION_HEADER

        )


        return align(
            size,
            self.file_alignment
        )



    # --------------------------------------------------------
    # Build
    # --------------------------------------------------------

    def build(
            self,
            filename
    ):


        headers_size = (
            self.headers_size()
        )



        #
        # Layout sections
        #

        table = SectionTable(

            section_alignment=
            self.section_alignment,

            file_alignment=
            self.file_alignment

        )


        for sec in self.sections:

            table.add(
                sec
            )


        table.layout(
            headers_size
        )



        #
        # Fix section RVAs
        #

        for sec in table.sections:


            if sec.fixup:


                sec.data = bytearray(

                    sec.fixup(

                        bytes(sec.data),

                        sec.virtual_address

                    )

                )



        #
        # Locate entry point
        #

        if self.entry_point == 0:


            text = table.get(
                ".text"
            )


            if text:

                self.entry_point = (
                    text.virtual_address
                )



        #
        # Build headers
        #

        dos = build_dos_header()



        nt = build_nt_headers(

            self.format,

            len(table.sections),

            self.dll,

            self.image_base,

            self.entry_point,

            table.sections[0].virtual_address,

            table.size_of_code(),

            table.size_of_data(),

            table.size_of_image(),

            headers_size,

            self.section_alignment,

            self.file_alignment,

            self.directories

        )



        #
        # Section headers
        #

        section_headers = (
            table.headers()
        )



        image = bytearray()



        image.extend(
            dos
        )


        if len(image) < 0x80:

            image.extend(
                b"\x00"
                *
                (
                    0x80 -
                    len(image)
                )
            )


        image.extend(
            nt
        )


        image.extend(
            section_headers
        )


        if len(image) < headers_size:

            image.extend(

                b"\x00"
                *
                (
                    headers_size -
                    len(image)
                )

            )



        #
        # Section raw data
        #

        image.extend(
            table.raw_data()
        )



        Path(filename).write_bytes(
            image
        )


        return filename



# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def build_exe(
        filename,
        sections,
        bits=64
):


    builder = PEBuilder(
        bits=bits,
        dll=False
    )


    for sec in sections:

        builder.add_section(
            sec
        )


    return builder.build(
        filename
    )



def build_dll(
        filename,
        sections,
        bits=64
):


    builder = PEBuilder(
        bits=bits,
        dll=True
    )


    for sec in sections:

        builder.add_section(
            sec
        )


    return builder.build(
        filename
    )