#!/usr/bin/env python3
"""
PE section builder.

Supports:
- PE32
- PE32+
- EXE
- DLL

Responsible for:
- section layout
- RVA assignment
- raw file layout
- section headers
"""


from dataclasses import dataclass, field

from pebuilder.pe import (
    align,
    build_section_header,
    code_section_flags,
    data_section_flags,

    IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
)



# ------------------------------------------------------------
# Section defaults
# ------------------------------------------------------------

DEFAULT_SECTION_ALIGNMENT = 0x1000
DEFAULT_FILE_ALIGNMENT = 0x200



# ------------------------------------------------------------
# Section object
# ------------------------------------------------------------

@dataclass
class PESection:

    name: str

    data: bytearray = field(
        default_factory=bytearray
    )

    characteristics: int = 0

    virtual_address: int = 0

    virtual_size: int = 0

    raw_pointer: int = 0

    raw_size: int = 0



    def set_data(self, data):

        self.data = bytearray(data)

        self.virtual_size = len(
            self.data
        )



    def align_raw(
            self,
            file_alignment
    ):

        self.raw_size = align(
            len(self.data),
            file_alignment
        )



    def align_virtual(
            self,
            section_alignment
    ):

        self.virtual_size = len(
            self.data
        )

        self.virtual_address = align(
            self.virtual_address,
            section_alignment
        )



    def header(self):

        return build_section_header(

            self.name,

            self.virtual_size,

            self.virtual_address,

            self.raw_size,

            self.raw_pointer,

            self.characteristics
        )



    def padded_data(self):

        result = bytearray(
            self.raw_size
        )

        result[:len(self.data)] = self.data

        return result




# ------------------------------------------------------------
# Standard section factories
# ------------------------------------------------------------

def make_text(data=b""):

    sec = PESection(
        ".text",
        characteristics=code_section_flags()
    )

    sec.set_data(data)

    return sec



def make_rdata(data=b""):

    sec = PESection(
        ".rdata",
        characteristics=(
            IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_MEM_READ
        )
    )

    sec.set_data(data)

    return sec



def make_data(data=b""):

    sec = PESection(
        ".data",
        characteristics=data_section_flags()
    )

    sec.set_data(data)

    return sec



def make_idata(data=b""):

    sec = PESection(
        ".idata",
        characteristics=(
            IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_MEM_READ |
            IMAGE_SCN_MEM_WRITE
        )
    )

    sec.set_data(data)

    return sec



def make_edata(data=b""):

    sec = PESection(
        ".edata",
        characteristics=(
            IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_MEM_READ
        )
    )

    sec.set_data(data)

    return sec



def make_reloc(data=b""):

    sec = PESection(
        ".reloc",
        characteristics=(
            IMAGE_SCN_CNT_INITIALIZED_DATA |
            IMAGE_SCN_MEM_READ
        )
    )

    sec.set_data(data)

    return sec




# ------------------------------------------------------------
# Section layout manager
# ------------------------------------------------------------

class SectionTable:


    def __init__(
            self,
            section_alignment=DEFAULT_SECTION_ALIGNMENT,
            file_alignment=DEFAULT_FILE_ALIGNMENT,
            image_base_address=0x1000
    ):

        self.sections = []

        self.section_alignment = (
            section_alignment
        )

        self.file_alignment = (
            file_alignment
        )

        self.next_virtual_address = (
            image_base_address
        )

        self.next_raw_pointer = 0



    def add(self, section):

        self.sections.append(
            section
        )



    def layout(
            self,
            headers_size
    ):

        #
        # First raw section starts
        # immediately after headers
        #

        self.next_raw_pointer = align(
            headers_size,
            self.file_alignment
        )


        self.next_virtual_address = align(
            self.next_virtual_address,
            self.section_alignment
        )



        for sec in self.sections:


            sec.virtual_address = (
                self.next_virtual_address
            )


            sec.virtual_size = len(
                sec.data
            )


            sec.raw_pointer = (
                self.next_raw_pointer
            )


            sec.raw_size = align(
                len(sec.data),
                self.file_alignment
            )


            self.next_virtual_address += align(
                sec.virtual_size,
                self.section_alignment
            )


            self.next_raw_pointer += (
                sec.raw_size
            )



    def size_of_image(self):

        if not self.sections:
            return 0


        last = self.sections[-1]


        return align(
            last.virtual_address +
            last.virtual_size,

            self.section_alignment
        )



    def headers(self):

        return b"".join(
            sec.header()
            for sec in self.sections
        )



    def raw_data(self):

        output = bytearray()


        for sec in self.sections:


            #
            # Ensure gaps between
            # sections are preserved
            #

            if len(output) < sec.raw_pointer:

                output.extend(
                    b"\x00" *
                    (
                        sec.raw_pointer -
                        len(output)
                    )
                )


            output.extend(
                sec.padded_data()
            )


        return bytes(output)



    def get(self,name):

        for sec in self.sections:

            if sec.name == name:
                return sec

        return None



# ------------------------------------------------------------
# Convenience builder
# ------------------------------------------------------------

def build_default_sections(
        text=b"",
        rdata=b"",
        data=b""
):

    table = SectionTable()


    if text:
        table.add(
            make_text(text)
        )


    if rdata:
        table.add(
            make_rdata(rdata)
        )


    if data:
        table.add(
            make_data(data)
        )


    return table