#!/usr/bin/env python3
"""
PE section management.

Supports:

    PE32
    PE32+

Provides:

    - section objects
    - section headers
    - section layout
    - raw/virtual alignment
    - default section factories
"""


from dataclasses import dataclass, field
import struct


from pebuilder.pe import align



# ------------------------------------------------------------
# Constants
# ------------------------------------------------------------

IMAGE_SIZEOF_SECTION_HEADER = 40


IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000



DEFAULT_SECTION_ALIGNMENT = 0x1000
DEFAULT_FILE_ALIGNMENT = 0x200



# ------------------------------------------------------------
# Section characteristics
# ------------------------------------------------------------

def code_section_flags():

    return (
        IMAGE_SCN_CNT_CODE |
        IMAGE_SCN_MEM_EXECUTE |
        IMAGE_SCN_MEM_READ
    )



def data_section_flags():

    return (
        IMAGE_SCN_CNT_INITIALIZED_DATA |
        IMAGE_SCN_MEM_READ |
        IMAGE_SCN_MEM_WRITE
    )



# ------------------------------------------------------------
# Section header
# ------------------------------------------------------------

def build_section_header(
        name,
        virtual_size,
        virtual_address,
        raw_size,
        raw_pointer,
        characteristics
):


    name_bytes = name.encode(
        "ascii"
    )[:8]


    name_bytes += (
        b"\x00"
        *
        (
            8 -
            len(name_bytes)
        )
    )


    return struct.pack(

        "<8sIIIIIIHHI",

        name_bytes,

        virtual_size,

        virtual_address,

        raw_size,

        raw_pointer,

        0,

        0,

        0,

        0,

        characteristics

    )



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
        if self.virtual_size == 0:
            self.virtual_size = len(self.data)



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

        output = bytearray(
            self.raw_size
        )

        output[:len(self.data)] = self.data

        return bytes(output)



# ------------------------------------------------------------
# Default sections
# ------------------------------------------------------------

def make_text(
        data=b""
):

    sec = PESection(

        ".text",

        characteristics=
        code_section_flags()

    )

    sec.set_data(
        data
    )

    return sec



def make_rdata(
        data=b""
):

    sec = PESection(

        ".rdata",

        characteristics=(

            IMAGE_SCN_CNT_INITIALIZED_DATA |

            IMAGE_SCN_MEM_READ

        )

    )

    sec.set_data(
        data
    )

    return sec



def make_data(
        data=b""
):

    sec = PESection(

        ".data",

        characteristics=
        data_section_flags()

    )

    sec.set_data(
        data
    )

    return sec



def make_idata(
        data=b""
):

    sec = PESection(

        ".idata",

        characteristics=(

            IMAGE_SCN_CNT_INITIALIZED_DATA |

            IMAGE_SCN_MEM_READ |

            IMAGE_SCN_MEM_WRITE

        )

    )

    sec.set_data(
        data
    )

    return sec



def make_edata(
        data=b""
):

    sec = PESection(

        ".edata",

        characteristics=(

            IMAGE_SCN_CNT_INITIALIZED_DATA |

            IMAGE_SCN_MEM_READ

        )

    )

    sec.set_data(
        data
    )

    return sec



def make_reloc(
        data=b""
):

    sec = PESection(

        ".reloc",

        characteristics=(

            IMAGE_SCN_CNT_INITIALIZED_DATA |

            IMAGE_SCN_MEM_READ

        )

    )

    sec.set_data(
        data
    )

    return sec



# ------------------------------------------------------------
# Section table
# ------------------------------------------------------------

class SectionTable:

    def __init__(

            self,

            section_alignment=
            DEFAULT_SECTION_ALIGNMENT,

            file_alignment=
            DEFAULT_FILE_ALIGNMENT

    ):


        self.sections = []

        self.section_alignment = (
            section_alignment
        )

        self.file_alignment = (
            file_alignment
        )



    def add(
            self,
            section
    ):

        self.sections.append(
            section
        )



    def layout(
            self,
            headers_size
    ):


        virtual = align(

            headers_size,

            self.section_alignment

        )


        raw = align(

            headers_size,

            self.file_alignment

        )


        for sec in self.sections:
            sec.virtual_address = virtual

            if sec.virtual_size == 0:
                sec.virtual_size = len(sec.data)

            sec.raw_pointer = raw
            sec.raw_size = align(
                len(sec.data),
                self.file_alignment
            )

            virtual += align(
                sec.virtual_size,
                self.section_alignment
            )

            raw += sec.raw_size



    def headers(self):

        return b"".join(

            sec.header()

            for sec in self.sections

        )



    def raw_data(self):

        output = bytearray()


        for sec in self.sections:


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



    def size_of_image(self):

        if not self.sections:

            return 0


        last = self.sections[-1]


        return align(

            last.virtual_address +

            last.virtual_size,

            self.section_alignment

        )



    def size_of_code(self):

        total = 0


        for sec in self.sections:

            if sec.characteristics & IMAGE_SCN_CNT_CODE:

                total += sec.raw_size


        return total



    def size_of_data(self):

        total = 0


        for sec in self.sections:

            if not (
                sec.characteristics &
                IMAGE_SCN_CNT_CODE
            ):

                total += sec.raw_size


        return total



    def get(
            self,
            name
    ):

        for sec in self.sections:

            if sec.name == name:

                return sec


        return None



# ------------------------------------------------------------
# Convenience
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