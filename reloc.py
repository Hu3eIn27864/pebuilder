#!/usr/bin/env python3
"""
PE relocation builder.

Supports:

    PE32:
        IMAGE_REL_BASED_HIGHLOW

    PE32+:
        IMAGE_REL_BASED_DIR64


Input sources:

1. Direct RVAs

2. Relocation objects produced by assembler.py


Output:

    .reloc section contents
"""


import struct

from dataclasses import dataclass

from pebuilder.pe import align



# ------------------------------------------------------------
# Constants
# ------------------------------------------------------------

IMAGE_REL_BASED_ABSOLUTE = 0

IMAGE_REL_BASED_HIGHLOW = 3

IMAGE_REL_BASED_DIR64 = 10


IMAGE_BASE_RELOCATION_SIZE = 8



# ------------------------------------------------------------
# Relocation object
# ------------------------------------------------------------

@dataclass
class BaseRelocation:

    rva: int

    size: int



# ------------------------------------------------------------
# Type selection
# ------------------------------------------------------------

def relocation_type(bits):

    if bits == 32:

        return IMAGE_REL_BASED_HIGHLOW


    if bits == 64:

        return IMAGE_REL_BASED_DIR64


    raise ValueError(
        "bits must be 32 or 64"
    )



# ------------------------------------------------------------
# Create single relocation entry
# ------------------------------------------------------------

def make_entry(
        rva,
        bits
):


    page = (
        rva &
        0xFFFFF000
    )


    offset = (
        rva &
        0xFFF
    )


    entry = (

        relocation_type(bits)
        << 12

    ) | offset


    return page, entry



# ------------------------------------------------------------
# Build one relocation block
# ------------------------------------------------------------

def build_block(
        page,
        entries
):


    size = (

        IMAGE_BASE_RELOCATION_SIZE

        +

        len(entries) * 2

    )


    aligned = align(
        size,
        4
    )


    block = bytearray(
        aligned
    )


    struct.pack_into(
        "<II",
        block,
        0,

        page,

        aligned
    )


    offset = (
        IMAGE_BASE_RELOCATION_SIZE
    )


    for entry in entries:


        struct.pack_into(
            "<H",
            block,
            offset,

            entry
        )


        offset += 2



    #
    # padding entries
    #

    while offset < aligned:


        struct.pack_into(
            "<H",
            block,
            offset,

            IMAGE_REL_BASED_ABSOLUTE << 12

        )


        offset += 2



    return bytes(block)



# ------------------------------------------------------------
# Core builder
# ------------------------------------------------------------

def build_reloc_section(
        relocations,
        bits=64
):

    """
    relocations:

        iterable of integer RVAs

    or:

        BaseRelocation objects

    """



    pages = {}



    for item in relocations:


        if isinstance(
            item,
            int
        ):

            rva = item


        else:

            rva = item.rva



        page,entry = make_entry(
            rva,
            bits
        )


        pages.setdefault(
            page,
            []
        ).append(
            entry
        )



    output = bytearray()



    for page in sorted(pages):


        output.extend(
            build_block(
                page,
                pages[page]
            )
        )



    return bytes(output)



# ------------------------------------------------------------
# NEW:
# assembler.py connector
# ------------------------------------------------------------

def build_from_assembler_relocations(
        assembler_relocations,
        section_rva,
        bits=64
):

    """
    Convert assembler relocation records
    into PE relocation entries.


    assembler.py produces:

        Relocation(
            address,
            size
        )


    where address is section-relative.


    PE requires:

        section RVA + offset
    """


    rvas = []


    for rel in assembler_relocations:


        rvas.append(

            section_rva
            +
            rel.rva

        )



    return build_reloc_section(
        rvas,
        bits
    )



# ------------------------------------------------------------
# Convenience wrapper
# ------------------------------------------------------------

def make_reloc_section(
        assembler_relocations,
        section_rva,
        bits=64
):

    """
    Direct helper for sections.py

    Example:

        reloc_data = make_reloc_section(
            relocs,
            0x1000,
            64
        )
    """


    return build_from_assembler_relocations(
        assembler_relocations,
        section_rva,
        bits
    )