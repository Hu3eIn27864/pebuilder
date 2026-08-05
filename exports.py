#!/usr/bin/env python3
"""
PE export directory builder.

Creates .edata contents.

Supports:
    PE32
    PE32+

Exports:
    - function names
    - ordinals
    - RVAs
"""


import struct

from dataclasses import dataclass, field



# ------------------------------------------------------------
# Constants
# ------------------------------------------------------------

IMAGE_EXPORT_DIRECTORY_SIZE = 40



# ------------------------------------------------------------
# Export objects
# ------------------------------------------------------------

@dataclass
class ExportFunction:

    name: str

    rva: int

    ordinal: int



@dataclass
class ExportModule:


    name: str

    functions: list = field(
        default_factory=list
    )


    base_ordinal: int = 1



    def add_function(
            self,
            name,
            rva,
            ordinal=None
    ):


        if ordinal is None:

            ordinal = (
                self.base_ordinal
                +
                len(self.functions)
            )


        self.functions.append(

            ExportFunction(

                name,

                rva,

                ordinal

            )
        )



# ------------------------------------------------------------
# Builder
# ------------------------------------------------------------

class ExportBuilder:


    def __init__(
            self,
            module_name,
            bits=64
    ):


        if bits not in (32,64):

            raise ValueError(
                "bits must be 32 or 64"
            )


        self.bits = bits


        self.module = ExportModule(
            module_name
        )



    def add(
            self,
            name,
            rva,
            ordinal=None
    ):


        self.module.add_function(
            name,
            rva,
            ordinal
        )



    # --------------------------------------------------------
    # Build export section
    # --------------------------------------------------------

    def build(self, section_rva=0):


        funcs = (
            self.module.functions
        )


        if not funcs:

            raise ValueError(
                "No exports defined"
            )


        data = bytearray()



        #
        # Reserve export directory
        #

        directory_offset = len(data)


        data.extend(
            b"\x00"
            *
            IMAGE_EXPORT_DIRECTORY_SIZE
        )



        #
        # Export Address Table
        #

        address_table_offset = len(data)


        for fn in funcs:

            data.extend(
                struct.pack(
                    "<I",
                    fn.rva
                )
            )



        #
        # Export Name Pointer Table
        #

        name_table_offset = len(data)


        for fn in funcs:

            data.extend(
                b"\x00\x00\x00\x00"
            )



        #
        # Export Ordinal Table
        #

        ordinal_table_offset = len(data)


        for fn in funcs:

            data.extend(
                struct.pack(
                    "<H",
                    fn.ordinal
                    -
                    self.module.base_ordinal
                )
            )



        #
        # Strings
        #

        function_name_offsets = []


        for fn in funcs:


            function_name_offsets.append(
                len(data)
            )


            data.extend(
                fn.name.encode(
                    "ascii"
                )
            )

            data.append(
                0
            )



        module_name_offset = len(data)


        data.extend(
            self.module.name.encode(
                "ascii"
            )
        )

        data.append(
            0
        )



        #
        # Patch name table with RVAs
        #

        for i,off in enumerate(
            function_name_offsets
        ):


            struct.pack_into(

                "<I",

                data,

                name_table_offset +
                i*4,

                section_rva + off

            )



        #
        # Patch directory with RVAs
        #

        struct.pack_into(

            "<IIHHIIIIIII",

            data,

            directory_offset,

            0,

            0,

            0,

            0,

            section_rva + module_name_offset,

            self.module.base_ordinal,

            len(funcs),

            len(funcs),

            section_rva + address_table_offset,

            section_rva + name_table_offset,

            section_rva + ordinal_table_offset

        )



        return bytes(data)

    def fix_rvas(self, raw, section_rva):
        return self.build(section_rva=section_rva)
