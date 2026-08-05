#!/usr/bin/env python3
"""
PE template patcher.

Uses an existing PE file as a base and
replaces selected sections while keeping
the original PE layout.

Preserves:

    - DOS header
    - PE headers
    - section layout
    - resources
    - overlay
    - certificate table bytes

Updates:

    - section sizes
    - entry point
    - data directories

Supports:

    PE32
    PE32+
"""


from pathlib import Path
import struct



IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_IAT = 12



IMAGE_SIZEOF_SECTION_HEADER = 40



# ------------------------------------------------------------
# helpers
# ------------------------------------------------------------

def align(value, alignment):

    return (
        (value + alignment - 1)
        //
        alignment
    ) * alignment



# ------------------------------------------------------------
# Template
# ------------------------------------------------------------

class PETemplate:


    def __init__(
            self,
            filename
    ):


        self.filename = filename


        self.data = bytearray(

            Path(filename).read_bytes()

        )


        self.sections = []

        self.directories = {}


        self.parse()



    # --------------------------------------------------------
    # Parse PE
    # --------------------------------------------------------

    def parse(self):


        if self.data[:2] != b"MZ":

            raise ValueError(
                "Invalid DOS header"
            )



        self.pe_offset = struct.unpack_from(

            "<I",

            self.data,

            0x3c

        )[0]



        if self.data[
            self.pe_offset:
            self.pe_offset+4
        ] != b"PE\0\0":

            raise ValueError(
                "Invalid PE signature"
            )



        file_header = (
            self.pe_offset + 4
        )


        self.number_sections = struct.unpack_from(

            "<H",

            self.data,

            file_header+2

        )[0]



        self.optional_offset = (

            file_header + 20

        )


        optional_size = struct.unpack_from(

            "<H",

            self.data,

            file_header+16

        )[0]



        self.section_table = (

            self.optional_offset

            +

            optional_size

        )



        self.optional_magic = struct.unpack_from(

            "<H",

            self.data,

            self.optional_offset

        )[0]



        if self.optional_magic == 0x10b:

            self.directory_offset = (

                self.optional_offset + 96

            )


        elif self.optional_magic == 0x20b:

            self.directory_offset = (

                self.optional_offset + 112

            )

        else:

            raise ValueError(
                "Unknown optional header"
            )



        self.parse_sections()



    # --------------------------------------------------------
    # Sections
    # --------------------------------------------------------

    def parse_sections(self):


        for i in range(
            self.number_sections
        ):


            off = (

                self.section_table

                +

                i * IMAGE_SIZEOF_SECTION_HEADER

            )


            name = self.data[

                off:
                off+8

            ].rstrip(
                b"\0"
            ).decode(
                errors="ignore"
            )


            virtual_size,virtual_address,raw_size,raw_ptr = struct.unpack_from(

                "<IIII",

                self.data,

                off+8

            )


            self.sections.append(

                {

                    "name": name,

                    "header": off,

                    "virtual_size": virtual_size,

                    "virtual_address": virtual_address,

                    "raw_size": raw_size,

                    "raw_ptr": raw_ptr

                }

            )



    # --------------------------------------------------------
    # Find section
    # --------------------------------------------------------

    def get_section(
            self,
            name
    ):


        for sec in self.sections:

            if sec["name"] == name:

                return sec


        return None



    # --------------------------------------------------------
    # Patch section
    # --------------------------------------------------------

    def replace_section(
            self,
            name,
            data
    ):


        sec = self.get_section(
            name
        )


        if not sec:

            raise ValueError(

                "Missing section: "
                +
                name

            )



        if len(data) > sec["raw_size"]:

            raise ValueError(

                f"{name} does not fit"

            )



        start = sec["raw_ptr"]


        self.data[
            start:
            start+len(data)
        ] = data



        if len(data) < sec["raw_size"]:

            self.data[

                start+len(data):
                start+sec["raw_size"]

            ] = (

                b"\0"
                *
                (
                    sec["raw_size"]
                    -
                    len(data)
                )

            )



        #
        # update VirtualSize
        #

        struct.pack_into(

            "<I",

            self.data,

            sec["header"]+8,

            len(data)

        )


        sec["virtual_size"] = len(data)



    # --------------------------------------------------------
    # Data directory
    # --------------------------------------------------------

    def set_directory(
            self,
            index,
            rva,
            size
    ):


        offset = (

            self.directory_offset

            +

            index*8

        )


        struct.pack_into(

            "<II",

            self.data,

            offset,

            rva,

            size

        )


        self.directories[index] = (

            rva,

            size

        )



    # --------------------------------------------------------
    # Convenience directory setters
    # --------------------------------------------------------

    def set_imports(
            self,
            section
    ):

        self.set_directory(

            IMAGE_DIRECTORY_ENTRY_IMPORT,

            section["virtual_address"],

            section["virtual_size"]

        )



    def set_exports(
            self,
            section
    ):

        self.set_directory(

            IMAGE_DIRECTORY_ENTRY_EXPORT,

            section["virtual_address"],

            section["virtual_size"]

        )



    def set_relocations(
            self,
            section
    ):

        self.set_directory(

            IMAGE_DIRECTORY_ENTRY_BASERELOC,

            section["virtual_address"],

            section["virtual_size"]

        )



    # --------------------------------------------------------
    # Entry point
    # --------------------------------------------------------

    def set_entry_point(
            self,
            rva
    ):


        struct.pack_into(

            "<I",

            self.data,

            self.optional_offset+16,

            rva

        )



    # --------------------------------------------------------
    # Preserve overlay
    # --------------------------------------------------------

    def extract_overlay(self):


        end = 0


        for sec in self.sections:


            end = max(

                end,

                sec["raw_ptr"]
                +
                sec["raw_size"]

            )


        return bytes(
            self.data[end:]
        )



    def append_overlay(
            self,
            overlay
    ):


        self.data.extend(
            overlay
        )



    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    def save(
            self,
            filename
    ):


        Path(filename).write_bytes(

            self.data

        )