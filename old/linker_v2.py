#!/usr/bin/env python3
"""
PE template patcher.

Keeps an original PE as a template.

Used for:

    - rebuilding .text
    - replacing .idata
    - replacing .edata
    - replacing .reloc

Preserves:

    - DOS header
    - NT headers
    - section table
    - resources
    - certificates
    - overlays


Supports:

    PE32
    PE32+
"""


from pathlib import Path
import struct



IMAGE_DOS_SIGNATURE = b"MZ"
IMAGE_NT_SIGNATURE = b"PE\x00\x00"

IMAGE_SIZEOF_SECTION_HEADER = 40



# ------------------------------------------------------------
# Alignment
# ------------------------------------------------------------

def align(value, alignment):

    return (
        (value + alignment - 1)
        //
        alignment
    ) * alignment



# ------------------------------------------------------------
# PE template
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


        self.parse()



    # --------------------------------------------------------
    # Parse PE
    # --------------------------------------------------------

    def parse(self):


        data = self.data


        if data[:2] != IMAGE_DOS_SIGNATURE:

            raise ValueError(
                "Not PE"
            )


        pe_offset = struct.unpack_from(

            "<I",

            data,

            0x3c

        )[0]



        if data[
            pe_offset:
            pe_offset+4
        ] != IMAGE_NT_SIGNATURE:


            raise ValueError(
                "Invalid PE"
            )



        self.pe_offset = pe_offset



        file_header = (
            pe_offset + 4
        )


        self.number_sections = struct.unpack_from(

            "<H",

            data,

            file_header + 2

        )[0]



        optional_size = struct.unpack_from(

            "<H",

            data,

            file_header + 16

        )[0]



        self.optional_offset = (
            file_header + 20
        )



        self.section_offset = (

            self.optional_offset

            +

            optional_size

        )



        for i in range(
            self.number_sections
        ):


            off = (

                self.section_offset

                +

                i * IMAGE_SIZEOF_SECTION_HEADER

            )


            name = data[
                off:
                off+8
            ].rstrip(
                b"\0"
            ).decode(
                errors="ignore"
            )



            virtual_size,virtual_address,raw_size,raw_ptr = struct.unpack_from(

                "<IIII",

                data,

                off+8

            )



            self.sections.append(

                {

                    "name": name,

                    "header": off,

                    "rva": virtual_address,

                    "virtual_size": virtual_size,

                    "raw_size": raw_size,

                    "raw_ptr": raw_ptr

                }

            )



    # --------------------------------------------------------
    # Find section
    # --------------------------------------------------------

    def section(
            self,
            name
    ):


        for sec in self.sections:


            if sec["name"] == name:

                return sec



        return None



    # --------------------------------------------------------
    # Replace section
    # --------------------------------------------------------

    def replace_section(
            self,
            name,
            blob
    ):


        sec = self.section(
            name
        )


        if sec is None:

            raise ValueError(

                "Missing section "
                +
                name

            )



        raw_size = sec["raw_size"]

        raw_ptr = sec["raw_ptr"]



        if len(blob) > raw_size:

            raise ValueError(

                "replacement too large"

            )



        #
        # write new data
        #

        self.data[
            raw_ptr:
            raw_ptr+len(blob)
        ] = blob



        #
        # zero remaining bytes
        #

        remaining = (

            raw_size
            -
            len(blob)

        )


        if remaining:


            self.data[
                raw_ptr+len(blob):
                raw_ptr+raw_size
            ] = (
                b"\0"
                *
                remaining
            )



        #
        # update virtual size
        #

        struct.pack_into(

            "<I",

            self.data,

            sec["header"]+8,

            len(blob)

        )



    # --------------------------------------------------------
    # Update directory
    # --------------------------------------------------------

    def set_directory(
            self,
            index,
            rva,
            size
    ):


        optional_magic = struct.unpack_from(

            "<H",

            self.data,

            self.optional_offset

        )[0]



        if optional_magic == 0x10b:

            directory_offset = (
                self.optional_offset
                +
                96
            )


        else:

            directory_offset = (
                self.optional_offset
                +
                112
            )



        offset = (

            directory_offset

            +

            index * 8

        )


        struct.pack_into(

            "<II",

            self.data,

            offset,

            rva,

            size

        )



    # --------------------------------------------------------
    # Change entry point
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
    # Add bytes at end
    # --------------------------------------------------------

    def append_overlay(
            self,
            blob
    ):


        self.data.extend(
            blob
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