#!/usr/bin/env python3
"""
PE Bound Import Directory handler.

Supports:

    PE32
    PE32+

Preserves:

    IMAGE_BOUND_IMPORT_DESCRIPTOR


Used with:

    template.py
"""


from pathlib import Path
import struct



IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11



BOUND_IMPORT_DESCRIPTOR_SIZE = 8



class PEBoundImports:


    def __init__(
            self,
            filename
    ):


        self.filename = filename


        self.data = bytearray(

            Path(filename).read_bytes()

        )


        self.bits = None


        self.bound = None


        self.entries = []


        self.parse()



    # --------------------------------------------------------
    # Parse PE
    # --------------------------------------------------------

    def parse(self):


        pe = struct.unpack_from(

            "<I",

            self.data,

            0x3c

        )[0]


        fh = pe + 4


        optional = fh + 20


        magic = struct.unpack_from(

            "<H",

            self.data,

            optional

        )[0]



        if magic == 0x10b:


            self.bits = 32


            directory = optional + 96



        elif magic == 0x20b:


            self.bits = 64


            directory = optional + 112



        else:


            raise ValueError(
                "Invalid PE"
            )



        rva,size = struct.unpack_from(

            "<II",

            self.data,

            directory
            +
            IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT*8

        )



        if rva == 0:


            return



        self.bound = {


            "rva": rva,

            "size": size

        }


        self.read_entries()



    # --------------------------------------------------------
    # RVA to file offset
    # --------------------------------------------------------

    def rva_to_offset(
            self,
            rva
    ):


        pe = struct.unpack_from(

            "<I",

            self.data,

            0x3c

        )[0]


        fh = pe+4


        count = struct.unpack_from(

            "<H",

            self.data,

            fh+2

        )[0]


        optional = fh+20


        optional_size = struct.unpack_from(

            "<H",

            self.data,

            fh+16

        )[0]


        section_table = optional + optional_size



        for i in range(count):


            off = section_table+i*40


            va,size,raw = struct.unpack_from(

                "<III",

                self.data,

                off+8

            )


            if va <= rva < va+size:


                return raw+(rva-va)



        raise ValueError(
            "Invalid RVA"
        )



    # --------------------------------------------------------
    # Read descriptors
    # --------------------------------------------------------

    def read_entries(self):


        if not self.bound:

            return



        start = self.rva_to_offset(

            self.bound["rva"]

        )


        base = start



        while True:


            timestamp,name_offset,forwarder_count = struct.unpack_from(

                "<IHH",

                self.data,

                start

            )



            #
            # Null descriptor ends list
            #

            if (

                timestamp == 0

                and

                name_offset == 0

                and

                forwarder_count == 0

            ):

                break



            name_pos = (

                base

                +

                name_offset

            )



            name = b""


            while self.data[name_pos] != 0:


                name += bytes(

                    [
                        self.data[name_pos]
                    ]

                )


                name_pos += 1



            self.entries.append(

                {

                    "timestamp": timestamp,

                    "name": name.decode(

                        errors="ignore"

                    ),

                    "forwarders": forwarder_count

                }

            )



            start += BOUND_IMPORT_DESCRIPTOR_SIZE



            #
            # skip forwarder refs
            #

            start += (

                forwarder_count

                *

                BOUND_IMPORT_DESCRIPTOR_SIZE

            )



    # --------------------------------------------------------
    # Extract raw data
    # --------------------------------------------------------

    def extract(self):


        if not self.bound:

            return None



        off = self.rva_to_offset(

            self.bound["rva"]

        )


        size = self.bound["size"]


        return bytes(

            self.data[

                off:
                off+size

            ]

        )



    # --------------------------------------------------------
    # Patch directory
    # --------------------------------------------------------

    def patch_directory(
            self,
            rva,
            size
    ):


        pe = struct.unpack_from(

            "<I",

            self.data,

            0x3c

        )[0]


        fh = pe+4


        optional = fh+20



        if self.bits == 32:

            directory = optional+96

        else:

            directory = optional+112



        struct.pack_into(

            "<II",

            self.data,

            directory
            +
            IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT*8,

            rva,

            size

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