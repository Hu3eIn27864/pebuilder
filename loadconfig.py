#!/usr/bin/env python3
"""
PE Load Configuration Directory handler.

Supports:

    PE32
    PE32+

Preserves:

    IMAGE_LOAD_CONFIG_DIRECTORY

Tracks:

    Security cookie
    CFG metadata
    Guard tables


Used with:

    template.py
"""


from pathlib import Path
import struct



IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10



# ------------------------------------------------------------
# Handler
# ------------------------------------------------------------

class PELoadConfig:


    def __init__(
            self,
            filename
    ):


        self.filename = filename


        self.data = bytearray(

            Path(filename).read_bytes()

        )


        self.bits = None


        self.load_config = None


        self.fields = {}



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
                "Invalid optional header"
            )



        rva,size = struct.unpack_from(

            "<II",

            self.data,

            directory
            +
            IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG*8

        )



        if rva == 0:


            return



        self.load_config = {

            "rva": rva,

            "size": size

        }


        self.read_fields()



    # --------------------------------------------------------
    # RVA conversion
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


        sections = struct.unpack_from(

            "<H",

            self.data,

            fh+2

        )[0]


        optional = fh+20


        opt_size = struct.unpack_from(

            "<H",

            self.data,

            fh+16

        )[0]


        sh = optional+opt_size



        for i in range(sections):


            off = sh+i*40


            va,size,raw = struct.unpack_from(

                "<III",

                self.data,

                off+8

            )


            if va <= rva < va+size:


                return raw+(rva-va)



        raise ValueError(
            "Bad RVA"
        )



    # --------------------------------------------------------
    # Read important fields
    # --------------------------------------------------------

    def read_fields(self):


        if not self.load_config:

            return



        off = self.rva_to_offset(

            self.load_config["rva"]

        )


        #
        # Common first fields:
        #
        # Size
        # TimeDateStamp
        # MajorVersion
        # MinorVersion
        # GlobalFlagsClear
        #

        self.fields["size"] = struct.unpack_from(

            "<I",

            self.data,

            off

        )[0]



        if self.bits == 32:


            #
            # SecurityCookie offset:
            # IMAGE_LOAD_CONFIG_DIRECTORY32
            #

            self.fields["security_cookie"] = struct.unpack_from(

                "<I",

                self.data,

                off+60

            )[0]


            self.fields["guard_cf_check"] = struct.unpack_from(

                "<I",

                self.data,

                off+80

            )[0]


            self.fields["guard_cf_table"] = struct.unpack_from(

                "<I",

                self.data,

                off+84

            )[0]



            self.fields["guard_cf_count"] = struct.unpack_from(

                "<I",

                self.data,

                off+88

            )[0]



            self.fields["guard_flags"] = struct.unpack_from(

                "<I",

                self.data,

                off+92

            )[0]



        else:


            #
            # IMAGE_LOAD_CONFIG_DIRECTORY64
            #

            self.fields["security_cookie"] = struct.unpack_from(

                "<Q",

                self.data,

                off+88

            )[0]



            self.fields["guard_cf_check"] = struct.unpack_from(

                "<Q",

                self.data,

                off+120

            )[0]


            self.fields["guard_cf_table"] = struct.unpack_from(

                "<Q",

                self.data,

                off+128

            )[0]


            self.fields["guard_cf_count"] = struct.unpack_from(

                "<Q",

                self.data,

                off+136

            )[0]


            self.fields["guard_flags"] = struct.unpack_from(

                "<I",

                self.data,

                off+144

            )[0]



    # --------------------------------------------------------
    # Extract raw directory
    # --------------------------------------------------------

    def extract(self):


        if not self.load_config:

            return None



        off = self.rva_to_offset(

            self.load_config["rva"]

        )


        size = self.load_config["size"]


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
            IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG*8,

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