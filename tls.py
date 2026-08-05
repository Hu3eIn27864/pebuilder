#!/usr/bin/env python3
"""
PE TLS directory preservation.

Supports:

    PE32
    PE32+

Preserves:

    TLS directory
    TLS raw data
    TLS callback array


Used with:

    template.py
    builder.py
"""


from pathlib import Path
import struct



IMAGE_DIRECTORY_ENTRY_TLS = 9



# ------------------------------------------------------------
# TLS handler
# ------------------------------------------------------------

class PETLS:


    def __init__(
            self,
            filename
    ):


        self.filename = filename


        self.data = bytearray(

            Path(filename).read_bytes()

        )


        self.bits = None


        self.tls = None


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


        file_header = pe + 4


        optional = file_header + 20


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
                "Unknown PE"
            )



        tls_rva,tls_size = struct.unpack_from(

            "<II",

            self.data,

            directory + IMAGE_DIRECTORY_ENTRY_TLS*8

        )


        if tls_rva == 0:

            return



        self.tls = {

            "rva": tls_rva,

            "size": tls_size

        }



    # --------------------------------------------------------
    # Extract TLS directory bytes
    # --------------------------------------------------------

    def extract_directory(self):


        if not self.tls:

            return None


        offset = self.rva_to_offset(

            self.tls["rva"]

        )


        size = self.tls["size"]


        return bytes(

            self.data[

                offset:
                offset+size

            ]

        )



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


        fh = pe + 4


        sections = struct.unpack_from(

            "<H",

            self.data,

            fh+2

        )[0]


        opt = fh + 20


        opt_size = struct.unpack_from(

            "<H",

            self.data,

            fh+16

        )[0]


        sh = opt + opt_size



        for i in range(sections):


            off = sh + i*40


            va,size,raw_ptr = struct.unpack_from(

                "<III",

                self.data,

                off+8

            )


            if va <= rva < va+size:


                return (

                    raw_ptr

                    +

                    (rva-va)

                )


        raise ValueError(
            "RVA outside sections"
        )



    # --------------------------------------------------------
    # Patch TLS directory
    # --------------------------------------------------------

    def patch_directory(
            self,
            new_rva,
            new_size
    ):


        pe = struct.unpack_from(

            "<I",

            self.data,

            0x3c

        )[0]


        fh = pe+4


        opt = fh+20


        if self.bits == 32:

            directory = opt+96

        else:

            directory = opt+112



        struct.pack_into(

            "<II",

            self.data,

            directory + IMAGE_DIRECTORY_ENTRY_TLS*8,

            new_rva,

            new_size

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