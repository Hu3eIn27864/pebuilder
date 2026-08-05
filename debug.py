#!/usr/bin/env python3
"""
PE Debug Directory preservation.

Supports:

    PE32
    PE32+

Preserves:

    IMAGE_DEBUG_DIRECTORY
    CodeView RSDS data
    PDB metadata


Used with:

    template.py
"""


from pathlib import Path
import struct



IMAGE_DIRECTORY_ENTRY_DEBUG = 6

IMAGE_DEBUG_TYPE_CODEVIEW = 2



IMAGE_DEBUG_DIRECTORY_SIZE = 28



# ------------------------------------------------------------
# Debug handler
# ------------------------------------------------------------

class PEDebug:


    def __init__(
            self,
            filename
    ):


        self.filename = filename


        self.data = bytearray(

            Path(filename).read_bytes()

        )


        self.bits = None


        self.debug = None


        self.entries = []


        self.parse()



    # --------------------------------------------------------
    # Parse
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
            IMAGE_DIRECTORY_ENTRY_DEBUG*8

        )



        if rva == 0:

            return



        offset = self.rva_to_offset(
            rva
        )


        count = (

            size

            //

            IMAGE_DEBUG_DIRECTORY_SIZE

        )



        for i in range(count):


            off = (

                offset

                +

                i*IMAGE_DEBUG_DIRECTORY_SIZE

            )


            entry = {


                "characteristics":
                    struct.unpack_from(
                        "<I",
                        self.data,
                        off
                    )[0],


                "timestamp":
                    struct.unpack_from(
                        "<I",
                        self.data,
                        off+4
                    )[0],


                "type":
                    struct.unpack_from(
                        "<I",
                        self.data,
                        off+12
                    )[0],


                "size":
                    struct.unpack_from(
                        "<I",
                        self.data,
                        off+16
                    )[0],


                "address":
                    struct.unpack_from(
                        "<I",
                        self.data,
                        off+20
                    )[0],


                "raw":
                    struct.unpack_from(
                        "<I",
                        self.data,
                        off+24
                    )[0]

            }


            self.entries.append(
                entry
            )



        self.debug = {

            "rva": rva,

            "size": size

        }



    # --------------------------------------------------------
    # Extract raw debug data
    # --------------------------------------------------------

    def extract(self):


        result = []


        for e in self.entries:


            raw = e["raw"]

            size = e["size"]


            result.append(

                bytes(

                    self.data[

                        raw:
                        raw+size

                    ]

                )

            )


        return result



    # --------------------------------------------------------
    # Find RSDS PDB info
    # --------------------------------------------------------

    def pdb_info(self):


        for blob in self.extract():


            if blob[:4] == b"RSDS":


                guid = blob[4:20]


                age = struct.unpack_from(

                    "<I",

                    blob,

                    20

                )[0]


                pdb = blob[24:].rstrip(

                    b"\0"

                ).decode(

                    errors="ignore"

                )


                return {

                    "guid": guid.hex(),

                    "age": age,

                    "pdb": pdb

                }


        return None



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


        optional_size = struct.unpack_from(

            "<H",

            self.data,

            fh+16

        )[0]


        sh = optional + optional_size



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
            "RVA invalid"
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
            IMAGE_DIRECTORY_ENTRY_DEBUG*8,

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