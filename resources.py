#!/usr/bin/env python3
"""
PE resource extractor / replacer.

Preserves the .rsrc section.

Typical resources:

    RT_ICON
    RT_GROUP_ICON
    RT_VERSION
    RT_MANIFEST
    RT_STRING
    RT_DIALOG


This module does not rebuild individual
resource trees. It preserves the raw
resource section and allows relocation.
"""


from pathlib import Path

import struct



IMAGE_DIRECTORY_ENTRY_RESOURCE = 2



class PEResources:


    def __init__(
            self,
            filename
    ):


        self.filename = filename

        self.data = bytearray(

            Path(filename).read_bytes()

        )


        self.resource = None


        self.optional_offset = None


        self.parse()



    # --------------------------------------------------------
    # Parse resource directory
    # --------------------------------------------------------

    def parse(self):


        data = self.data


        pe = struct.unpack_from(

            "<I",

            data,

            0x3c

        )[0]


        file_header = pe + 4


        optional_size = struct.unpack_from(

            "<H",

            data,

            file_header+16

        )[0]


        self.optional_offset = (

            file_header+20

        )


        section_offset = (

            self.optional_offset

            +

            optional_size

        )


        sections = struct.unpack_from(

            "<H",

            data,

            file_header+2

        )[0]



        for i in range(sections):


            off = (

                section_offset

                +

                i*40

            )


            name = data[
                off:
                off+8
            ].rstrip(
                b"\0"
            ).decode(
                errors="ignore"
            )


            virtual_size,rva,raw_size,raw_ptr = struct.unpack_from(

                "<IIII",

                data,

                off+8

            )



            if name == ".rsrc":

                self.resource = {

                    "rva": rva,

                    "raw_ptr": raw_ptr,

                    "raw_size": raw_size,

                    "header": off

                }


                break



    # --------------------------------------------------------
    # Extract
    # --------------------------------------------------------

    def extract(self):


        if not self.resource:

            return None



        r = self.resource


        return bytes(

            self.data[

                r["raw_ptr"]:

                r["raw_ptr"]+
                r["raw_size"]

            ]

        )



    # --------------------------------------------------------
    # Replace resource section
    # --------------------------------------------------------

    def replace(
            self,
            blob
    ):


        if not self.resource:

            raise ValueError(
                "No .rsrc section"
            )


        r = self.resource


        if len(blob) > r["raw_size"]:

            raise ValueError(
                "Resource section too small"
            )



        self.data[

            r["raw_ptr"]:
            r["raw_ptr"]+len(blob)

        ] = blob



        remaining = (

            r["raw_size"]
            -
            len(blob)

        )


        if remaining:


            self.data[

                r["raw_ptr"]+len(blob):

                r["raw_ptr"]+
                r["raw_size"]

            ] = (

                b"\0"*remaining

            )



        struct.pack_into(

            "<I",

            self.data,

            r["header"]+8,

            len(blob)

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