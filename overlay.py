#!/usr/bin/env python3
"""
PE overlay handler.

A PE overlay is any data after:

    max(section.raw_ptr + section.raw_size)

Examples:

    installers
    self-extracting data
    embedded archives
    custom payloads


The overlay is NOT part of a PE section.
"""


from pathlib import Path

import struct



class PEOverlay:


    def __init__(
            self,
            filename
    ):


        self.filename = filename


        self.data = (

            Path(filename)
            .read_bytes()

        )


        self.offset = (
            self.find_offset()
        )



    # --------------------------------------------------------
    # Find overlay
    # --------------------------------------------------------

    def find_offset(self):


        data = self.data


        pe = struct.unpack_from(

            "<I",

            data,

            0x3c

        )[0]



        file_header = pe + 4


        sections = struct.unpack_from(

            "<H",

            data,

            file_header+2

        )[0]


        optional_size = struct.unpack_from(

            "<H",

            data,

            file_header+16

        )[0]



        section_table = (

            file_header
            +
            20
            +
            optional_size

        )


        end = 0



        for i in range(sections):


            off = (

                section_table

                +

                i*40

            )


            raw_ptr,raw_size = struct.unpack_from(

                "<II",

                data,

                off+20

            )


            end = max(

                end,

                raw_ptr+raw_size

            )



        return end



    # --------------------------------------------------------
    # Extract overlay
    # --------------------------------------------------------

    def extract(self):


        if self.offset >= len(self.data):

            return b""


        return self.data[
            self.offset:
        ]



    # --------------------------------------------------------
    # Append overlay
    # --------------------------------------------------------

    def append_to(
            self,
            filename
    ):


        overlay = self.extract()


        if overlay:


            with open(
                filename,
                "ab"
            ) as f:

                f.write(
                    overlay
                )