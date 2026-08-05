#!/usr/bin/env python3
"""
x64 PE exception metadata builder.

Creates:

    .pdata
    .xdata


Supports:

    PE32+ only


Used by:

    linker.py
"""


import struct



IMAGE_REL_BASED_DIR64 = 10



# ------------------------------------------------------------
# Alignment
# ------------------------------------------------------------

def align(
        value,
        size
):

    return (

        (value + size - 1)

        //

        size

    ) * size



# ------------------------------------------------------------
# Runtime Function Entry
# ------------------------------------------------------------

class RuntimeFunction:


    def __init__(
            self,
            begin,
            end,
            unwind
    ):


        self.begin = begin

        self.end = end

        self.unwind = unwind



    def pack(self):

        return struct.pack(

            "<III",

            self.begin,

            self.end,

            self.unwind

        )



# ------------------------------------------------------------
# Unwind information
# ------------------------------------------------------------

class UnwindInfo:


    def __init__(self):


        self.version = 1

        self.flags = 0


        self.prologue_size = 0


        self.codes = []


        self.frame_register = 0

        self.frame_offset = 0



    def build(self):


        count = len(

            self.codes

        )


        header = (

            self.version

            |

            (

                self.flags

                <<

                3

            )

        )



        frame = (

            self.frame_register

            |

            (

                self.frame_offset

                <<

                4

            )

        )



        data = bytearray()



        data += struct.pack(

            "<BBBB",

            header,

            self.prologue_size,

            count,

            frame

        )



        for code in self.codes:

            data += code



        #
        # UNWIND_INFO must be aligned
        #

        while len(data) % 4:

            data += b"\x00"



        return bytes(data)



# ------------------------------------------------------------
# PDATA builder
# ------------------------------------------------------------

class PDataBuilder:


    def __init__(self):


        self.functions = []


        self.xdata = bytearray()



    # --------------------------------------------------------
    # Add function
    # --------------------------------------------------------

    def add_function(
            self,
            begin,
            end
    ):


        #
        # Current xdata RVA placeholder
        #

        unwind_offset = len(

            self.xdata

        )


        unwind = UnwindInfo()


        self.xdata += unwind.build()



        self.functions.append(

            RuntimeFunction(

                begin,

                end,

                unwind_offset

            )

        )



    # --------------------------------------------------------
    # Build xdata + pdata
    # --------------------------------------------------------

    def build(self):


        #
        # xdata comes immediately after pdata
        # RVA fixup is performed by linker
        #

        pdata = bytearray()



        for fn in self.functions:


            pdata += fn.pack()



        return (

            bytes(pdata),

            bytes(self.xdata)

        )



    # --------------------------------------------------------
    # Linker helper
    # --------------------------------------------------------

    def patch_rvas(
            self,
            pdata_rva,
            xdata_rva
    ):


        #
        # Convert xdata offsets
        # into real RVAs
        #

        fixed = []



        for fn in self.functions:


            fixed.append(

                RuntimeFunction(

                    fn.begin,

                    fn.end,

                    xdata_rva + fn.unwind

                )

            )



        self.functions = fixed



    # --------------------------------------------------------
    # Directory information
    # --------------------------------------------------------

    def directory_info(
            self,
            pdata_rva
    ):


        return {

            "exception": {

                "rva":

                    pdata_rva,


                "size":

                    len(self.functions)
                    *
                    12

            }

        }