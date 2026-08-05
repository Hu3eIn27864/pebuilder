#!/usr/bin/env python3
"""
PE header generation.

Supports:

    PE32
    PE32+

Creates:

    DOS header
    NT headers
    File header
    Optional header
    Data directories
"""


import struct



# ------------------------------------------------------------
# Constants
# ------------------------------------------------------------

IMAGE_DOS_SIGNATURE = b"MZ"

IMAGE_NT_SIGNATURE = b"PE\x00\x00"


IMAGE_FILE_MACHINE_I386 = 0x014C

IMAGE_FILE_MACHINE_AMD64 = 0x8664



IMAGE_SIZEOF_SECTION_HEADER = 40



IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B

IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B



IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002

IMAGE_FILE_DLL = 0x2000



IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16



# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def align(
        value,
        alignment
):

    return (
        (value + alignment - 1)
        //
        alignment
    ) * alignment



# ------------------------------------------------------------
# PE format
# ------------------------------------------------------------

class PEFormat:


    def __init__(
            self,
            bits=64
    ):


        if bits not in (32,64):

            raise ValueError(
                "bits must be 32 or 64"
            )


        self.bits = bits



        if bits == 32:

            self.machine = (
                IMAGE_FILE_MACHINE_I386
            )

            self.optional_magic = (
                IMAGE_NT_OPTIONAL_HDR32_MAGIC
            )

            self.optional_size = (
                0xE0
            )

            self.image_base_default = (
                0x400000
            )


        else:

            self.machine = (
                IMAGE_FILE_MACHINE_AMD64
            )

            self.optional_magic = (
                IMAGE_NT_OPTIONAL_HDR64_MAGIC
            )

            self.optional_size = (
                0xF0
            )

            self.image_base_default = (
                0x140000000
            )



# ------------------------------------------------------------
# DOS header
# ------------------------------------------------------------

def build_dos_header():

    header = bytearray(
        0x80
    )


    header[0:2] = (
        IMAGE_DOS_SIGNATURE
    )


    #
    # e_lfanew
    #

    struct.pack_into(
        "<I",
        header,
        0x3C,
        0x80
    )


    return bytes(header)



# ------------------------------------------------------------
# NT headers
# ------------------------------------------------------------

def build_nt_headers(

        fmt,

        number_sections,

        dll,

        image_base,

        entry_point,

        base_of_code,

        size_of_code,

        size_of_data,

        size_of_image,

        size_of_headers,

        section_alignment,

        file_alignment,

        directories=None

):


    if directories is None:

        directories = {}



    output = bytearray()



    #
    # Signature
    #

    output.extend(
        IMAGE_NT_SIGNATURE
    )



    #
    # File header
    #

    characteristics = (
        IMAGE_FILE_EXECUTABLE_IMAGE
    )


    if dll:

        characteristics |= (
            IMAGE_FILE_DLL
        )


    struct.pack_into(

        "<HHIIIHH",

        output,

        len(output),

        fmt.machine,

        number_sections,

        0,

        0,

        0,

        fmt.optional_size,

        characteristics

    )


    output.extend(
        b"\x00"
        *
        20
    )



    #
    # Optional header
    #

    optional = bytearray(
        fmt.optional_size
    )



    #
    # Common fields
    #

    struct.pack_into(

        "<HBB",

        optional,

        0,

        fmt.optional_magic,

        0,

        0

    )



    #
    # Sizes
    #

    struct.pack_into(

        "<III",

        optional,

        4,

        size_of_code,

        size_of_data,

        0

    )



    #
    # Entry/code/data
    #

    struct.pack_into(

        "<III",

        optional,

        16,

        entry_point,

        base_of_code,

        0

    )



    if fmt.bits == 32:


        #
        # PE32
        #

        struct.pack_into(

            "<I",

            optional,

            28,

            image_base

        )


        struct.pack_into(

            "<II",

            optional,

            32,

            section_alignment,

            file_alignment

        )


        data_directory_offset = 96



    else:


        #
        # PE32+
        #

        struct.pack_into(

            "<Q",

            optional,

            24,

            image_base

        )


        struct.pack_into(

            "<II",

            optional,

            32,

            section_alignment,

            file_alignment

        )


        data_directory_offset = 112



    #
    # Version fields
    #

    struct.pack_into(

        "<HHHHHH",

        optional,

        40,

        6,

        0,

        0,

        0,

        6,

        0

    )



    #
    # Image sizes
    #

    struct.pack_into(

        "<III",

        optional,

        56,

        size_of_image,

        size_of_headers,

        0

    )



    #
    # Subsystem
    #

    struct.pack_into(

        "<H",

        optional,

        68,

        3

    )



    #
    # DLL characteristics
    #

    dll_chars = (

        0x8140

    )


    struct.pack_into(

        "<H",

        optional,

        70,

        dll_chars

    )



    #
    # Stack/heap
    #

    if fmt.bits == 32:


        struct.pack_into(

            "<IIII",

            optional,

            72,

            0x100000,

            0x1000,

            0x100000,

            0x1000

        )


        number_rva_offset = 92


    else:


        struct.pack_into(

            "<QQQQ",

            optional,

            72,

            0x100000,

            0x1000,

            0x100000,

            0x1000

        )


        number_rva_offset = 108



    #
    # Number of directories
    #

    struct.pack_into(

        "<I",

        optional,

        number_rva_offset,

        IMAGE_NUMBEROF_DIRECTORY_ENTRIES

    )



    #
    # Data directories
    #

    for index,(rva,size) in directories.items():


        if index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES:

            continue


        offset = (

            data_directory_offset

            +

            index * 8

        )


        struct.pack_into(

            "<II",

            optional,

            offset,

            rva,

            size

        )



    output.extend(
        optional
    )


    return bytes(output)