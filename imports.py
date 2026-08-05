#!/usr/bin/env python3
"""
PE import Directory builder.

Creates .idata.

Supports:

    PE32
    PE32+

    import DLLs
    import functions
    import Address Table
    import Lookup Table

Used only when the binary imports
Windows APIs.
"""


import struct

from dataclasses import dataclass, field



# ------------------------------------------------------------
# Structures
# ------------------------------------------------------------

@dataclass
class ImportFunction:

    name: str



@dataclass
class ImportDLL:

    name: str

    functions: list = field(
        default_factory=list
    )


    def add(
            self,
            name
    ):

        self.functions.append(
            ImportFunction(name)
        )



# ------------------------------------------------------------
# Builder
# ------------------------------------------------------------

class ImportBuilder:


    def __init__(
            self,
            bits=64
    ):


        if bits not in (32,64):

            raise ValueError(
                "bits must be 32 or 64"
            )


        self.bits = bits


        self.dlls = []



    # --------------------------------------------------------
    # Add DLL
    # --------------------------------------------------------

    def add_dll(
            self,
            name
    ):


        dll = ImportDLL(
            name
        )


        self.dlls.append(
            dll
        )


        return dll



    def add(
            self,
            dll,
            function
    ):
        for d in self.dlls:
            if d.name.lower() == dll.lower():
                d.add(function)
                return d
        d = self.add_dll(dll)
        d.add(function)
        return d

    # --------------------------------------------------------
    # Pointer size
    # --------------------------------------------------------

    def ptr_size(self):

        return (
            8
            if self.bits == 64
            else 4
        )



    # --------------------------------------------------------
    # Build raw .idata
    # --------------------------------------------------------

    def build(self, section_rva=0):


        if not self.dlls:

            raise ValueError(
                "No imports"
            )


        data = bytearray()

        ptr = self.ptr_size()

        #
        # Reserve import descriptors
        # One extra null descriptor
        #

        descriptor_offset = 0

        descriptor_count = (
            len(self.dlls)+1
        )

        data.extend(
            b"\x00"
            *
            (
                descriptor_count
                *
                20
            )
        )

        #
        # ILT
        #

        ilt_offsets = {}

        for dll in self.dlls:
            ilt_offsets[dll.name] = len(data)
            for fn in dll.functions:
                data.extend(b"\x00" * ptr)
            # null thunk
            data.extend(b"\x00" * ptr)

        #
        # IAT
        #

        iat_offsets = {}

        for dll in self.dlls:
            iat_offsets[dll.name] = len(data)
            for fn in dll.functions:
                data.extend(b"\x00" * ptr)
            # null thunk
            data.extend(b"\x00" * ptr)

        #
        # Hint/name entries
        #

        hint_offsets = {}

        for dll in self.dlls:
            for fn in dll.functions:
                hint_offsets[fn.name] = len(data)
                data.extend(struct.pack("<H", 0))
                data.extend(fn.name.encode("ascii"))
                data.append(0)

        #
        # DLL names
        #

        dll_name_offsets = {}

        for dll in self.dlls:
            dll_name_offsets[dll.name] = len(data)
            data.extend(dll.name.encode("ascii"))
            data.append(0)

        #
        # Patch ILT and IAT with correct RVAs
        #

        fmt = "<I" if self.bits == 32 else "<Q"

        for dll in self.dlls:
            offset = ilt_offsets[dll.name]
            for fn in dll.functions:
                thunk_rva = section_rva + hint_offsets[fn.name]
                struct.pack_into(fmt, data, offset, thunk_rva)
                offset += ptr

        for dll in self.dlls:
            offset = iat_offsets[dll.name]
            for fn in dll.functions:
                thunk_rva = section_rva + hint_offsets[fn.name]
                struct.pack_into(fmt, data, offset, thunk_rva)
                offset += ptr

        #
        # Patch descriptors with correct RVAs
        #

        for index, dll in enumerate(self.dlls):
            offset = descriptor_offset + index * 20
            struct.pack_into(
                "<IIIII",
                data,
                offset,
                section_rva + ilt_offsets[dll.name],
                0,
                0,
                section_rva + dll_name_offsets[dll.name],
                section_rva + iat_offsets[dll.name]
            )

        return bytes(data)

    # --------------------------------------------------------
    # RVA fixer
    # --------------------------------------------------------

    def fix_rvas(
            self,
            raw,
            section_rva
    ):
        return self.build(section_rva=section_rva)



        data = bytearray(
            raw
        )


        ptr = self.ptr_size()



        descriptor_count = (
            len(self.dlls)
        )


        descriptor_size = (
            (descriptor_count+1)
            *
            20
        )


        #
        # Calculate areas
        #

        ilt = descriptor_size


        ilt_size = 0


        for dll in self.dlls:

            ilt_size += (
                (len(dll.functions)+1)
                *
                ptr
            )


        iat = ilt + ilt_size


        names = iat + ilt_size



        #
        # Fix descriptors
        #

        for index,dll in enumerate(
            self.dlls
        ):


            off = (
                index*20
            )


            struct.pack_into(

                "<IIIII",

                data,

                off,

                section_rva + ilt,

                0,

                0,

                section_rva + names,

                section_rva + iat

            )


            ilt += (
                (len(dll.functions)+1)
                *
                ptr
            )


            iat += (
                (len(dll.functions)+1)
                *
                ptr
            )


        #
        # Fix thunk values
        #

        name_ptr = names


        for dll in self.dlls:


            name_ptr += (
                len(dll.name.encode())
                +
                1
            )


            for fn in dll.functions:


                name_rva = (
                    section_rva
                    +
                    name_ptr
                )


                #
                # ILT/IAT already point
                # to the same offsets.
                #

                name_ptr += (
                    2
                    +
                    len(fn.name.encode())
                    +
                    1
                )


        return bytes(data)