#!/usr/bin/env python3
"""
Disassembly -> PE reassembler.

Consumes a disassembly listing and feeds:

    assembler.py
            |
            v
        linker.py
            |
            v
        builder.py


Supports:

    x86
    x64

    EXE
    DLL
"""


import argparse
import re


from pathlib import Path


from pebuilder.assembler import (
    X86Assembler,
    AsmSection
)


from pebuilder.linker import Linker



# ------------------------------------------------------------
# Disassembly parser
# ------------------------------------------------------------

class DisassemblyParser:


    def __init__(
            self,
            image_base=0,
            section_name=".text"
    ):

        self.image_base = image_base

        self.section_name = (
            section_name
        )



    def parse(
            self,
            filename
    ):


        section = AsmSection(

            self.section_name,

            0x1000

        )


        entry = None



        with open(
            filename,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:


            for line in f:


                line = line.strip()


                if not line:

                    continue



                #
                # Address line
                #

                m = re.match(

                    r"0x([0-9a-fA-F]+):\s*(.*)",

                    line

                )


                if not m:

                    continue



                address = int(

                    m.group(1),

                    16

                )


                if entry is None:

                    entry = address



                text = m.group(2)



                #
                # Remove comments
                #

                if ";" in text:

                    text = text.split(

                        ";",

                        1

                    )[0]


                text = text.strip()



                if not text:

                    continue



                #
                # DB data
                #

                if text.lower().startswith(
                    "db"
                ):


                    values = []


                    for item in text[2:].split(","):


                        item = item.strip()


                        if item:


                            values.append(

                                int(

                                    item,

                                    0

                                )

                                &

                                0xff

                            )


                    section.bytes(

                        address,

                        bytes(values)

                    )


                else:


                    section.instruction(

                        address,

                        text

                    )



        return section, entry



# ------------------------------------------------------------
# Reassembler
# ------------------------------------------------------------

class PEReassembler:


    def __init__(
            self,
            bits=64,
            dll=False,
            image_base=None
    ):


        self.bits = bits

        self.dll = dll

        self.image_base = image_base



        self.parser = DisassemblyParser()



        self.imports = []

        self.exports = []



    # --------------------------------------------------------
    # Add import requirement
    # --------------------------------------------------------

    def add_import(
            self,
            dll,
            function
    ):

        self.imports.append(

            (
                dll,

                function

            )

        )



    # --------------------------------------------------------
    # Add export
    # --------------------------------------------------------

    def add_export(
            self,
            name,
            rva
    ):

        self.exports.append(

            (
                name,

                rva

            )

        )



    # --------------------------------------------------------
    # Rebuild
    # --------------------------------------------------------

    def rebuild(
            self,
            listing,
            output
    ):


        #
        # Parse disassembly
        #

        section,entry = (
            self.parser.parse(
                listing
            )
        )



        #
        # Assemble
        #

        assembler = X86Assembler(
            self.bits
        )


        code,relocs = (
            assembler.assemble_section(
                section
            )
        )



        #
        # Link
        #

        linker = Linker(

            bits=self.bits,

            dll=self.dll

        )



        linker.add_text(

            code,

            entry=section.virtual_address

        )



        #
        # Imports
        #

        for dll,fn in self.imports:


            linker.add_import(

                dll,

                fn

            )



        #
        # Exports
        #

        for name,rva in self.exports:


            linker.add_export(

                name,

                rva

            )



        #
        # Relocations
        #

        linker.add_relocations(
            relocs
        )



        return linker.link(
            output
        )



# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

def main():


    p = argparse.ArgumentParser()


    p.add_argument(
        "--disasm",
        required=True
    )


    p.add_argument(
        "--output",
        required=True
    )


    p.add_argument(
        "--bits",
        type=int,
        default=64
    )


    p.add_argument(
        "--dll",
        action="store_true"
    )


    args = p.parse_args()



    r = PEReassembler(

        bits=args.bits,

        dll=args.dll

    )


    r.rebuild(

        args.disasm,

        args.output

    )


    print(
        "written:",
        args.output
    )



if __name__ == "__main__":

    main()