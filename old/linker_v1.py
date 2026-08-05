#!/usr/bin/env python3
"""
Simple PE linker.

Connects:

    assembler
    imports
    exports
    relocations
    sections
    builder


Supports:

    PE32
    PE32+

    EXE
    DLL
"""


from dataclasses import dataclass, field


from pebuilder.builder import PEBuilder

from pebuilder.sections import (
    PESection,
    make_text,
    make_idata,
    make_edata,
    make_reloc,
)


from pebuilder.imports import ImportBuilder

from pebuilder.exports import ExportBuilder

from pebuilder.reloc import (
    make_reloc_section
)



# ------------------------------------------------------------
# Linked image
# ------------------------------------------------------------

@dataclass
class LinkedImage:


    text = None

    idata = None

    edata = None

    reloc = None


    imports = None

    exports = None



# ------------------------------------------------------------
# Linker
# ------------------------------------------------------------

class Linker:


    def __init__(
            self,
            bits=64,
            dll=False
    ):


        self.bits = bits

        self.dll = dll


        self.builder = PEBuilder(

            bits=bits,

            dll=dll

        )


        self.image = LinkedImage()



        self.imports = ImportBuilder(
            bits
        )


        self.exports = ExportBuilder(
            "output.dll",
            bits
        )



        self.has_imports = False

        self.has_exports = False



        self.relocations = []



    # --------------------------------------------------------
    # Add text
    # --------------------------------------------------------

    def add_text(
            self,
            data,
            entry=None
    ):


        self.image.text = make_text(
            data
        )


        self.builder.add_section(
            self.image.text
        )


        if entry:

            self.builder.entry_point = entry



    # --------------------------------------------------------
    # Imports
    # --------------------------------------------------------

    def add_import(
            self,
            dll,
            function
    ):


        self.has_imports = True


        target = None


        for existing in self.imports.dlls:


            if existing.name.lower() == dll.lower():

                target = existing

                break



        if target is None:

            target = self.imports.add_dll(
                dll
            )


        target.add(
            function
        )



    def build_imports(self):


        if not self.has_imports:

            return



        raw = self.imports.build()


        self.image.idata = make_idata(
            raw
        )


        self.image.idata.fixup = (
            self.imports.fix_rvas
        )


        self.builder.add_section(
            self.image.idata
        )


        self.builder.add_import_directory(
            self.image.idata
        )



    # --------------------------------------------------------
    # Exports
    # --------------------------------------------------------

    def add_export(
            self,
            name,
            rva
    ):


        self.has_exports = True


        self.exports.add(
            name,
            rva
        )



    def build_exports(self):


        if not self.has_exports:

            return



        raw = self.exports.build()


        self.image.edata = make_edata(
            raw
        )


        self.image.edata.fixup = (
            self.exports.fix_rvas
        )


        self.builder.add_section(
            self.image.edata
        )


        self.builder.add_export_directory(
            self.image.edata
        )



    # --------------------------------------------------------
    # Relocations
    # --------------------------------------------------------

    def add_relocations(
            self,
            relocs
    ):

        self.relocations.extend(
            relocs
        )



    def build_relocations(self):


        if not self.relocations:

            return



        raw = make_reloc_section(

            self.relocations,

            self.image.text.virtual_address,

            self.bits

        )


        self.image.reloc = make_reloc(
            raw
        )


        self.builder.add_section(
            self.image.reloc
        )


        self.builder.add_reloc_directory(
            self.image.reloc
        )



    # --------------------------------------------------------
    # Final link
    # --------------------------------------------------------

    def link(
            self,
            output
    ):


        self.build_imports()

        self.build_exports()

        self.build_relocations()


        return self.builder.build(
            output
        )