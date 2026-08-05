#!/usr/bin/env python3
"""
PE linker.

Combines:

    assembler.py
    imports.py
    exports.py
    reloc.py
    sections.py


Produces:

    linked PE layout

Supports:

    PE32
    PE32+

    EXE
    DLL
"""


from dataclasses import dataclass, field


from pebuilder.sections import PESection



# ------------------------------------------------------------
# Constants
# ------------------------------------------------------------

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000



SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200



# ------------------------------------------------------------
# Alignment
# ------------------------------------------------------------

def align(value, alignment):

    return (
        (value + alignment - 1)
        //
        alignment
    ) * alignment



# ------------------------------------------------------------
# Linked section
# ------------------------------------------------------------

@dataclass
class LinkedSection:

    name: str

    data: bytes

    rva: int = 0

    raw_offset: int = 0

    characteristics: int = 0



# ------------------------------------------------------------
# Linker
# ------------------------------------------------------------

class Linker:


    def __init__(
            self,
            bits=64,
            dll=False,
            image_base=None
    ):


        self.bits = bits

        self.dll = dll


        if image_base is None:

            if bits == 32:

                image_base = 0x400000

            else:

                image_base = 0x140000000



        self.image_base = image_base



        self.sections = []



        self.entry_point = None



        self.import_builder = None

        self.export_builder = None

        self.reloc_builder = None



        self.extra_directories = {}



    # --------------------------------------------------------
    # Add code
    # --------------------------------------------------------

    def add_text(
            self,
            data,
            entry=None
    ):


        sec = LinkedSection(

            ".text",

            bytes(data),

            characteristics=(

                IMAGE_SCN_CNT_CODE

                |

                IMAGE_SCN_MEM_EXECUTE

                |

                IMAGE_SCN_MEM_READ

            )

        )


        self.sections.append(
            sec
        )



        if entry is not None:

            self.entry_point = (

                ".text",

                entry

            )



    # --------------------------------------------------------
    # Add generic section
    # --------------------------------------------------------

    def add_section(
            self,
            name,
            data,
            characteristics
    ):


        self.sections.append(

            LinkedSection(

                name,

                bytes(data),

                characteristics=characteristics

            )

        )



    # --------------------------------------------------------
    # Imports
    # --------------------------------------------------------

    def add_import(
            self,
            dll,
            function
    ):


        if self.import_builder is None:

            from pebuilder.imports import ImportBuilder

            self.import_builder = ImportBuilder(

                bits=self.bits

            )


        self.import_builder.add(

            dll,

            function

        )



    # --------------------------------------------------------
    # Exports
    # --------------------------------------------------------

    def add_export(
            self,
            name,
            rva
    ):


        if self.export_builder is None:

            from pebuilder.exports import ExportBuilder


            self.export_builder = ExportBuilder(

                bits=self.bits

            )


        self.export_builder.add(

            name,

            rva

        )



    # --------------------------------------------------------
    # Relocations
    # --------------------------------------------------------

    def add_relocations(
            self,
            relocations
    ):


        if self.reloc_builder is None:


            from pebuilder.reloc import RelocationBuilder


            self.reloc_builder = RelocationBuilder(

                bits=self.bits

            )


        for r in relocations:

            self.reloc_builder.add(
                r
            )



    # --------------------------------------------------------
    # Metadata directories
    # --------------------------------------------------------

    def add_directory(
            self,
            name,
            data
    ):


        self.extra_directories[name] = bytes(data)



    # --------------------------------------------------------
    # Build sections
    # --------------------------------------------------------

    def build_sections(self):


        #
        # Add generated sections
        #

        if self.import_builder:


            data = self.import_builder.build()


            self.add_section(

                ".idata",

                data,

                (

                    IMAGE_SCN_CNT_INITIALIZED_DATA

                    |

                    IMAGE_SCN_MEM_READ

                    |

                    IMAGE_SCN_MEM_WRITE

                )

            )



        if self.export_builder:


            data = self.export_builder.build()


            self.add_section(

                ".edata",

                data,

                (

                    IMAGE_SCN_CNT_INITIALIZED_DATA

                    |

                    IMAGE_SCN_MEM_READ

                )

            )



        if self.reloc_builder:


            data = self.reloc_builder.build()


            self.add_section(

                ".reloc",

                data,

                (

                    IMAGE_SCN_CNT_INITIALIZED_DATA

                    |

                    IMAGE_SCN_MEM_READ

                )

            )



    # --------------------------------------------------------
    # Layout sections
    # --------------------------------------------------------

    def layout(self):


        self.build_sections()



        rva = SECTION_ALIGNMENT



        raw = 0



        #
        # header space reserved
        #

        raw = align(

            0x1000,

            FILE_ALIGNMENT

        )



        for sec in self.sections:


            sec.rva = align(

                rva,

                SECTION_ALIGNMENT

            )


            sec.raw_offset = align(

                raw,

                FILE_ALIGNMENT

            )


            rva = (

                sec.rva

                +

                align(

                    len(sec.data),

                    SECTION_ALIGNMENT

                )

            )


            raw = (

                sec.raw_offset

                +

                align(

                    len(sec.data),

                    FILE_ALIGNMENT

                )

            )



    # --------------------------------------------------------
    # Resolve entry
    # --------------------------------------------------------

    def get_entry_rva(self):


        if self.entry_point is None:

            return 0



        name,offset = self.entry_point



        for sec in self.sections:


            if sec.name == name:


                return sec.rva + offset



        raise ValueError(
            "entry section missing"
        )



    # --------------------------------------------------------
    # Link
    # --------------------------------------------------------

    def link(
            self,
            output
    ):


        self.layout()



        from pebuilder.builder import PEBuilder



        builder = PEBuilder(

            bits=self.bits,

            dll=self.dll,

            image_base=self.image_base

        )



        for sec in self.sections:


            builder.add_section(

                sec.name,

                sec.data,

                sec.characteristics,

                sec.rva,

                sec.raw_offset

            )



        builder.entry_point = (

            self.get_entry_rva()

        )



        #
        # Directory information
        #

        for name,data in self.extra_directories.items():


            builder.directories[name] = data



        builder.write(

            output

        )



        return output