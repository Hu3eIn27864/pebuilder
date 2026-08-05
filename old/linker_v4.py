#!/usr/bin/env python3
"""
Metadata-aware PE linker.

Automatically places:

    .text
    .idata
    .edata
    .reloc
    .tls
    .pdata
    .xdata
    .rsrc
    .debug


Supports:

    PE32
    PE32+

    EXE
    DLL
"""


from dataclasses import dataclass


from pebuilder.sections import PESection



SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200



IMAGE_SCN_CODE = (
    0x00000020
    |
    0x20000000
    |
    0x40000000
)


IMAGE_SCN_DATA = (
    0x00000040
    |
    0x40000000
)


IMAGE_SCN_RW_DATA = (
    0x00000040
    |
    0x40000000
    |
    0x80000000
)



DIRECTORIES = {

    ".edata":
        "export",

    ".idata":
        "import",

    ".rsrc":
        "resource",

    ".reloc":
        "reloc",

    ".tls":
        "tls",

    ".pdata":
        "exception",

    ".debug":
        "debug",

    ".loadcfg":
        "load_config",

    ".bind":
        "bound_import"

}



def align(
        value,
        alignment
):

    return (

        (value + alignment - 1)

        //

        alignment

    ) * alignment



@dataclass
class LinkedSection:

    name: str

    data: bytes

    characteristics: int

    rva: int = 0

    raw: int = 0



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

            image_base = (

                0x400000
                if bits == 32
                else
                0x140000000

            )


        self.image_base = image_base


        self.sections = []


        self.directories = {}


        self.entry = None



        #
        # providers
        #

        self.providers = {}



    # --------------------------------------------------------
    # Provider registration
    # --------------------------------------------------------

    def register(
            self,
            name,
            provider
    ):

        self.providers[name] = provider



    # --------------------------------------------------------
    # Add raw section
    # --------------------------------------------------------

    def add_section(
            self,
            name,
            data,
            characteristics=IMAGE_SCN_DATA
    ):

        self.sections.append(

            LinkedSection(

                name,

                bytes(data),

                characteristics

            )

        )



    # --------------------------------------------------------
    # Add code
    # --------------------------------------------------------

    def add_text(
            self,
            data,
            entry=0
    ):


        self.add_section(

            ".text",

            data,

            IMAGE_SCN_CODE

        )


        self.entry = (

            ".text",

            entry

        )



    # --------------------------------------------------------
    # Automatically build provider sections
    # --------------------------------------------------------

    def build_metadata_sections(self):


        #
        # imports
        #

        if "imports" in self.providers:


            self.add_section(

                ".idata",

                self.providers["imports"].build(),

                IMAGE_SCN_RW_DATA

            )



        #
        # exports
        #

        if "exports" in self.providers:


            self.add_section(

                ".edata",

                self.providers["exports"].build(),

                IMAGE_SCN_DATA

            )



        #
        # relocations
        #

        if "reloc" in self.providers:


            self.add_section(

                ".reloc",

                self.providers["reloc"].build(),

                IMAGE_SCN_DATA

            )



        #
        # TLS
        #

        if "tls" in self.providers:


            self.add_section(

                ".tls",

                self.providers["tls"].build(),

                IMAGE_SCN_RW_DATA

            )



        #
        # x64 exception metadata
        #

        if "pdata" in self.providers:


            pdata,xdata = (

                self.providers["pdata"].build()

            )


            self.add_section(

                ".pdata",

                pdata,

                IMAGE_SCN_DATA

            )


            self.add_section(

                ".xdata",

                xdata,

                IMAGE_SCN_DATA

            )



        #
        # resources
        #

        if "resources" in self.providers:


            self.add_section(

                ".rsrc",

                self.providers["resources"].build(),

                IMAGE_SCN_DATA

            )



        #
        # debug
        #

        if "debug" in self.providers:


            self.add_section(

                ".debug",

                self.providers["debug"].build(),

                IMAGE_SCN_DATA

            )



        #
        # load config
        #

        if "load_config" in self.providers:


            self.add_section(

                ".loadcfg",

                self.providers["load_config"].build(),

                IMAGE_SCN_DATA

            )



        #
        # bound imports
        #

        if "bound_import" in self.providers:


            self.add_section(

                ".bind",

                self.providers["bound_import"].build(),

                IMAGE_SCN_DATA

            )



    # --------------------------------------------------------
    # Assign layout
    # --------------------------------------------------------

    def layout(self):


        self.build_metadata_sections()



        next_rva = SECTION_ALIGNMENT


        next_raw = align(

            0x1000,

            FILE_ALIGNMENT

        )



        for sec in self.sections:


            sec.rva = align(

                next_rva,

                SECTION_ALIGNMENT

            )


            sec.raw = align(

                next_raw,

                FILE_ALIGNMENT

            )


            next_rva = (

                sec.rva

                +

                align(

                    len(sec.data),

                    SECTION_ALIGNMENT

                )

            )


            next_raw = (

                sec.raw

                +

                align(

                    len(sec.data),

                    FILE_ALIGNMENT

                )

            )



    # --------------------------------------------------------
    # Patch directories
    # --------------------------------------------------------

    def patch_directories(self):


        for sec in self.sections:


            if sec.name not in DIRECTORIES:

                continue



            directory = DIRECTORIES[

                sec.name

            ]


            self.directories[directory] = {


                "rva":
                    sec.rva,


                "size":
                    len(sec.data)

            }



    # --------------------------------------------------------
    # Entry point
    # --------------------------------------------------------

    def entry_rva(self):


        if not self.entry:

            return 0



        name,offset = self.entry



        for sec in self.sections:


            if sec.name == name:

                return sec.rva + offset



        return 0



    # --------------------------------------------------------
    # Final link
    # --------------------------------------------------------

    def link(
            self,
            filename
    ):


        self.layout()


        self.patch_directories()



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

                sec.raw

            )



        builder.entry_point = (

            self.entry_rva()

        )


        builder.directories.update(

            self.directories

        )


        builder.write(

            filename

        )


        return filename