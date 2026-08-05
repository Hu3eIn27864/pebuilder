#!/usr/bin/env python3
"""
Metadata-aware PE linker.

Supports:

    PE32
    PE32+

    EXE
    DLL


Automatically manages:

    .text
    .idata
    .edata
    .reloc
    .tls
    .pdata
    .xdata
    .rsrc
    .debug
"""


from dataclasses import dataclass



SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200



IMAGE_SCN_CODE = (
    0x00000020 |
    0x20000000 |
    0x40000000
)


IMAGE_SCN_DATA = (
    0x00000040 |
    0x40000000
)


IMAGE_SCN_RW_DATA = (
    0x00000040 |
    0x40000000 |
    0x80000000
)



DIRECTORY_NAMES = {

    ".idata": "import",

    ".edata": "export",

    ".reloc": "reloc",

    ".tls": "tls",

    ".pdata": "exception",

    ".rsrc": "resource",

    ".debug": "debug",

    ".loadcfg": "load_config",

    ".bind": "bound_import"

}



def align(value, alignment):

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

    raw_offset: int = 0



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

            self.image_base = (

                0x400000

                if bits == 32

                else

                0x140000000

            )

        else:

            self.image_base = image_base



        self.sections = []


        self.providers = {}


        self.directories = {}


        self.entry = None



    # --------------------------------------------------------
    # Register provider
    # --------------------------------------------------------

    def register(
            self,
            name,
            provider
    ):

        self.providers[name] = provider



    # --------------------------------------------------------
    # Add section
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
    # Code
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
    # Generate metadata
    # --------------------------------------------------------

    def build_metadata(self):


        if "imports" in self.providers:


            self.add_section(

                ".idata",

                self.providers["imports"].build(),

                IMAGE_SCN_RW_DATA

            )



        if "exports" in self.providers:


            self.add_section(

                ".edata",

                self.providers["exports"].build(),

                IMAGE_SCN_DATA

            )



        if "reloc" in self.providers:


            self.add_section(

                ".reloc",

                self.providers["reloc"].build(),

                IMAGE_SCN_DATA

            )



        if "tls" in self.providers:


            self.add_section(

                ".tls",

                self.providers["tls"].build(),

                IMAGE_SCN_RW_DATA

            )



        #
        # x64 exception data
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



        if "resources" in self.providers:


            self.add_section(

                ".rsrc",

                self.providers["resources"].build(),

                IMAGE_SCN_DATA

            )



        if "debug" in self.providers:


            self.add_section(

                ".debug",

                self.providers["debug"].build(),

                IMAGE_SCN_DATA

            )



        if "load_config" in self.providers:


            self.add_section(

                ".loadcfg",

                self.providers["load_config"].build(),

                IMAGE_SCN_DATA

            )



        if "bound_import" in self.providers:


            self.add_section(

                ".bind",

                self.providers["bound_import"].build(),

                IMAGE_SCN_DATA

            )



    # --------------------------------------------------------
    # Layout
    # --------------------------------------------------------

    def layout(self):


        self.build_metadata()


        rva = SECTION_ALIGNMENT


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



        self.fix_pdata()



    # --------------------------------------------------------
    # Fix x64 unwind RVAs
    # --------------------------------------------------------

    def fix_pdata(self):


        if "pdata" not in self.providers:

            return



        pdata_provider = self.providers["pdata"]



        pdata_rva = None

        xdata_rva = None



        for sec in self.sections:


            if sec.name == ".pdata":

                pdata_rva = sec.rva



            if sec.name == ".xdata":

                xdata_rva = sec.rva



        if (

            pdata_rva is None

            or

            xdata_rva is None

        ):

            return



        pdata_provider.patch_rvas(

            pdata_rva,

            xdata_rva

        )



        #
        # rebuild pdata with fixed addresses
        #

        pdata,xdata = (

            pdata_provider.build()

        )



        for sec in self.sections:


            if sec.name == ".pdata":

                sec.data = pdata


            elif sec.name == ".xdata":

                sec.data = xdata



    # --------------------------------------------------------
    # Directories
    # --------------------------------------------------------

    def collect_directories(self):


        for sec in self.sections:


            if sec.name in DIRECTORY_NAMES:


                name = DIRECTORY_NAMES[

                    sec.name

                ]


                self.directories[name] = {


                    "rva":
                        sec.rva,


                    "size":
                        len(sec.data)

                }



    # --------------------------------------------------------
    # Entry RVA
    # --------------------------------------------------------

    def entry_rva(self):


        if self.entry is None:

            return 0



        section,offset = self.entry



        for sec in self.sections:


            if sec.name == section:


                return sec.rva + offset



        return 0



    # --------------------------------------------------------
    # Link
    # --------------------------------------------------------

    def link(
            self,
            filename
    ):


        self.layout()


        self.collect_directories()



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



        builder.entry_point = self.entry_rva()



        builder.directories.update(

            self.directories

        )



        builder.write(

            filename

        )



        return filename