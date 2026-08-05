#!/usr/bin/env python3
"""
Metadata aware PE linker.

Targets the new PEBuilder / PESection API.

Supports:

    PE32
    PE32+

    EXE
    DLL


Responsibilities:

    - collect sections
    - assign RVAs
    - build metadata sections
    - patch pdata/xdata
    - register PE data directories
    - invoke PEBuilder
"""


from dataclasses import dataclass

from pebuilder.pe import align

from pebuilder.sections import (
    PESection,
    SectionTable,

    make_text,
    make_rdata,
    make_data,
    make_idata,
    make_edata,
    make_reloc,

    code_section_flags,
    data_section_flags,
)

from pebuilder.builder import PEBuilder


SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200



# ------------------------------------------------------------
# Section characteristics
# ------------------------------------------------------------

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



# ------------------------------------------------------------
# PE directory constants & indexes
# ------------------------------------------------------------

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11
IMAGE_DIRECTORY_ENTRY_IAT = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14


DIRECTORY_INDEX = {
    ".edata": IMAGE_DIRECTORY_ENTRY_EXPORT,
    ".idata": IMAGE_DIRECTORY_ENTRY_IMPORT,
    ".rsrc": IMAGE_DIRECTORY_ENTRY_RESOURCE,
    ".pdata": IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    ".reloc": IMAGE_DIRECTORY_ENTRY_BASERELOC,
    ".debug": IMAGE_DIRECTORY_ENTRY_DEBUG,
    ".tls": IMAGE_DIRECTORY_ENTRY_TLS,
}

DIRECTORY_MAP = {
    "export": IMAGE_DIRECTORY_ENTRY_EXPORT,
    "exports": IMAGE_DIRECTORY_ENTRY_EXPORT,
    ".edata": IMAGE_DIRECTORY_ENTRY_EXPORT,
    "0": IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DIRECTORY_ENTRY_EXPORT: IMAGE_DIRECTORY_ENTRY_EXPORT,

    "import": IMAGE_DIRECTORY_ENTRY_IMPORT,
    "imports": IMAGE_DIRECTORY_ENTRY_IMPORT,
    ".idata": IMAGE_DIRECTORY_ENTRY_IMPORT,
    "1": IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT: IMAGE_DIRECTORY_ENTRY_IMPORT,

    "resource": IMAGE_DIRECTORY_ENTRY_RESOURCE,
    "resources": IMAGE_DIRECTORY_ENTRY_RESOURCE,
    ".rsrc": IMAGE_DIRECTORY_ENTRY_RESOURCE,
    "2": IMAGE_DIRECTORY_ENTRY_RESOURCE,
    IMAGE_DIRECTORY_ENTRY_RESOURCE: IMAGE_DIRECTORY_ENTRY_RESOURCE,

    "exception": IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    "exceptions": IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    "pdata": IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    ".pdata": IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    "3": IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    IMAGE_DIRECTORY_ENTRY_EXCEPTION: IMAGE_DIRECTORY_ENTRY_EXCEPTION,

    "security": IMAGE_DIRECTORY_ENTRY_SECURITY,
    "4": IMAGE_DIRECTORY_ENTRY_SECURITY,
    IMAGE_DIRECTORY_ENTRY_SECURITY: IMAGE_DIRECTORY_ENTRY_SECURITY,

    "reloc": IMAGE_DIRECTORY_ENTRY_BASERELOC,
    "relocs": IMAGE_DIRECTORY_ENTRY_BASERELOC,
    "basereloc": IMAGE_DIRECTORY_ENTRY_BASERELOC,
    ".reloc": IMAGE_DIRECTORY_ENTRY_BASERELOC,
    "5": IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_BASERELOC: IMAGE_DIRECTORY_ENTRY_BASERELOC,

    "debug": IMAGE_DIRECTORY_ENTRY_DEBUG,
    ".debug": IMAGE_DIRECTORY_ENTRY_DEBUG,
    "6": IMAGE_DIRECTORY_ENTRY_DEBUG,
    IMAGE_DIRECTORY_ENTRY_DEBUG: IMAGE_DIRECTORY_ENTRY_DEBUG,

    "architecture": IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
    "7": IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,

    "globalptr": IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
    "8": IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR: IMAGE_DIRECTORY_ENTRY_GLOBALPTR,

    "tls": IMAGE_DIRECTORY_ENTRY_TLS,
    ".tls": IMAGE_DIRECTORY_ENTRY_TLS,
    "9": IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_DIRECTORY_ENTRY_TLS: IMAGE_DIRECTORY_ENTRY_TLS,

    "load_config": IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
    "10": IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,

    "bound_import": IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
    "bound_imports": IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
    "11": IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,

    "iat": IMAGE_DIRECTORY_ENTRY_IAT,
    "12": IMAGE_DIRECTORY_ENTRY_IAT,
    IMAGE_DIRECTORY_ENTRY_IAT: IMAGE_DIRECTORY_ENTRY_IAT,

    "delay_import": IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    "13": IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,

    "com_descriptor": IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
    "14": IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
}




# ------------------------------------------------------------
# Section wrapper
# ------------------------------------------------------------

@dataclass
class LinkedSection:

    section: PESection



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


        self.image_base = image_base



        self.sections = []


        self.providers = {}


        self.entry = None



    # --------------------------------------------------------
    # Add provider
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

            section

    ):


        if not isinstance(

                section,

                PESection

        ):

            raise TypeError(
                "expected PESection"
            )


        self.sections.append(

            LinkedSection(section)

        )



    # --------------------------------------------------------
    # Add code
    # --------------------------------------------------------

    def add_text(

            self,

            data,

            entry=0

    ):


        sec = make_text(

            data

        )


        self.add_section(

            sec

        )


        self.entry = (

            sec,

            entry

        )



    # --------------------------------------------------------
    # Metadata generation
    # --------------------------------------------------------

    def build_metadata(self):


        if "imports" in self.providers:


            self.add_section(

                make_idata(

                    self.providers["imports"].build()

                )

            )



        if "exports" in self.providers:


            self.add_section(

                make_edata(

                    self.providers["exports"].build()

                )

            )



        if "reloc" in self.providers:


            self.add_section(

                make_reloc(

                    self.providers["reloc"].build()

                )

            )



        if "resources" in self.providers:


            self.add_section(

                PESection(

                    ".rsrc",

                    self.providers["resources"].build(),

                    data_section_flags()

                )

            )



        if "debug" in self.providers:


            self.add_section(

                PESection(

                    ".debug",

                    self.providers["debug"].build(),

                    data_section_flags()

                )

            )



        #
        # x64 unwind information
        #

        if "pdata" in self.providers:


            pdata, xdata = (

                self.providers["pdata"].build()

            )


            self.add_section(

                PESection(

                    ".pdata",

                    pdata,

                    data_section_flags()

                )

            )


            self.add_section(

                PESection(

                    ".xdata",

                    xdata,

                    data_section_flags()

                )

            )

    # --------------------------------------------------------
    # Build PE image
    # --------------------------------------------------------

    def build_image(self):

        table = SectionTable(
            section_alignment=SECTION_ALIGNMENT,
            file_alignment=FILE_ALIGNMENT
        )

        for linked in self.sections:
            sec = linked.section if isinstance(linked, LinkedSection) else linked

            pe_sec = PESection(
                sec.name,
                bytearray(sec.data),
                sec.characteristics
            )
            pe_sec.virtual_size = getattr(sec, "virtual_size", len(sec.data)) # <-- HIER HINZUGEFÜGT

            table.add(
                pe_sec
            )

        headers_size = (
            0x80
            + 4
            + 20
            + (
                0xF0
                if self.bits == 64
                else 0xE0
            )
            + (
                len(table.sections)
                * 40
            )
        )

        headers_size = align(
            headers_size,
            FILE_ALIGNMENT
        )

        table.layout(
            headers_size
        )

        #
        # Copy final RVAs back
        #

        for old, new in zip(
                self.sections,
                table.sections
        ):
            sec_obj = old.section if isinstance(old, LinkedSection) else old
            sec_obj.virtual_address = new.virtual_address
            sec_obj.raw_pointer = new.raw_pointer

            if hasattr(old, "rva"):
                old.rva = new.virtual_address
            if hasattr(old, "raw_offset"):
                old.raw_offset = new.raw_pointer

        #
        # Rebuild directories
        #

        self.collect_directories()

        return table

    # --------------------------------------------------------
    # Collect section directories
    # --------------------------------------------------------

    def collect_directories(self):
            if not hasattr(self, "directories") or self.directories is None:
                self.directories = {}

            for linked in self.sections:
                sec = linked.section if isinstance(linked, LinkedSection) else linked
                sname = sec.name.lower()
                if sname in DIRECTORY_INDEX:
                    idx = DIRECTORY_INDEX[sname]
                    # Nur eintragen, wenn nicht manuell vorgegeben!
                    if idx not in self.directories:
                        rva = getattr(sec, "virtual_address", getattr(sec, "rva", 0))
                        size = len(sec.data) if hasattr(sec, "data") else 0
                        self.directories[idx] = {
                            "rva": rva,
                            "size": size
                        }

    # --------------------------------------------------------
    # Entry RVA helper
    # --------------------------------------------------------

    def entry_rva(self):
        if self.entry is None:
            if self.sections:
                first = self.sections[0]
                sec = first.section if isinstance(first, LinkedSection) else first
                return getattr(sec, "virtual_address", getattr(sec, "rva", 0))
            return 0

        if isinstance(self.entry, (int, float)):
            return int(self.entry)

        if isinstance(self.entry, tuple):
            sec, offset = self.entry
            sec_obj = sec.section if isinstance(sec, LinkedSection) else sec
            rva = getattr(sec_obj, "virtual_address", getattr(sec_obj, "rva", 0))
            return rva + offset

        return 0

    # --------------------------------------------------------
    # Convert directories
    # --------------------------------------------------------

    def directory_table(self):
        result = {}

        if not hasattr(self, "directories") or self.directories is None:
            self.directories = {}

        for name, value in self.directories.items():
            if isinstance(value, dict):
                rva = value.get("rva", 0)
                size = value.get("size", 0)
            elif isinstance(value, (list, tuple)):
                rva, size = value[0], value[1]
            else:
                continue

            if name in DIRECTORY_MAP:
                result[DIRECTORY_MAP[name]] = (rva, size)
            elif isinstance(name, int) and 0 <= name < 16:
                result[name] = (rva, size)

        return result




    # --------------------------------------------------------
    # Link final executable
    # --------------------------------------------------------

    def link(
            self,
            filename
    ):


        table = self.build_image()



        builder = PEBuilder(
            bits=self.bits,
            dll=self.dll,
            image_base=self.image_base,
            section_alignment=SECTION_ALIGNMENT,
            file_alignment=FILE_ALIGNMENT,
            subsystem=getattr(self, "subsystem", 2),  # <-- HIER HINZUGEFÜGT
            dos_stub=getattr(self, "dos_stub", None),  # <-- HIER HINZUGEFÜGT
            timestamp=getattr(self, "timestamp", 0),
            checksum=getattr(self, "checksum", 0),
            os_ver=getattr(self, "os_ver", (6, 0, 0, 0, 6, 0)),
            file_characteristics=getattr(self, "file_characteristics", 0x0002),
            linker_ver=getattr(self, "linker_ver", (0, 0)),
            size_of_init_data=getattr(self, "size_of_init_data", None),
            size_of_uninit_data=getattr(self, "size_of_uninit_data", None),
            size_of_image_override=getattr(self, "size_of_image_override", None),
            dll_characteristics=getattr(self, "dll_characteristics", 0x8140),
            size_of_code_override=getattr(self, "size_of_code_override", None)
        )



        #
        # Add sections using new API
        #

        for sec in table.sections:

            builder.add_section(
                sec
            )



        #
        # Entry point
        #

        builder.entry_point = (

            self.entry_rva()

        )



        #
        # Data directories
        #

        builder.directories.update(

            self.directory_table()

        )



        #
        # Emit PE
        #

        return builder.build(

            filename

        )



# ------------------------------------------------------------
# Convenience helpers
# ------------------------------------------------------------

def link_exe(
        filename,
        text,
        bits=64
):


    linker = Linker(
        bits=bits,
        dll=False
    )


    linker.add_text(
        text,
        0
    )


    return linker.link(
        filename
    )



def link_dll(
        filename,
        text,
        bits=64
):


    linker = Linker(
        bits=bits,
        dll=True
    )


    linker.add_text(
        text,
        0
    )


    return linker.link(
        filename
    )