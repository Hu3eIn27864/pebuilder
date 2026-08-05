#!/usr/bin/env python3
"""
Example x64 PE build using:

    assembler
    linker
    pdata
    imports
    reloc

Creates:

    .text
    .pdata
    .xdata
    .idata
    .reloc
"""


from pebuilder.linker import Linker
from pebuilder.pdata import PDataBuilder
from pebuilder.imports import ImportBuilder
from pebuilder.reloc import RelocationBuilder



# ------------------------------------------------------------
# Example machine code
# ------------------------------------------------------------
#
# x64:
#
#   sub rsp,28h
#   call MessageBoxA
#   add rsp,28h
#   ret
#
# Normally this comes from assembler.py
#

code = bytes(
    [
        0x48,0x83,0xEC,0x28,
        0xC3,
        0x48,0x83,0xC4,0x28,
        0xC3
    ]
)



# ------------------------------------------------------------
# Create linker
# ------------------------------------------------------------

linker = Linker(

    bits=64,

    dll=False

)



# ------------------------------------------------------------
# Add code section
# ------------------------------------------------------------

linker.add_text(

    code,

    entry=0

)



# ------------------------------------------------------------
# Add x64 unwind metadata
# ------------------------------------------------------------
#
# Function:
#
# RVA 0x1000
#
# Size:
#
# 0x50 bytes
#
# In a real build these addresses come from
# the linker section layout.
#

pdata = PDataBuilder()



pdata.add_function(

    0x1000,

    0x1050

)



linker.register(

    "pdata",

    pdata

)



# ------------------------------------------------------------
# Add imports
# ------------------------------------------------------------

imports = ImportBuilder(

    bits=64

)


imports.add(

    "KERNEL32.dll",

    "ExitProcess"

)


linker.register(

    "imports",

    imports

)



# ------------------------------------------------------------
# Add relocations
# ------------------------------------------------------------

reloc = RelocationBuilder(

    bits=64

)


#
# Example:
#
# absolute address fixup
#
# RVA 0x1010
#

reloc.add(

    0x1010

)



linker.register(

    "reloc",

    reloc

)



# ------------------------------------------------------------
# Build
# ------------------------------------------------------------

linker.link(

    "example64.exe"

)


print(

    "created example64.exe"

)