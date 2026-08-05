#!/usr/bin/env python3
"""
PE assembler backend.

Features:
    - x86
    - x64
    - labels
    - two-pass assembly
    - branch fixups
    - relocation tracking

Output:
    bytes
    relocation RVAs
"""


from dataclasses import dataclass, field
import re
import struct

try:
    from keystone import (
        Ks,
        KS_ARCH_X86,
        KS_MODE_32,
        KS_MODE_64,
    )

except ImportError:
    Ks = None



# ------------------------------------------------------------
# Data structures
# ------------------------------------------------------------

@dataclass
class Relocation:

    """
    A relocation entry.

    rva:
        location containing absolute address

    type:
        HIGHLOW for x86
        DIR64 for x64
    """

    rva: int

    size: int



@dataclass
class Instruction:


    address: int

    text: str = None

    raw: bytes = None

    label: str = None



@dataclass
class AsmSection:


    name: str

    virtual_address: int

    items: list = field(
        default_factory=list
    )


    def label(self, name):

        self.items.append(
            Instruction(
                address=0,
                label=name
            )
        )


    def instruction(
            self,
            address,
            text
    ):

        self.items.append(
            Instruction(
                address,
                text=text
            )
        )


    def bytes(
            self,
            address,
            data
    ):

        self.items.append(
            Instruction(
                address,
                raw=data
            )
        )



# ------------------------------------------------------------
# Assembler
# ------------------------------------------------------------

class X86Assembler:


    def __init__(
            self,
            bits=64
    ):


        if Ks is None:
            raise ImportError(
                "pip install keystone-engine"
            )


        self.bits = bits


        mode = (
            KS_MODE_32
            if bits == 32
            else KS_MODE_64
        )


        self.ks = Ks(
            KS_ARCH_X86,
            mode
        )


        self.labels = {}

        self.relocations = []



    # --------------------------------------------------------
    # helpers
    # --------------------------------------------------------

    def relocation_size(self):

        return (
            4
            if self.bits == 32
            else 8
        )



    def assemble(
            self,
            text,
            address=0
    ):
        if isinstance(text, tuple):
            if len(text) >= 2:
                address, text = text[0], text[1]
            elif len(text) == 1:
                text = text[0]
        elif hasattr(text, "text"):
            address = getattr(text, "address", address)
            text = getattr(text, "text")

        if not text:
            return b""

        raw_comment_bytes = None
        if ";" in text:
            code_part, comment_part = text.split(";", 1)
            comment_tokens = comment_part.strip().split()
            if comment_tokens and all(re.fullmatch(r"[0-9A-Fa-f]{2}", t) for t in comment_tokens):
                raw_comment_bytes = bytes(int(t, 16) for t in comment_tokens)
            text = code_part.strip()

        if raw_comment_bytes is not None:
            return raw_comment_bytes

        if not text:
            return b""

        try:
            encoding, _ = self.ks.asm(
                text,
                address
            )
            return bytes(encoding)
        except Exception:
            if raw_comment_bytes is not None:
                return raw_comment_bytes
            print("FAILED ASM:")
            print("  text:", repr(text))
            print("  address:", hex(address) if isinstance(address, int) else address)
            raise


    def assemble_listing(self, instructions):
        """
        Assemble a Capstone/NASM-style listing.

        Supports:
            instruction
            db
            dw
            dd
            dq
            align
            times
            labels

        Returns:
            (bytes, relocations)
        """

        output = bytearray()

        for item in instructions:

            #
            # Support both
            #   (address, text)
            # and
            #   Instruction(...)
            #
            if isinstance(item, tuple):
                address, text = item
            else:
                address = item.address

                if item.raw:
                    output.extend(item.raw)
                    continue

                if item.label:
                    continue

                text = item.text

            text = text.strip()

            #
            # Skip empty/comment lines
            #
            if not text or text.startswith(";"):
                continue

            #
            # Extract raw bytes from comment if present (e.g. '; 48 83 EC 20')
            #
            comment_raw_bytes = None
            if ";" in text:
                code_part, comment_part = text.split(";", 1)
                comment_tokens = comment_part.strip().split()
                if comment_tokens and all(re.fullmatch(r"[0-9A-Fa-f]{2}", t) for t in comment_tokens):
                    comment_raw_bytes = bytes(int(t, 16) for t in comment_tokens)
                text = code_part.strip()

            if comment_raw_bytes is not None:
                output.extend(comment_raw_bytes)
                self.detect_relocations(comment_raw_bytes, address)
                continue

            if not text:
                continue

            #
            # Label:
            #
            if text.endswith(":"):
                continue


            #
            # ALIGN n
            #
            m = re.match(r"align\s+(\d+)", text, re.I)
            if m:
                align = int(m.group(1))

                while len(output) % align:
                    output.append(0x90)

                continue

            #
            # TIMES n db ...
            #
            m = re.match(
                r"times\s+(\d+)\s+(.*)",
                text,
                re.I,
            )

            if m:
                count = int(m.group(1))
                body = m.group(2)

                fake = [(address, body)]

                blob, _ = self.assemble_listing(fake)

                output.extend(blob * count)

                continue

            #
            # DB
            #
            if text.lower().startswith("db "):

                values = re.findall(
                    r"0x[0-9A-Fa-f]+|\d+",
                    text[3:]
                )

                output.extend(
                    int(v, 0)
                    for v in values
                )

                continue

            #
            # DW
            #
            if text.lower().startswith("dw "):

                values = re.findall(
                    r"0x[0-9A-Fa-f]+|\d+",
                    text[3:]
                )

                for v in values:
                    output.extend(
                        struct.pack(
                            "<H",
                            int(v, 0)
                        )
                    )

                continue

            #
            # DD
            #
            if text.lower().startswith("dd "):

                values = re.findall(
                    r"0x[0-9A-Fa-f]+|\d+",
                    text[3:]
                )

                for v in values:
                    output.extend(
                        struct.pack(
                            "<I",
                            int(v, 0)
                        )
                    )

                continue

            #
            # DQ
            #
            if text.lower().startswith("dq "):

                values = re.findall(
                    r"0x[0-9A-Fa-f]+|\d+",
                    text[3:]
                )

                for v in values:
                    output.extend(
                        struct.pack(
                            "<Q",
                            int(v, 0)
                        )
                    )

                continue

            #
            # Real instruction
            #
            code = self.assemble(
                text,
                address
            )

            output.extend(code)

            self.detect_relocations(
                code,
                address
            )

        return bytes(output), self.relocations
    
    # --------------------------------------------------------
    # First pass
    # --------------------------------------------------------

    def first_pass(
            self,
            section
    ):


        current = (
            section.virtual_address
        )


        self.labels.clear()



        for item in section.items:


            if item.label:


                self.labels[
                    item.label
                ] = current

                continue



            item.address = current


            if item.raw:

                size = len(
                    item.raw
                )

            else:

                size = len(
                    self.assemble(
                        item.text,
                        current
                    )
                )


            current += size



        return current



    # --------------------------------------------------------
    # Replace labels
    # --------------------------------------------------------

    def resolve_labels(
            self,
            text,
            address
    ):


        tokens = text.split()


        if len(tokens) < 2:

            return text



        opcode = tokens[0].lower()


        operand = tokens[1]



        if operand in self.labels:


            target = self.labels[
                operand
            ]


            #
            # Keystone understands
            # absolute addresses,
            # but not our labels.
            #

            return (
                opcode
                +
                " "
                +
                hex(target)
            )


        return text



    # --------------------------------------------------------
    # Second pass
    # --------------------------------------------------------

    def second_pass(
            self,
            section
    ):


        start = (
            section.virtual_address
        )


        end = self.first_pass(
            section
        )


        output = bytearray(
            end-start
        )


        self.relocations.clear()



        for item in section.items:


            if item.label:
                continue



            offset = (
                item.address -
                start
            )


            if item.raw:


                output[
                    offset:
                    offset+
                    len(item.raw)
                ] = item.raw


                continue



            asm = self.resolve_labels(
                item.text,
                item.address
            )



            code = self.assemble(
                asm,
                item.address
            )


            output[
                offset:
                offset+
                len(code)
            ] = code



            #
            # Detect absolute immediates
            #

            self.detect_relocations(
                code,
                item.address
            )



        return bytes(output)



    # --------------------------------------------------------
    # Relocation detection
    # --------------------------------------------------------

    def detect_relocations(
            self,
            code,
            address
    ):


        """
        Basic relocation detection.

        Finds embedded image addresses.

        A full linker would get these
        from assembler fixups.
        """


        size = (
            4
            if self.bits == 32
            else 8
        )


        step = size



        for off in range(
                0,
                len(code)-size+1,
                step
        ):


            value = int.from_bytes(
                code[
                    off:
                    off+size
                ],
                "little"
            )


            if self.bits == 64:


                if value >= 0x140000000:

                    self.relocations.append(
                        Relocation(
                            address+off,
                            size
                        )
                    )


            else:

                if value >= 0x400000:

                    self.relocations.append(
                        Relocation(
                            address+off,
                            size
                        )
                    )



    # --------------------------------------------------------
    # Public API
    # --------------------------------------------------------

    def assemble_section(
            self,
            section
    ):


        data = self.second_pass(
            section
        )


        return (
            data,
            self.relocations
        )