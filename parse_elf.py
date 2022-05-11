#!/usr/bin/env python

# Copyright (c) 2022 Anton Kolesov
# SPDX-License-Identifier: MIT

from argparse import ArgumentParser
import dataclasses
from pathlib import Path
from typing import cast
from sys import stdout

import elf
import header


class Arguments:
    input: Path
    file_header: bool
    program_headers: bool
    section_headers: bool


def create_parser() -> ArgumentParser:
    parser = ArgumentParser(
        description="""A simple program to parse ELF files.
            Similar to readelf/objdump, but not a replacement."""
    )
    parser.add_argument(
        '--file-header', '-f',
        help='Display the ELF file header',
        action='store_true',
    )
    parser.add_argument(
        '--program-headers', '-l',
        help='Display the program headers',
        action='store_true',
    )
    parser.add_argument(
        '--section-headers', '-S',
        help='Display the sections\' header',
        action='store_true',
    )
    parser.add_argument(
        'input',
        type=Path,
        help='input file path',
    )
    return parser


if __name__ == "__main__":
    parser = create_parser()
    args = cast(Arguments, parser.parse_args())
    elf_file = open(args.input, 'rb')
    elf_header = elf.ElfHeader.read_elf_header(elf_file)
    if args.file_header:
        print("# ELF header")
        header.format_header_as_list(elf_header, stdout)

    # Now parse program headers.
    pheaders = elf.read_program_headers(elf_file, elf_header)
    if args.program_headers:
        print("\n# Program headers")
        header.format_headers_as_table(list(pheaders), stdout)

    # Section headers
    if args.section_headers:
        section_headers = list(elf.read_section_headers(elf_file, elf_header))
        section_names = dict(elf.map_section_names(elf_file, elf_header, section_headers))

        def sh_as_tuple(sheader: elf.SectionHeader) -> tuple:
            """Replace name offset with the name itself."""
            return (section_names[sheader.name_offset], *dataclasses.astuple(sheader)[1::])

        print("\n# Section headers")
        header.format_headers_as_table(section_headers, stdout, astuple=sh_as_tuple)

    elf_file.close()
