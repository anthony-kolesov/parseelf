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
    symbols: bool
    string_dump: list[str]


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
        '--symbols', '--syms', '-s',
        help='Display the symbol table',
        action='store_true',
    )
    parser.add_argument(
        '--string-dump', '-p',
        metavar='NUMBER|NAME',
        help='Dump the contents of section <number|name> as strings',
        action='append',
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
    section_headers = list(elf.read_section_headers(elf_file, elf_header))
    section_names = dict(elf.map_section_names(elf_file, elf_header, section_headers))
    # The line below relies on the fact that section names are in the same order as sections.
    sections = dict(zip(section_names.values(), section_headers))
    if args.section_headers:
        def sh_as_tuple(sheader: elf.SectionHeader) -> tuple:
            """Replace name offset with the name itself."""
            return (section_names[sheader.name_offset], *dataclasses.astuple(sheader)[1::])

        print("\n# Section headers")
        header.format_headers_as_table(section_headers, stdout, astuple=sh_as_tuple)

    def section_id_to_name(id: str) -> str:
        """Convert section name or number to a name.

        :param id: Can be either a section name or a number.
        :returns: Name of a specified section."""
        if id.isnumeric():
            return section_names[int(id)]
        else:
            return id

    # Symbols
    if args.symbols:
        # Select SYMTAB and DYNSYM sections
        symbol_names = elf.StringTable(elf_file, sections['.strtab'])
        for section in section_headers:
            if section.type not in (elf.SectionType.SYMTAB, elf.SectionType.DYNSYM):
                continue
            section_name = section_names[section.name_offset]
            symbols = list(elf.read_symbols(elf_file, section, elf_header.elf_class))
            value_width = elf_header.elf_class.string_width
            print(f"\nSymbol table '{section_name}' contains {len(symbols)} entries:")
            print(f'   Num: {"   Value":{value_width}}  Size Type    Bind   Vis      Ndx Name')
            for num, symbol in enumerate(symbols):
                print(
                    f'{num:6}:',
                    f'{symbol.value:0{value_width}x}',
                    f'{symbol.size:5}',
                    f'{symbol.type.name:7}',
                    f'{symbol.bind.name:6}',
                    f'{symbol.visibility.name:8}',
                    f'{symbol.section_index_name:>3}',
                    f'{symbol_names[symbol.name_offset]}',
                )

    # Strings.
    if args.string_dump:
        for section_id in args.string_dump:
            section_name = section_id_to_name(section_id)
            section = sections[section_name]
            print(f"\nString dump of section '{section_name}':")
            for offset, s in elf.StringTable(elf_file, section):
                print(f'  [{offset:6x}]  {s}')
            print()

    elf_file.close()
