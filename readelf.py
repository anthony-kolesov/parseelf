#!/usr/bin/env python

from argparse import ArgumentParser
import dataclasses
from pathlib import Path
from sys import stdout

import elf
import header


class Arguments:
    input: Path


def create_parser() -> ArgumentParser:
    parser = ArgumentParser()
    parser.add_argument(
        'input',
        type=Path,
        help='input file path',
    )
    return parser


if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args()
    elf_file = open(args.input, 'rb')
    elf_header = elf.ElfHeader.read_elf_header(elf_file)
    print("# ELF header")
    header.format_header_as_list(elf_header, stdout)

    # Now parse program headers.
    pheaders = elf.read_program_headers(elf_file, elf_header)
    print("\n# Program headers")
    header.format_headers_as_table(list(pheaders), stdout)

    # Section headers
    section_headers = list(elf.read_section_headers(elf_file, elf_header))
    section_names = dict(elf.map_section_names(elf_file, elf_header, section_headers))

    def sh_as_tuple(sheader: elf.SectionHeader) -> tuple:
        """Replace name offset with the name itself."""
        return (section_names[sheader.name_offset], *dataclasses.astuple(sheader)[1::])

    print("\n# Section headers")
    header.format_headers_as_table(section_headers, stdout, astuple=sh_as_tuple)

    elf_file.close()
