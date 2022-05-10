#!/usr/bin/env python

from argparse import ArgumentParser
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
    header.format_headers_as_table(pheaders, stdout)

    # Section headers
    section_headers = elf.read_section_headers(elf_file, elf_header)
    print("\n# Section headers")
    header.format_headers_as_table(list(section_headers), stdout)

    elf_file.close()
