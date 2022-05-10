#!/usr/bin/env python

from argparse import ArgumentParser
from io import SEEK_SET
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
    pheader_class = elf.get_program_header_type(elf_header.elf_class)
    pheader_start = elf_header.program_header_offset
    pheader_count = elf_header.program_header_entries
    pheader_size = elf_header.program_header_size
    pheaders = []
    for cnt in range(pheader_count):
        start = pheader_start + pheader_size * cnt
        end = start + pheader_size
        elf_file.seek(start, SEEK_SET)
        pheader_data = elf_file.read(pheader_size)
        pheader_entry = header.parse_header(pheader_data, pheader_class, elf_header.elf_class)
        pheaders.append(pheader_entry)
    print("\n# Program headers")
    header.format_headers_as_table(pheaders, stdout)

    elf_file.close()
