#!/usr/bin/env python

# Copyright (c) 2022 Anton Kolesov
# SPDX-License-Identifier: MIT

from argparse import ArgumentParser
from pathlib import Path
from typing import BinaryIO, cast, Iterable, Mapping

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


def print_file_header(
    elf_header: elf.ElfHeader,
    magic_bytes: bytes,
) -> None:
    """Print ELF header in format identical to readelf --file-header."""
    print("ELF Header:")

    def pr(t: str, v: object) -> None:
        t += ':'
        print(f'  {t:34}', v)

    # Magic line is different from the rest.
    print('  Magic:  ', bytes.hex(magic_bytes[0:16], sep=' ', bytes_per_sep=1), '')
    pr('Class', elf_header.elf_class.name)
    pr('Data', elf_header.endiannes.description)
    pr('Version', str(elf_header.version) + (' (current)' if elf_header.version == 1 else ''))
    pr('OS/ABI', elf_header.osabi.description)
    pr('ABI Version', elf_header.abiversion)
    obj_type_description = (f' ({elf_header.objectType.description})' if elf_header.objectType.description else '')
    pr('Type', elf_header.objectType.name + obj_type_description)
    mdescr = elf_header.machine.description if elf_header.machine.description else elf_header.machine.name
    pr('Machine', mdescr)
    pr('Version', format(elf_header.version2, '#x'))
    pr('Entry point address', format(elf_header.entry, '#x'))
    pr('Start of program headers', f'{elf_header.program_header_offset} (bytes into file)')
    pr('Start of section headers', f'{elf_header.section_header_offset} (bytes into file)')
    pr('Flags', format(elf_header.flags, '#x'))
    pr('Size of this header', f'{elf_header.elf_header_size} (bytes)')
    pr('Size of program headers', f'{elf_header.program_header_size} (bytes)')
    pr('Number of program headers', elf_header.program_header_entries)
    pr('Size of section headers', f'{elf_header.section_header_size} (bytes)')
    pr('Number of section headers', elf_header.section_header_entries)
    pr('Section header string table index', elf_header.section_header_names_index)


def print_program_headers(
    headers: Iterable[elf.ProgramHeader],
    sections: Mapping[str, elf.SectionHeader],
    elf_header: elf.ElfHeader,
) -> None:
    obj_type_description = (f' ({elf_header.objectType.description})' if elf_header.objectType.description else '')
    print(f'\nElf file type is {elf_header.objectType.name}{obj_type_description}')
    print(f'Entry point {elf_header.entry:#x}')
    print(
        f'There are {elf_header.program_header_entries} program headers, '
        f'starting at offset {elf_header.program_header_offset}'
    )
    print("\nProgram Headers:")
    addrw = elf_header.elf_class.address_string_width + 2
    sizew = 8 if elf_header.elf_class == header.ElfClass.ELF64 else 7
    print(
        '  Type           Offset   '
        f'{"VirtAddr":{addrw}} {"PhysAddr":{addrw}} {"FileSiz":{sizew}} {"MemSiz":{sizew}}'
        ' Flg Align'
    )
    for ph in headers:
        print(
            ' ',
            format(ph.type.name, '14'),
            format(ph.offset, '#08x'),
            format(ph.vaddr, f'#0{addrw}x'),
            format(ph.paddr, f'#0{addrw}x'),
            format(ph.filesz, f'#0{sizew}x'),
            format(ph.memsz, f'#0{sizew}x'),
            format(ph.flags.summary, '3'),
            format(ph.align, '#x'),
        )

    print('\n Section to Segment mapping:')
    print('  Segment Sections...')
    for nr, ph in enumerate(headers):
        shnames = (
            name
            for name, s in sections.items()
            # Conditions are based on ELF_SECTION_IN_SEGMENT_1 from
            # include/elf/internal.h, but the conditions are copied not verbatim
            # to make implementation as simple as possible (at least for now).
            if (
                # PT_LOAD and similar segments only have SHF_ALLOC sections.
                (
                    (ph.type not in (elf.ProgramHeaderType.LOAD, elf.ProgramHeaderType.DYNAMIC))
                    or (elf.SectionFlags.ALLOC in s.flags)
                )
                # Any section besides one of type SHT_NOBITS must have file offsets within the segment.
                and (
                    (s.type == elf.SectionType.NOBITS)
                    or (ph.offset <= s.offset and (s.offset + s.size <= ph.offset + ph.filesz))
                )
                # SHF_ALLOC sections must have VMAs within the segment.
                and (
                     (elf.SectionFlags.ALLOC not in s.flags)
                     or (ph.vaddr <= s.address and (s.address + s.size) <= (ph.vaddr + ph.memsz))
                     )
                and name
                )
        )
        print(
            f'   {nr:02}    ',
            *shnames,
            '',
        )


def print_section_headers(
    sections: Mapping[str, elf.SectionHeader],
    elf_header: elf.ElfHeader,
) -> None:
    print(f'There are {len(sections)} section headers, '
          f'starting at offset {elf_header.section_header_offset:#x}:')
    print('\nSection Headers:')
    address_title = format('Addr', '8') if elf_header.elf_class == header.ElfClass.ELF32 else format('Address', '16')
    print(f'  [Nr] Name              Type            {address_title} Off    Size   ES Flg Lk Inf Al')
    for nr, item in enumerate(sections.items()):
        name = item[0]
        section = item[1]
        print(
            f'  [{nr:2}]',
            format(name, '17'),
            format(section.type.name, '15'),
            format(section.address, elf_header.elf_class.address_format),
            format(section.offset, '06x'),
            format(section.size, '06x'),
            format(section.entry_size, '02x'),
            format(section.flags.summary, '>3'),
            format(section.link, '2'),
            format(section.info, '3'),
            format(section.address_alignment, '2'),
        )
    print(f"""Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  {'l (large), ' if elf_header.elf_class == header.ElfClass.ELF64 else ''}p (processor specific)""")


def print_symbols(
    sections: Mapping[str, elf.SectionHeader],
    elf_class: header.ElfClass,
    elf_file: BinaryIO,
) -> None:
    # Select SYMTAB and DYNSYM sections. Names are in .strtab and .dynstr
    # sections respectively.
    strtab = elf.StringTable(elf_file, sections['.strtab'])
    if '.dynstr' in sections:
        dynstr = elf.StringTable(elf_file, sections['.dynstr'])
    for section_name, section in sections.items():
        if section.type not in (elf.SectionType.SYMTAB, elf.SectionType.DYNSYM):
            continue
        symbols = list(elf.read_symbols(elf_file, section, elf_class))
        value_width = elf_class.address_string_width
        print(f"\nSymbol table '{section_name}' contains {len(symbols)} entries:")
        print(f'   Num: {"   Value":{value_width}}  Size Type    Bind   Vis      Ndx Name')
        name_section = strtab if section.type == elf.SectionType.SYMTAB else dynstr
        for num, symbol in enumerate(symbols):
            print(
                f'{num:6}:',
                f'{symbol.value:0{value_width}x}',
                f'{symbol.size:5}',
                f'{symbol.type.name:7}',
                f'{symbol.bind.name:6}',
                f'{symbol.visibility.name:8}',
                f'{symbol.section_index_name:>3}',
                f'{name_section[symbol.name_offset]}',
            )


def string_dump(
    sections_to_dump: Iterable[str],
    sections: Mapping[str, elf.SectionHeader],
    elf_file: BinaryIO,
) -> None:
    """Dump the content of the specified sections as strings.

    This function doesn't try to test wether the section is actually a string
    table or not, except that it checks the first byte - it should be 0
    according to SystemV ABI (http://www.sco.com/developers/gabi/latest/ch4.strtab.html).

    :param sections_to_dump: Names of sections to dump.
    :param sections: Mapping from section names to headers."""
    for section_name in sections_to_dump:
        if section_name not in sections:
            print(f"readelf: Warning: Section '{section_name}' was not dumped because it does not exist!")
            continue
        section = sections[section_name]
        print(f"\nString dump of section '{section_name}':")
        for offset, s in elf.StringTable(elf_file, section):
            print(f'  [{offset:6x}]  {s}')
        print()


if __name__ == "__main__":
    parser = create_parser()
    args = cast(Arguments, parser.parse_args())
    elf_file = open(args.input, 'rb')
    elf_header = elf.ElfHeader.read_elf_header(elf_file)
    if args.file_header:
        elf_file.seek(0)
        print_file_header(elf_header, elf_file.read(16))

    section_headers = list(elf.read_section_headers(elf_file, elf_header))
    section_names = dict(elf.map_section_names(elf_file, elf_header, section_headers))
    # The line below relies on the fact that section names are in the same order as sections.
    sections = dict(zip(section_names.values(), section_headers))
    pheaders = list(elf.read_program_headers(elf_file, elf_header))

    def section_id_to_name(id: str) -> str:
        """Convert section name or number to a name.

        :param id: Can be either a section name or a number.
        :returns: Name of a specified section."""
        if id.isnumeric():
            return list(sections.keys())[int(id)]
        else:
            return id

    if args.program_headers:
        print_program_headers(pheaders, sections, elf_header)
    if args.section_headers:
        print_section_headers(sections, elf_header)
    if args.symbols:
        print_symbols(sections, elf_header.elf_class, elf_file)
    if args.string_dump:
        string_dump(
            (section_id_to_name(shid) for shid in args.string_dump),
            sections,
            elf_file,
        )

    elf_file.close()
