#!/usr/bin/env python

# Copyright (c) 2022 Anton Kolesov
# SPDX-License-Identifier: MIT

from argparse import ArgumentParser
from pathlib import Path
from typing import cast, Iterable

import elf
import header


class Arguments:
    input: Path
    file_header: bool
    program_headers: bool
    section_headers: bool
    symbols: bool
    relocations: bool
    dynamic: bool
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
        '--relocations', '--relocs', '-r',
        help='Display the relocations (if present)',
        action='store_true',
    )
    parser.add_argument(
        '--dynamic', '-d',
        help='Display the dynamic section (if present)',
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
    elf_obj: elf.Elf,
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
    for ph in elf_obj.program_headers:
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
        if ph.type == elf.ProgramHeaderType.INTERP:
            interp_bytes = elf_obj.read(ph.offset, ph.filesz)
            # This is null-terminated string.
            assert interp_bytes[-1] == 0
            interp = interp_bytes[:-1].decode('ascii')
            print(f'      [Requesting program interpreter: {interp}]')

    print('\n Section to Segment mapping:')
    print('  Segment Sections...')
    for nr, ph in enumerate(elf_obj.program_headers):
        shnames = (
            name
            for _, name, s in elf_obj.sections
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
    elf_obj: elf.Elf,
) -> None:
    print(f'There are {elf_obj.file_header.section_header_entries} section headers, '
          f'starting at offset {elf_header.section_header_offset:#x}:')
    print('\nSection Headers:')
    address_title = format('Addr', '8') if elf_header.elf_class == header.ElfClass.ELF32 else format('Address', '16')
    print(f'  [Nr] Name              Type            {address_title} Off    Size   ES Flg Lk Inf Al')
    for nr, name, section in elf_obj.sections:
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
    elf_obj: elf.Elf,
) -> None:
    for section_num, section_name, section in elf_obj.sections:
        if section.type not in (elf.SectionType.SYMTAB, elf.SectionType.DYNSYM):
            continue
        value_width = elf_obj.elf_class.address_string_width
        print(f"\nSymbol table '{section_name}' contains {section.size // section.entry_size} entries:")
        print(f'   Num: {"   Value":{value_width}}  Size Type    Bind   Vis      Ndx Name')
        for symbol_num, symbol_name, symbol in elf_obj.symbols(section_num):
            print(
                format(symbol_num, '6') + ':',
                format(symbol.value, f'0{value_width}x'),
                format(symbol.size, '5'),
                format(symbol.type.name, '7'),
                format(symbol.bind.name, '6'),
                format(symbol.visibility.name, '8'),
                format(symbol.section_index_name, '>3'),
                symbol_name,
            )


def print_relocations(
    elf_obj: elf.Elf,
) -> None:
    for section_num, section_name, section in elf_obj.sections:
        if section.type not in (elf.SectionType.REL, elf.SectionType.RELA):
            continue

        relocs_count = section.size // section.entry_size
        print(f"\nRelocation section '{section_name}' at offset {section.offset:#x} "
              f"contains {relocs_count} entr{'ies' if relocs_count != 1 else 'y'}:")
        # The relocations header tries to center the text, but it doesn't
        # really center it! Header are off-center for 64bit values. As a result
        # trying to represent it with a single string and multiple formats
        # would look ridiculous.
        if elf_obj.elf_class == header.ElfClass.ELF32:
            print(" Offset     Info    Type                Sym. Value  Symbol's Name", end='')
        else:
            print("    Offset             Info             Type               Symbol's Value  Symbol's Name", end='')
        print(' + Addend' if section.type == elf.SectionType.RELA else '')

        for r, symbol in elf_obj.relocations(section_num):
            type_name = elf_obj.relocation_type(r).name

            print(
                format(r.offset, elf_obj.elf_class.address_format),
                '',
                format(r.get_info(elf_obj.elf_class), elf_obj.elf_class.address_format),
                format(type_name, '22'),
                end='',
            )

            if symbol:
                symbol_value = ' ' + format(symbol.entry.value, elf_obj.elf_class.address_format)
                symbol_w_addend = ' ' + symbol.name
                if elf_obj.elf_class == header.ElfClass.ELF32:
                    symbol_w_addend = '  ' + symbol_w_addend
                if section.type == elf.SectionType.RELA:
                    symbol_w_addend += f' + {getattr(r, "addend", 0):x}'
            else:
                if section.type == elf.SectionType.RELA:
                    symbol_value = format('', str(elf_obj.elf_class.address_string_width + 1))
                else:
                    symbol_value = ''
                symbol_w_addend = f'   {getattr(r, "addend", 0):x}' if section.type == elf.SectionType.RELA else ''
            print(symbol_value + symbol_w_addend)


def print_dynamic_info(elf_obj: elf.Elf) -> None:
    # Dynamic section can contain several NULLs at the end, so we can't rely on
    # section size and section entity size to figure out amount of entries.
    # In theory it would be even better to use program header entries instead of
    # section entries.

    dynamic_section = next(elf_obj.sections_of_type(elf.SectionType.DYNAMIC), None)
    if dynamic_section is None:
        return

    entries = list(elf_obj.dynamic_info)
    print(f'\nDynamic section at offset {dynamic_section.header.offset:#x} contains {len(entries)} entries:')
    print('  Tag        Type                         Name/Value')

    # Print formats are defined here instead of being defined on the
    # DynamicTagType, mostly because it is because it is a presentation-specific
    # information, and also adding it to enum - custom print function value for
    # each value could be quite complicated.
    hex_format = {
        elf.DynamicEntryTag.NULL,
        elf.DynamicEntryTag.PLTGOT,
        elf.DynamicEntryTag.STRTAB,
        elf.DynamicEntryTag.SYMTAB,
        elf.DynamicEntryTag.RELA,
        elf.DynamicEntryTag.INIT,
        elf.DynamicEntryTag.FINI,
        elf.DynamicEntryTag.DEBUG,
        elf.DynamicEntryTag.JMPREL,
        elf.DynamicEntryTag.REL,
        elf.DynamicEntryTag.INIT_ARRAY,
        elf.DynamicEntryTag.FINI_ARRAY,
        elf.DynamicEntryTag.GNU_HASH,
        elf.DynamicEntryTag.VERSYM,
        elf.DynamicEntryTag.VERNEED,
    }
    bytes_format = {
        elf.DynamicEntryTag.PLTRELSZ,
        elf.DynamicEntryTag.RELASZ,
        elf.DynamicEntryTag.RELAENT,
        elf.DynamicEntryTag.STRSZ,
        elf.DynamicEntryTag.SYMENT,
        elf.DynamicEntryTag.RELSZ,
        elf.DynamicEntryTag.RELENT,
        elf.DynamicEntryTag.INIT_ARRAYSZ,
        elf.DynamicEntryTag.FINI_ARRAYSZ,
    }

    for dyn_entry in entries:
        if dyn_entry.tag in hex_format:
            formatted_value = format(dyn_entry.value, '#x')
        elif dyn_entry.tag in bytes_format:
            formatted_value = f'{dyn_entry.value} (bytes)'
        elif dyn_entry.tag == elf.DynamicEntryTag.FLAGS:
            formatted_value = str(elf.DynamicEntryFlags(dyn_entry.value))
        elif dyn_entry.tag == elf.DynamicEntryTag.FLAGS_1:
            formatted_value = 'Flags: ' + str(elf.DynamicEntryFlags1(dyn_entry.value))
        elif dyn_entry.tag == elf.DynamicEntryTag.PLTREL:
            formatted_value = elf.DynamicEntryTag(dyn_entry.value).name
        else:
            formatted_value = str(dyn_entry.value)
        print(
            '',
            format(dyn_entry.tag.value, elf_obj.elf_class.address_xformat),
            format(f'({dyn_entry.tag.name})', str(36 - elf_obj.elf_class.address_string_width)),
            formatted_value,
        )


def string_dump(
    sections_to_dump: Iterable[str],
    elf_obj: elf.Elf,
) -> None:
    """Dump the content of the specified sections as strings.

    This function doesn't try to test wether the section is actually a string
    table or not, except that it checks the first byte - it should be 0
    according to SystemV ABI (http://www.sco.com/developers/gabi/latest/ch4.strtab.html).

    :param sections_to_dump: Names of sections to dump.
    :param sections: Mapping from section names to headers."""
    for section_num_or_name in sections_to_dump:
        if (not section_num_or_name.isnumeric()
           and section_num_or_name not in elf_obj.section_names):
            print(f"readelf: Warning: Section '{section_num_or_name}' was not dumped because it does not exist!")
            continue
        section_num = elf_obj.section_number(section_num_or_name)
        section_name = elf_obj.section_names[section_num]
        section = elf_obj.section_headers[section_num]
        print(f"\nString dump of section '{section_name}':")
        for offset, s in elf.StringTable(elf_file, section):
            print(f'  [{offset:6x}]  {s}')
        print()


if __name__ == "__main__":
    parser = create_parser()
    args = cast(Arguments, parser.parse_args())
    elf_file = open(args.input, 'rb')
    elf_header = elf.ElfHeader.read_elf_header(elf_file)
    elf_obj = elf.Elf(elf_file)
    if args.file_header:
        elf_file.seek(0)
        print_file_header(elf_obj.file_header, elf_file.read(16))

    if args.program_headers:
        print_program_headers(elf_obj)
    if args.section_headers:
        print_section_headers(elf_obj)
    if args.symbols:
        print_symbols(elf_obj)
    if args.relocations:
        print_relocations(elf_obj)
    if args.dynamic:
        print_dynamic_info(elf_obj)
    if args.string_dump:
        string_dump(
            args.string_dump,
            elf_obj,
        )

    elf_file.close()
