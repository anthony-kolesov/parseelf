#!/usr/bin/env python

# Copyright (c) 2022 Anton Kolesov
# SPDX-License-Identifier: MIT

from argparse import ArgumentParser
from functools import partial
from io import BytesIO
from pathlib import Path
import sys
from typing import Any, Callable, cast, Iterable, Sequence

import dwarf
import elf


class Arguments:
    input: Path
    file_header: bool
    program_headers: bool
    section_headers: bool
    symbols: bool
    notes: bool
    relocations: bool
    dynamic: bool
    version_info: bool
    string_dump: list[str]
    hex_dump: list[str]
    dwarf: list[str]


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
        '--notes', '-n',
        help='Display the core notes (if present)',
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
        '--version-info', '-V',
        help='Display the version sections (if present)',
        action='store_true',
    )
    parser.add_argument(
        '--string-dump', '-p',
        metavar='NUMBER|NAME',
        help='Dump the contents of section <number|name> as strings',
        action='append',
    )
    parser.add_argument(
        '--hex-dump', '-x',
        metavar='NUMBER|NAME',
        help='Dump the contents of section <number|name> as bytes',
        action='append',
    )
    parser.add_argument(
        '--dwarf', '--debug-dump', '-w',
        help='Display debug information in object file',
        choices=(
            'rawline',
            'decodedline',
            'info',
            'abbrev',
            'aranges',
            'frames',
            'frames-interp',
            'str',
            'str-offsets',
        ),
        action='append',
    )
    parser.add_argument(
        'input',
        type=Path,
        help='input file path',
    )
    return parser


def entry_word(cnt: int) -> str:
    if cnt == 1:
        return '1 entry'
    return f'{cnt} entries'


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
    print("\nProgram Headers:")
    addrw = elf_header.elf_class.address_string_width + 2
    sizew = 8 if elf_header.elf_class == elf.ElfClass.ELF64 else 7
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
                # .tbss is special.  It doesn't contribute memory space to normal
                # segments and it doesn't take file space in normal segments.
                and not (
                    (elf.SectionFlags.TLS in s.flags)
                    and (s.type == elf.SectionType.NOBITS)
                    and (ph.type != elf.ProgramHeaderType.TLS)
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
    print('\nSection Headers:')
    address_title = format('Addr', '8') if elf_header.elf_class == elf.ElfClass.ELF32 else format('Address', '16')
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
  {'l (large), ' if elf_header.elf_class == elf.ElfClass.ELF64 else ''}p (processor specific)""")


def print_symbols(
    elf_obj: elf.Elf,
) -> None:
    for section_num, section_name, section in elf_obj.sections:
        if section.type not in (elf.SectionType.SYMTAB, elf.SectionType.DYNSYM):
            continue
        value_width = elf_obj.elf_class.address_string_width
        print(f"\nSymbol table '{section_name}' contains {entry_word(section.size // section.entry_size)}:")
        print(f'   Num: {"   Value":{value_width}}  Size Type    Bind   Vis      Ndx Name')
        for symbol_num, symbol_name, symbol, vna in elf_obj.symbols(section_num):
            complete_name = symbol_name
            if vna is not None:
                complete_name = f'{complete_name}@{vna.name} ({vna.version})'
            print(
                format(symbol_num, '6') + ':',
                format(symbol.value, f'0{value_width}x'),
                format(symbol.size, '5'),
                format(symbol.type.name, '7'),
                format(symbol.bind.name, '6'),
                format(symbol.visibility.name, '8'),
                format(symbol.section_index_name, '>3'),
                complete_name,
            )


def print_notes(
    elf_obj: elf.Elf,
) -> None:
    # """Each note section can have it's own format."""
    NT_GNU_ABI_TAG = 1
    # NT_GNU_HWCAP = 2
    NT_GNU_BUILD_ID = 3
    # NT_GNU_GOLD_VERSION = 4
    # NT_GNU_PROPERTY_TYPE_0 = 5

    df = elf_obj.data_format
    for section in elf_obj.sections_of_type(elf.SectionType.NOTE):
        stream = BytesIO(elf_obj.section_content(section.number))
        namesz = df.read_uint4(stream.read(4))
        descsz = df.read_uint4(stream.read(4))
        note_type = df.read_uint4(stream.read(4))
        name = df.parse_cstring(stream.read(elf.align_up(namesz, 4)))

        def print_section_info(type_name: str, details: str = '', suffix: str = '') -> None:
            print(f'\nDisplaying notes found in: {section.name}')
            print('  Owner                Data size \tDescription')
            d = type_name
            if details:
                d = f'{d} ({details})'
            print(f'  {name:<20} {descsz:#010x}\t{d}', end='')
            if suffix:
                print(f'\t{suffix}')
            else:
                print()

        if name == 'GNU':
            if note_type == NT_GNU_ABI_TAG:
                if descsz < 16:
                    suffix = '    <corrupt GNU_ABI_TAG>'
                else:
                    os = {
                        0: 'Linux',
                        1: 'Hurd',
                        2: 'Solaris',
                        3: 'FreeBSD',
                        4: 'NetBSD',
                        5: 'Syllable',
                        6: 'NaCl',
                    }.get(df.read_uint4(stream.read(4)), "Unknown")
                    major = df.read_uint4(stream.read(4))
                    minor = df.read_uint4(stream.read(4))
                    subminor = df.read_uint4(stream.read(4))
                    suffix = f'    OS: {os}, ABI: {major}.{minor}.{subminor}'
                print_section_info(
                    'NT_GNU_ABI_TAG',
                    'ABI version tag',
                    suffix,
                )
            elif note_type == NT_GNU_BUILD_ID:
                build_id = stream.read(descsz)
                print_section_info(
                    'NT_GNU_BUILD_ID',
                    'unique build ID bitstring',
                    f'    Build ID: {build_id.hex()}',
                )
            # Would like to support NT_GNU_PROPERTY_TYPE_0 used by GCC, but
            # for now it looks too complicated to be worth it.


def print_relocations(
    elf_obj: elf.Elf,
) -> None:
    found = False
    for section_num, section_name, section in elf_obj.sections:
        if section.type not in (elf.SectionType.REL, elf.SectionType.RELA):
            continue

        found = True
        relocs_count = section.size // section.entry_size
        print(f"\nRelocation section '{section_name}' at offset {section.offset:#x} "
              f"contains {entry_word(relocs_count)}:")
        # The relocations header tries to center the text, but it doesn't
        # really center it! Header are off-center for 64bit values. As a result
        # trying to represent it with a single string and multiple formats
        # would look ridiculous.
        if elf_obj.elf_class == elf.ElfClass.ELF32:
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
                symbol_w_addend = ' ' + symbol.full_name
                if elf_obj.elf_class == elf.ElfClass.ELF32:
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
    if not found:
        print('\nThere are no relocations in this file.')


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

    # Load section with library names. Value for `NEEDED` tags is the offset to a library name.
    library_names = elf_obj.strings(dynamic_section.header.link)

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
        if dyn_entry.tag == elf.DynamicEntryTag.NEEDED:
            formatted_value = f'Shared library: [{library_names[dyn_entry.value]}]'
        elif dyn_entry.tag == elf.DynamicEntryTag.FLAGS:
            formatted_value = str(elf.DynamicEntryFlags(dyn_entry.value))
        elif dyn_entry.tag == elf.DynamicEntryTag.FLAGS_1:
            formatted_value = 'Flags: ' + str(elf.DynamicEntryFlags1(dyn_entry.value))
        elif dyn_entry.tag == elf.DynamicEntryTag.PLTREL:
            formatted_value = elf.DynamicEntryTag(dyn_entry.value).name
        elif dyn_entry.tag in hex_format:
            formatted_value = format(dyn_entry.value, '#x')
        elif dyn_entry.tag in bytes_format:
            formatted_value = f'{dyn_entry.value} (bytes)'
        else:
            formatted_value = str(dyn_entry.value)
        print(
            '',
            format(dyn_entry.tag.value, elf_obj.elf_class.address_xformat),
            format(f'({dyn_entry.tag.name})', str(36 - elf_obj.elf_class.address_string_width)),
            formatted_value,
        )


def _print_verneed_info(
    elf_obj: elf.Elf,
    section: elf.Section,
    verneed_entries: Sequence[elf.VersionNeeded],
) -> None:
    # I have no idea who designed those inconsistent printing formats in readelf.
    def offset(value: int) -> str:
        if value == 0:
            return format(0, '06')
        return format(value, '#06x')

    print(f"\nVersion needs section '{section.name}' contains {entry_word(len(verneed_entries))}:")
    print(
        f' Addr: {section.header.address:#018x}',
        f'Offset: {section.header.offset:#08x}',
        f'Link: {section.header.link} ({elf_obj.section_names[section.header.link]})',
        sep='  ',
    )

    for vn in verneed_entries:
        print(f'  {offset(vn.offset)}: Version: {vn.version}  File: {vn.file}  Cnt: {vn.count}')
        for vna in vn.aux:
            print(
                f'  {offset(vna.offset)}: ',
                f'Name: {vna.name}',
                f'Flags: {vna.flags}',
                f'Version: {vna.version}',
                sep='  ',
            )


def _print_versym_info(
    elf_obj: elf.Elf,
    section: elf.Section,
) -> None:
    count = section.header.size // section.header.entry_size
    print(f"\nVersion symbols section '{section.name}' contains {count} entries:")
    print(
        f' Addr: {section.header.address:#018x}',
        f'Offset: {section.header.offset:#08x}',
        f'Link: {section.header.link} ({elf_obj.section_names[section.header.link]})',
        sep='  ',
    )
    for index, entry in enumerate(elf_obj.symbol_versions(section.number)):
        value = entry[0]
        vna = entry[1]
        if index % 4 == 0:
            print(f'  {index:03x}:', end='')
        if vna is None:
            if value == 0:
                print('   0 (*local*)    ', end='')
            elif value == 1:
                print('   1 (*global*)   ', end='')
            else:
                print(f'{value:4x}{"":14}', end='')
        else:
            library_name = vna.name.join(('(', ')'))
            hidden = 'h' if vna.hidden else ' '
            print(f'{value:4x}{hidden}{library_name:13}', end='')
        if index % 4 == 3:
            print()
    if count % 4 != 0:
        print()


def print_version_info(
    elf_obj: elf.Elf,
) -> None:
    verneed_entries = tuple(elf_obj.version_needed)
    if len(verneed_entries) == 0:
        print('\nNo version information found in this file.')
        return
    verneed_section = next(elf_obj.sections_of_type(elf.SectionType.VERNEED))
    versym_section = next(elf_obj.sections_of_type(elf.SectionType.VERSYM))
    _print_versym_info(elf_obj, versym_section)
    _print_verneed_info(elf_obj, verneed_section, verneed_entries)


def string_dump(
    sections_to_dump: Iterable[str],
    elf_obj: elf.Elf,
) -> None:
    """Dump the content of the specified sections as strings.

    This function doesn't try to test whether the section is actually a string
    table or not, except that it checks the first byte - it should be 0
    according to SystemV ABI (http://www.sco.com/developers/gabi/latest/ch4.strtab.html)."""
    # For compatibility with readelf first print warnings for non-existing sections.
    existing_section_numbers = []
    for section_num_or_name in sections_to_dump:
        if (not section_num_or_name.isnumeric()
           and section_num_or_name not in elf_obj.section_names):
            print(f"readelf: Warning: Section '{section_num_or_name}' was not dumped because it does not exist!")
        else:
            existing_section_numbers.append(elf_obj.section_number(section_num_or_name))

    for section_num in existing_section_numbers:
        section_name = elf_obj.section_names[section_num]
        section = elf_obj.section_headers[section_num]
        print(f"\nString dump of section '{section_name}':")
        for offset, s in elf.StringTable.read(elf_file, section):
            print(f'  [{offset:6x}]  {s}')
        print()


def _dump_hex(
    buffer: bytes,
    base_offset: int = 0,
) -> None:
    translation: list[int] = [
        (x if (x >= 0x20 and x <= 0x7e) else b'.'[0]) for x in range(256)
    ]
    for start in range(0, len(buffer), 16):
        h1 = buffer[start:start+4].hex()
        h2 = buffer[start+4:start+8].hex()
        h3 = buffer[start+8:start+12].hex()
        h4 = buffer[start+12:start+16].hex()
        # Hide non-printable characters.
        translated_buffer = buffer[start:start+16].translate(bytes(translation))
        s = translated_buffer.decode('ascii').replace('\0', '.')
        print(f'  {base_offset + start:#010x} {h1:<8} {h2:<8} {h3:<8} {h4:<8} {s}')


def hex_dump(
    sections_to_dump: Iterable[str],
    elf_obj: elf.Elf,
) -> None:
    """Dump the content of the specified sections as bytes."""
    # For compatibility with readelf first print warnings for non-existing sections.
    existing_section_numbers = []
    for section_num_or_name in sections_to_dump:
        if (not section_num_or_name.isnumeric()
           and section_num_or_name not in elf_obj.section_names):
            print(f"readelf: Warning: Section '{section_num_or_name}' was not dumped because it does not exist!")
        else:
            existing_section_numbers.append(elf_obj.section_number(section_num_or_name))

    for section_num in range(elf_obj.file_header.section_header_entries):
        if section_num not in existing_section_numbers:
            continue
        section_name = elf_obj.section_names[section_num]
        print(f"\nHex dump of section '{section_name}':")
        section_header = elf_obj.section_headers[section_num]
        _dump_hex(elf_obj.section_content(section_num), section_header.address)
        print()


def print_dwarf_rawline(
    elf_obj: elf.Elf,
) -> None:
    debug_line = elf_obj.find_section('.debug_line')
    if debug_line is None:
        return
    print('Raw dump of debug contents of section .debug_line:\n')

    stream = BytesIO(elf_obj.section_content(debug_line.number))
    sr = dwarf.StreamReader(elf_obj.data_format, stream)
    for line_prog in dwarf.LineNumberProgram.read(sr):
        w = 30
        print('  Offset:'.ljust(w), format(line_prog.offset, '#x'))
        print('  Length:'.ljust(w), line_prog.length)
        print('  DWARF Version:'.ljust(w), line_prog.version)
        print('  Prologue Length:'.ljust(w), line_prog.header_length)
        print('  Minimum Instruction Length:'.ljust(w), line_prog.minimum_instruction_length)
        print("  Initial value of 'is_stmt':".ljust(w), line_prog.default_is_stmt)
        print('  Line Base:'.ljust(w), line_prog.line_base)
        print('  Line Range:'.ljust(w), line_prog.line_range)
        print('  Opcode Base:'.ljust(w), line_prog.opcode_base)
        print()

        print(' Opcodes:')
        for i, args_num in enumerate(line_prog.standard_opcode_operands, start=1):
            print(f'  Opcode {i} has {args_num} {"args" if args_num != 1 else "arg"}')
        print()

        if len(line_prog.include_directories):
            print(f' The Directory Table (offset {line_prog.include_directories_offset:#x}):')
            for i, dir in enumerate(line_prog.include_directories, start=1):
                print(f'  {i}\t{dir}')
        else:
            print(' The Directory Table is empty.')
        print()

        if len(line_prog.files):
            print(f' The File Name Table (offset {line_prog.file_table_offset:#x}):')
            print('  Entry\tDir\tTime\tSize\tName')
            for i, file in enumerate(line_prog.files, start=1):
                print('\t'.join((
                    f'  {i}',
                    str(file.directory_index),
                    str(file.modification_time),
                    str(file.file_size),
                    file.name,
                )))
        else:
            print(' The File Name Table is empty.')
        print()

        if len(line_prog.statements):
            print(' Line Number Statements:')
            stateMachine = dwarf.LineNumberStateMachine(line_prog)
            for lns in line_prog.statements:
                description = stateMachine.do_statement(lns)
                print(f'  [{lns.offset:#010x}]  {description}')
            print()
            print()
        else:
            print(' No Line Number Statements.')


def print_dwarf_decodedline(
    elf_obj: elf.Elf,
) -> None:
    debug_line = elf_obj.find_section('.debug_line')
    if debug_line is None:
        return
    print('Contents of the .debug_line section:\n')

    stream = BytesIO(elf_obj.section_content(debug_line.number))
    sr = dwarf.StreamReader(elf_obj.data_format, stream)
    colw = (36, 11, 19, 7, 7)
    for line_prog in dwarf.LineNumberProgram.read(sr):
        # Quick exit if there is no file table, because further code requires
        # at least one file to be present.
        if len(line_prog.files) == 0:
            # The message says "directory table", but binutils prints it when
            # file table is not present.
            print('CU: No directory table')
            print('CU: Empty file name table')
            print()
            continue

        stateMachine = dwarf.LineNumberStateMachine(line_prog)
        for lns in line_prog.statements:
            stateMachine.do_statement(lns)

        file = stateMachine.file_names[stateMachine.rows[0].file-1]
        # If directory index is 0, then directory is printed as current
        # directory: `./`, but if there is no directory table at all, then `./`
        # is not printed.
        if len(line_prog.include_directories) == 0:
            print(f'CU: {file.name}:')
        else:
            if file.directory_index > 0:
                dirname = line_prog.include_directories[file.directory_index - 1]
            else:
                dirname = ''
            print(f'{dirname}{file.name}:')
        print(f'{"File name":{colw[0]}} {"Line number":>{colw[1]}} {"Starting address":>{colw[2]}} '
              f'{"View":>{colw[3]}} {"Stmt":>{colw[4]}}')

        for row in stateMachine.rows:
            file = stateMachine.file_names[row.file-1]
            filepath = file.name
            stmt = 'x' if row.is_stmt else ''
            line = row.line if not row.end_sequence else '-'
            print(
                f'{filepath:{colw[0]}} {line:>{colw[1]}} {row.address:>#{colw[2]}x} '
                f'{"":{colw[3]}} {stmt:>{colw[4]}}'
            )
        print()
        print()


def _format_die_attribute_value(
    attribute: dwarf.AttributeEncoding,
    form: dwarf.FormEncoding,
    value: int | bytes,
    cu: dwarf.CompilationUnit,
    debug_str_offsets: dwarf.StringOffsetsTable,
) -> str:
    # A formatter for attributes that use an Enum that has a 'human_name' attribute.
    def human_name(typ: type, value: int, /, attr_name: str = 'human_name') -> str:
        return f'{value}\t({getattr(typ(value), attr_name)})'

    attr_formatting: dict[dwarf.AttributeEncoding, Callable[[int], str]] = {
        dwarf.AttributeEncoding.DW_AT_high_pc: lambda a: format(a, '#x'),
        dwarf.AttributeEncoding.DW_AT_language: partial(human_name, dwarf.LanguageEncoding),
        dwarf.AttributeEncoding.DW_AT_encoding: partial(human_name, dwarf.AttributeTypeEncoding),
        dwarf.AttributeEncoding.DW_AT_identifier_case: partial(human_name, dwarf.IdCaseEncoding),
        dwarf.AttributeEncoding.DW_AT_loclists_base: lambda a: f'{a:#x} (location list)',
    }

    def strp_formatting(value: int) -> str:
        return f'(indirect string, offset: {value:#x}): {debug_str_offsets.strings[value]}'

    def strx_formatting(value: int) -> str:
        base = cu.str_offsets_base()
        return f'(indexed string: {value:#x}): {debug_str_offsets.get(base, value)}'

    def explr_formatting(b: bytes) -> str:
        init_instr_sr = dwarf.StreamReader(elf_obj.data_format, BytesIO(b))
        fmt = dwarf.TargetFormatter(elf_obj.file_header.machine, elf_obj.data_format.bits.address_size)
        s = dwarf.ExpressionOperation.objdump_format_seq(fmt, dwarf.ExpressionOperation.read(init_instr_sr))
        return f'{len(b)} byte block: {b.hex()} \t({s})'

    def indirect_formatting(form_id: int, value: int | bytes) -> str:
        return ' '.join((
            dwarf.FormEncoding(form_id).name,
            _format_die_attribute_value(
                attribute,
                dwarf.FormEncoding(form_id),
                value,
                cu,
                debug_str_offsets,
            )
        ))

    # Must explicitly identify type as Any, to avoid mypy errors when calling
    # a function returned from this dictionary.
    form_formatting: dict[dwarf.FormEncoding, Any] = {
        dwarf.FormEncoding.DW_FORM_addr: lambda a: format(a, '#x'),
        dwarf.FormEncoding.DW_FORM_block2: str,
        dwarf.FormEncoding.DW_FORM_block4: str,
        dwarf.FormEncoding.DW_FORM_data2: str,
        dwarf.FormEncoding.DW_FORM_data4: str,
        dwarf.FormEncoding.DW_FORM_data8: str,
        dwarf.FormEncoding.DW_FORM_string: str,
        dwarf.FormEncoding.DW_FORM_block: str,
        dwarf.FormEncoding.DW_FORM_block1: str,
        dwarf.FormEncoding.DW_FORM_data1: str,
        dwarf.FormEncoding.DW_FORM_flag: str,
        dwarf.FormEncoding.DW_FORM_sdata: lambda a: format(a, '#x'),
        dwarf.FormEncoding.DW_FORM_strp: strp_formatting,
        dwarf.FormEncoding.DW_FORM_udata: lambda a: format(a, '#x'),
        dwarf.FormEncoding.DW_FORM_ref_addr: lambda a: f'<{a:#x}>',
        dwarf.FormEncoding.DW_FORM_ref1: lambda a: f'<{a + cu.offset:#x}>',
        dwarf.FormEncoding.DW_FORM_ref2: lambda a: f'<{a + cu.offset:#x}>',
        dwarf.FormEncoding.DW_FORM_ref4: lambda a: f'<{a + cu.offset:#x}>',
        dwarf.FormEncoding.DW_FORM_ref8: lambda a: f'<{a + cu.offset:#x}>',
        dwarf.FormEncoding.DW_FORM_ref_udata: lambda a: f'<{a + cu.offset:#x}>',
        dwarf.FormEncoding.DW_FORM_sec_offset: lambda a: format(a, '#x'),
        dwarf.FormEncoding.DW_FORM_exprloc: explr_formatting,
        dwarf.FormEncoding.DW_FORM_flag_present: str,
        dwarf.FormEncoding.DW_FORM_ref_sig8: lambda a: f'<{a + cu.offset:#x}>',
        dwarf.FormEncoding.DW_FORM_indirect: lambda a: indirect_formatting(a[0], a[1]),
        dwarf.FormEncoding.DW_FORM_strx: strx_formatting,
    }

    # In most cases the printing format for a value is based on it's
    # form, but for some particular attributes the format is
    # different from what makes sense for this form, hence
    # attribute-specific formatters have higher priority over
    # form-specific.
    # attr_value_int = cast(int, attr.value)
    if attribute in attr_formatting:
        return attr_formatting[attribute](cast(int, value))
    else:
        return form_formatting.get(form, str)(value)


def _print_die_attribute(
    attr: dwarf.DieAttributeValue,
    cu: dwarf.CompilationUnit,
    debug_str_offsets: dwarf.StringOffsetsTable,
) -> None:
    print(
        f'    <{attr.offset:x}>  ',
        f'{attr.attribute.name:18}:',
        _format_die_attribute_value(attr.attribute, attr.form, attr.value, cu, debug_str_offsets),
    )


def print_dwarf_info(
    elf_obj: elf.Elf,
) -> None:
    debug_info = elf_obj.find_section('.debug_info')
    if debug_info is None:
        return

    # .debug_str might be absent, if .debug_info doesn't reference it.
    # Pass an empty table in this case.
    debug_str_section = elf_obj.find_section('.debug_str')
    if debug_str_section is not None:
        debug_strings = elf_obj.strings(debug_str_section.number)
    else:
        debug_strings = elf.StringTable(b'\0')

    debug_str_offsets_section = elf_obj.find_section('.debug_str_offsets')
    if debug_str_offsets_section is not None:
        debug_str_offsets_stream = BytesIO(elf_obj.section_content(debug_str_offsets_section.number))
        debug_str_offsets_sr = dwarf.StreamReader(elf_obj.data_format, debug_str_offsets_stream)
        debug_str_offsets = dwarf.StringOffsetsTable.read(debug_str_offsets_sr, debug_strings)
    else:
        # Empty offset table.
        debug_str_offsets = dwarf.StringOffsetsTable.empty(debug_strings)

    # Read abbreviation data.
    debug_abbrev = elf_obj.find_section('.debug_abbrev')
    assert debug_abbrev is not None
    debug_abbrev_stream = BytesIO(elf_obj.section_content(debug_abbrev.number))
    debug_abbrev_sr = dwarf.StreamReader(elf_obj.data_format, debug_abbrev_stream)

    print('Contents of the .debug_info section:\n')
    stream = BytesIO(elf_obj.section_content(debug_info.number))
    sr = dwarf.StreamReader(elf_obj.data_format, stream)
    for cu in dwarf.CompilationUnit.read(sr, debug_abbrev_sr):
        print(f'  Compilation Unit @ offset {cu.offset:#x}:')
        print(f'   Length:        {cu.length:#x} ({"32" if cu.is_dwarf32 else "64"}-bit)')
        print(f'   Version:       {cu.version}')
        if cu.version >= 5:
            print(f'   Unit Type:     {cu.unit_type.name} ({cu.unit_type.value})')
        print(f'   Abbrev Offset: {cu.debug_abbrev_offset:#x}')
        print(f'   Pointer Size:  {cu.address_size}')
        for die in cu.die_entries:
            abbrev_name = f' ({die.tag.name})' if not die.is_null_entry else ''
            print(f' <{die.level}><{die.offset:x}>: Abbrev Number: {die.abbreviation_number}{abbrev_name}')
            for attr in die.attributes:
                _print_die_attribute(attr, cu, debug_str_offsets)
    print()


def print_dwarf_abbrev(
    elf_obj: elf.Elf,
) -> None:
    def print_abbrev(abbrev: dwarf.AbbreviationDeclaration) -> None:
        if abbrev.code == 1:
            print(f'  Number TAG ({abbrev.offset:#x})')
        children = 'has' if abbrev.has_children else 'no'
        tag_name = dwarf.TagEncoding(abbrev.tag).name
        print(f'   {abbrev.code}      {tag_name}    [{children} children]')
        for attr in abbrev.attributes:
            attr_name = (dwarf.AttributeEncoding(attr.attribute_id).name if attr.attribute_id
                         else f'DW_AT value: {attr.attribute_id}')
            attr_form = dwarf.FormEncoding(attr.form_id).name if attr.form_id else f'DW_FORM value: {attr.form_id}'
            print(f'    {attr_name:18} {attr_form}')
        for child in abbrev.children:
            print_abbrev(child)

    debug_abbrev = elf_obj.find_section('.debug_abbrev')
    if debug_abbrev is None:
        return
    print('Contents of the .debug_abbrev section:\n')
    stream = BytesIO(elf_obj.section_content(debug_abbrev.number))
    sr = dwarf.StreamReader(elf_obj.data_format, stream)
    for abbrev in dwarf.AbbreviationDeclaration.read(sr):
        print_abbrev(abbrev)
    print()


def print_dwarf_aranges(
    elf_obj: elf.Elf,
) -> None:
    debug_aranges = elf_obj.find_section('.debug_aranges')
    if debug_aranges is None:
        return
    print(f'Contents of the {debug_aranges.name} section:\n')
    stream = BytesIO(elf_obj.section_content(debug_aranges.number))
    sr = dwarf.StreamReader(elf_obj.data_format, stream)
    left_column_format = '<25'
    for arange in dwarf.ArangeEntry.read(sr):
        print(' ', format('Length:', left_column_format), arange.length)
        print(' ', format('Version:', left_column_format), arange.version)
        print(
            ' ',
            format('Offset into .debug_info:', left_column_format),
            format(arange.debug_info_offset, '#x'),
        )
        print(' ', format('Pointer Size:', left_column_format), arange.address_size)
        print(' ', format('Segment Size:', left_column_format), arange.segment_selector_size)
        print(f'\n    {"Address":{elf_obj.elf_class.address_string_width}}   Length')
        for descriptor in arange.descriptors:
            print(
                '   ',
                format(descriptor[0], elf_obj.elf_class.address_format),
                format(descriptor[1], elf_obj.elf_class.address_format),
                '',
            )
    print()


def _offset_format(is_dwarf32: bool) -> str:
    """HEX format to print DWARF stream offset."""
    return '08x' if is_dwarf32 else '016x'


def _format_address_range(
    start: int,
    end: int,
    fmt: dwarf.TargetFormatter,
) -> str:
    """Format an address range as {start}..{end}"""
    return f'{start:{fmt.pointer_format}}..{end:{fmt.pointer_format}}'


def _dwarf_frame_cie_common(
    cie: dwarf.CieRecord,
    fmt: dwarf.TargetFormatter,
) -> str:
    """Format CIE line common to frames and frames-interp."""
    return ' '.join((
        format(cie.offset, '08x'),
        format(cie.size, fmt.pointer_format),
        format(cie.cie_id, _offset_format(cie.is_dwarf32)),
        'CIE',
    ))


def _dwarf_frame_fde(
    fde: dwarf.FdeRecord,
    fmt: dwarf.TargetFormatter,
) -> str:
    """Format an FDE entry to a single line for printing.

    This line format is shared by frames and frames-interp formats."""
    pc_begin = fde.pc_begin
    return ' '.join((
        format(fde.offset, '08x'),
        format(fde.size, fmt.pointer_format),
        format(fde.cie_ptr, _offset_format(fde.cie.is_dwarf32)),
        f'FDE cie={fde.cie.offset:08x}',
        f'pc={_format_address_range(pc_begin, pc_begin + fde.pc_range, fmt)}',
    ))


def print_dwarf_frames(
    elf_obj: elf.Elf,
) -> None:
    def print_cie(cie: dwarf.CieRecord) -> None:
        fmt = dwarf.TargetFormatter(elf_obj.file_header.machine, cie.address_size)
        print()
        print(_dwarf_frame_cie_common(cie, fmt))
        print('  Version:'.ljust(24), cie.version)
        print('  Augmentation:'.ljust(24), f'"{cie.augmentation}"')
        if cie.version >= 4:
            print('  Pointer Size:'.ljust(24), cie.address_size)
            print('  Segment Size:'.ljust(24), cie.segment_selector_size)
        print('  Code alignment factor:'.ljust(24), cie.code_alignment_factor)
        print('  Data alignment factor:'.ljust(24), cie.data_alignment_factor)
        print('  Return address column:'.ljust(24), cie.return_address_register)
        if len(cie.augmentation_data):
            print('  Augmentation data:'.ljust(24), cie.augmentation_data.hex(bytes_per_sep=1, sep=' '))
        else:
            print()
        for cfinstr in cie.initial_instructions:
            print('  ' + cfinstr.objdump_format(fmt, cie, 0))

    def print_fde(fde: dwarf.FdeRecord) -> None:
        fmt = dwarf.TargetFormatter(elf_obj.file_header.machine, fde.cie.address_size)
        print()
        print(_dwarf_frame_fde(fde, fmt))
        if fde.augmentation_data:
            print('  Augmentation data:'.ljust(24), fde.augmentation_data.hex(bytes_per_sep=1, sep=' '))

        fde_cftable = dwarf.CallFrameTable(fde.cie).copy(fde.pc_begin)
        for fde_instr in fde.instructions:
            fde_cftable.do_instruction(fde_instr)
            frame_pc = fde_cftable.current_loc()
            print('  ' + fde_instr.objdump_format(fmt, fde.cie, frame_pc))

    def print_records(
        records: Iterable[dwarf.CieRecord | dwarf.FdeRecord],
    ) -> None:
        for entry in records:
            if isinstance(entry, dwarf.CieRecord):
                if entry.is_zero_record:
                    print(f'\n{entry.offset:08x} ZERO terminator\n')
                else:
                    print_cie(entry)
            else:
                print_fde(entry)
        print()

    def print_frame_section(frame_section_name: str) -> None:
        frame_section = elf_obj.find_section(frame_section_name)
        if frame_section is None:
            return

        print(f'Contents of the {frame_section.name} section:\n')
        stream = BytesIO(elf_obj.section_content(frame_section.number))
        sr = dwarf.StreamReader(elf_obj.data_format, stream)
        # I can't say I'm a fan of this `if`, but section parse functions don't
        # have the same signature, which makes it difficult to extract common
        # code into functions and unroll the loop without too much duplication.
        # The quick return if the section is not found makes it even more
        # difficult to unroll without duplication.
        if frame_section_name == '.eh_frame':
            records = dwarf.read_eh_frame(sr, frame_section.header.address)
        else:
            records = dwarf.read_dwarf_frame(sr)
        print_records(records)

    for section_name in ('.eh_frame', '.debug_frame'):
        print_frame_section(section_name)


def print_dwarf_frames_interp(
    elf_obj: elf.Elf,
) -> None:
    def print_fde(
        fde: dwarf.FdeRecord,
        cftable: dwarf.CallFrameTable,
    ) -> None:
        fmt = dwarf.TargetFormatter(elf_obj.file_header.machine, fde.cie.address_size)
        print()
        print(_dwarf_frame_fde(fde, fmt))

        fde_cftable = cftable.copy(fde.pc_begin)
        fde_cftable.do_instruction(*fde.instructions)
        fde_cftable.objdump_print(fmt, sys.stdout)

    def print_records(
        records: Iterable[dwarf.CieRecord | dwarf.FdeRecord],
    ) -> None:
        cie_cftables: dict[int, dwarf.CallFrameTable] = {}
        for entry in records:
            if isinstance(entry, dwarf.CieRecord):
                if entry.is_zero_record:
                    print(f'\n{entry.offset:08x} ZERO terminator\n')
                else:
                    fmt = dwarf.TargetFormatter(elf_obj.file_header.machine, entry.address_size)
                    print()
                    print(' '.join((
                        _dwarf_frame_cie_common(entry, fmt),
                        f'"{entry.augmentation}"',
                        f'cf={entry.code_alignment_factor}',
                        f'df={entry.data_alignment_factor}',
                        f'ra={entry.return_address_register}',
                    )))
                    cie_cftable = dwarf.CallFrameTable(entry)
                    cie_cftable.do_instruction(*entry.initial_instructions)
                    cie_cftable.objdump_print(fmt, sys.stdout)
                    cie_cftables[entry.offset] = cie_cftable
            else:
                print_fde(entry, cie_cftables[entry.cie.offset])
        print()

    def print_frame_section(frame_section_name: str) -> None:
        frame_section = elf_obj.find_section(frame_section_name)
        if frame_section is None:
            return

        print(f'Contents of the {frame_section.name} section:\n')
        stream = BytesIO(elf_obj.section_content(frame_section.number))
        sr = dwarf.StreamReader(elf_obj.data_format, stream)
        if frame_section_name == '.eh_frame':
            entries = dwarf.read_eh_frame(sr, frame_section.header.address)
        else:
            entries = dwarf.read_dwarf_frame(sr)
        print_records(entries)

    for section_name in ('.eh_frame', '.debug_frame'):
        print_frame_section(section_name)


def print_dwarf_str(
    elf_obj: elf.Elf,
) -> None:
    debug_str = elf_obj.find_section('.debug_str')
    if debug_str is None:
        return
    print(f'Contents of the {debug_str.name} section:\n')
    debug_str_content = elf_obj.section_content(debug_str.number)
    _dump_hex(debug_str_content)
    print()


def print_dwarf_str_offsets(
    elf_obj: elf.Elf,
) -> None:
    debug_str = elf_obj.find_section('.debug_str')
    debug_str_offsets = elf_obj.find_section('.debug_str_offsets')
    if debug_str_offsets is None or debug_str is None:
        return
    print(f'Contents of the {debug_str_offsets.name} section:\n')
    stream = BytesIO(elf_obj.section_content(debug_str_offsets.number))
    sr = dwarf.StreamReader(elf_obj.data_format, stream)
    strings = elf_obj.strings(debug_str.number)
    str_offsets = dwarf.StringOffsetsTable.read(sr, strings)
    print(f'    Length: {str_offsets.table_length_in_bytes:#x}')
    print(f'    Version: {str_offsets.version:#x}')
    print('       Index   Offset [String]')
    for index, offset, string in str_offsets:
        print(f'{index:12} {offset:8x} {string}')


if __name__ == "__main__":
    parser = create_parser()
    args = cast(Arguments, parser.parse_args())
    elf_file = open(args.input, 'rb')
    elf_header = elf.ElfHeader.read_elf_header(elf_file)
    elf_obj = elf.Elf(elf_file)

    if args.file_header:
        elf_file.seek(0)
        print_file_header(elf_obj.file_header, elf_file.read(16))
    if args.section_headers:
        if not args.file_header:
            print(
                f'There are {elf_obj.file_header.section_header_entries} section headers, '
                f'starting at offset {elf_header.section_header_offset:#x}:'
            )
        print_section_headers(elf_obj)
    if args.program_headers:
        if not args.file_header:
            if elf_header.objectType.description:
                obj_type_description = f' ({elf_header.objectType.description})'
            else:
                obj_type_description = ''
            print(f'\nElf file type is {elf_header.objectType.name}{obj_type_description}')
            print(f'Entry point {elf_header.entry:#x}')
            print(
                f'There are {elf_header.program_header_entries} program headers, '
                f'starting at offset {elf_header.program_header_offset}'
            )
        print_program_headers(elf_obj)
    if args.dynamic:
        print_dynamic_info(elf_obj)
    if args.relocations:
        print_relocations(elf_obj)
    if args.symbols:
        print_symbols(elf_obj)
    if args.version_info:
        print_version_info(elf_obj)
    if args.notes:
        print_notes(elf_obj)
    if args.string_dump:
        string_dump(args.string_dump, elf_obj)
    if args.hex_dump:
        hex_dump(args.hex_dump, elf_obj)
    if args.dwarf:
        if 'frames' in args.dwarf:
            print_dwarf_frames(elf_obj)
        if 'frames-interp' in args.dwarf:
            print_dwarf_frames_interp(elf_obj)
        if 'aranges' in args.dwarf:
            print_dwarf_aranges(elf_obj)
        if 'info' in args.dwarf:
            print_dwarf_info(elf_obj)
        if 'abbrev' in args.dwarf:
            print_dwarf_abbrev(elf_obj)
        if 'rawline' in args.dwarf:
            print_dwarf_rawline(elf_obj)
        if 'decodedline' in args.dwarf:
            print_dwarf_decodedline(elf_obj)
        if 'str' in args.dwarf:
            print_dwarf_str(elf_obj)
        if 'str-offsets' in args.dwarf:
            print_dwarf_str_offsets(elf_obj)

    elf_file.close()
