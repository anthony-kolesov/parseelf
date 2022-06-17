#!/usr/bin/env python

# Copyright (c) 2022 Anton Kolesov
# SPDX-License-Identifier: MIT

from argparse import ArgumentParser
from io import BytesIO
from pathlib import Path
import sys
from typing import cast, Iterable, Sequence

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
        '--dwarf', '--debug-dump', '-w',
        help='Display debug information in object file',
        choices=(
            'rawline',
            'decodedline',
            'info',
            'frames-interp',
            'frames',
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
    obj_type_description = (f' ({elf_header.objectType.description})' if elf_header.objectType.description else '')
    print(f'\nElf file type is {elf_header.objectType.name}{obj_type_description}')
    print(f'Entry point {elf_header.entry:#x}')
    print(
        f'There are {elf_header.program_header_entries} program headers, '
        f'starting at offset {elf_header.program_header_offset}'
    )
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
    print(f'There are {elf_obj.file_header.section_header_entries} section headers, '
          f'starting at offset {elf_header.section_header_offset:#x}:')
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
        print(f"\nSymbol table '{section_name}' contains {section.size // section.entry_size} entries:")
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

        def print_section_info(type_name: str, details: str = '') -> None:
            print(f'\nDisplaying notes found in: {section.name}')
            print('  Owner                Data size \tDescription')
            d = type_name
            if details:
                d = f'{d} ({details})'
            print(f'  {name:<20} {descsz:#010x}\t{d}')

        if name == 'GNU':
            if note_type == NT_GNU_ABI_TAG:
                print_section_info('NT_GNU_ABI_TAG', 'ABI version tag')
                if descsz < 16:
                    print('    <corrupt GNU_ABI_TAG>')
                    continue
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
                print(f'    OS: {os}, ABI: {major}.{minor}.{subminor}')
            elif note_type == NT_GNU_BUILD_ID:
                print_section_info('NT_GNU_BUILD_ID', 'unique build ID bitstring')
                build_id = stream.read(descsz)
                print(f'    Build ID: {build_id.hex()}')
            # Would like to support NT_GNU_PROPERTY_TYPE_0 used by GCC, but
            # for now it looks too complicated to be worth it.


def print_relocations(
    elf_obj: elf.Elf,
) -> None:
    for section_num, section_name, section in elf_obj.sections:
        if section.type not in (elf.SectionType.REL, elf.SectionType.RELA):
            continue

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
    according to SystemV ABI (http://www.sco.com/developers/gabi/latest/ch4.strtab.html).

    :param sections_to_dump: Names of sections to dump.
    :param sections: Mapping from section names to headers."""
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
        for offset, s in elf.StringTable(elf_file, section):
            print(f'  [{offset:6x}]  {s}')
        print()


def print_dwarf_rawline(
    elf_obj: elf.Elf,
) -> None:
    debug_line = next((s for s in elf_obj.sections if s.name == '.debug_line'), None)
    if debug_line is None:
        print()
        return
    print('\nRaw dump of debug contents of section .debug_line:\n')

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

        print(f' The Directory Table (offset {line_prog.include_directories_offset:#x}):')
        for i, dir in enumerate(line_prog.include_directories, start=1):
            print(f'  {i}\t{dir}')
        print()

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
        print()

        print(' Line Number Statements:')
        stateMachine = dwarf.LineNumberStateMachine(line_prog)
        for lns in line_prog.statements:
            description = stateMachine.do_statement(lns)
            print(f'  [{lns.offset:#010x}]  {description}')
        print()

        print()


def print_dwarf_decodedline(
    elf_obj: elf.Elf,
) -> None:
    debug_line = next((s for s in elf_obj.sections if s.name == '.debug_line'), None)
    if debug_line is None:
        print()
        return
    print('\nContents of the .debug_line section:\n')

    stream = BytesIO(elf_obj.section_content(debug_line.number))
    sr = dwarf.StreamReader(elf_obj.data_format, stream)
    colw = (36, 11, 19, 7, 7)
    for line_prog in dwarf.LineNumberProgram.read(sr):
        stateMachine = dwarf.LineNumberStateMachine(line_prog)
        for lns in line_prog.statements:
            stateMachine.do_statement(lns)

        file = stateMachine.file_names[stateMachine.rows[0].file-1]
        dirname = line_prog.include_directories[file.directory_index - 1] if file.directory_index > 0 else './'
        filepath = file.name
        print(f'CU: {dirname}{filepath}:')
        print(f'{"File name":{colw[0]}} {"Line number":>{colw[1]}} {"Starting address":>{colw[2]}} '
              f'{"View":>{colw[3]}} {"Stmt":>{colw[4]}}')

        for row in stateMachine.rows:
            file = stateMachine.file_names[row.file-1]
            dirname = line_prog.include_directories[file.directory_index - 1] if file.directory_index > 0 else './'
            filepath = file.name
            stmt = 'x' if row.is_stmt else ''
            print(
                f'{filepath:{colw[0]}} {row.line:>{colw[1]}} {row.address:>#{colw[2]}x} '
                f'{"":{colw[3]}} {stmt:>{colw[4]}}'
            )
        print()
        print()


def print_dwarf_info(
    elf_obj: elf.Elf,
) -> None:
    debug_info = next((s for s in elf_obj.sections if s.name == '.debug_info'), None)
    if debug_info is None:
        print()
        return
    print('\nContents of the .debug_info section:\n')
    stream = BytesIO(elf_obj.section_content(debug_info.number))
    sr = dwarf.StreamReader(elf_obj.data_format, stream)
    for cu in dwarf.CompilationUnit.read(sr):
        print(f'  Compilation Unit @ offset {cu.offset:#x}:')
        print(f'   Length:        {cu.length:#x} ({"32" if cu.is_dwarf32 else "64"}-bit)')
        print(f'   Version:       {cu.version}')
        print(f'   Abbrev Offset: {cu.debug_abbrev_offset:#x}')
        print(f'   Pointer Size:  {cu.address_size}')
        print()


def _format_address_range(start: int, end: int, bits: elf.ElfClass) -> str:
    """Format an address range as {start}..{end}"""
    return f'{start:{bits.address_format}}..{end:{bits.address_format}}'


def _dwarf_frame_cie_common(
    cie: dwarf.CieRecord,
    bits: elf.ElfClass,
) -> str:
    """Format CIE line common to frames and frames-interp."""
    return ' '.join((
        format(cie.offset, '08x'),
        format(cie.size, bits.address_format),
        format(0, '08x'),
        'CIE',
    ))


def _dwarf_frame_fde(
    fde: dwarf.FdeRecord,
    bits: elf.ElfClass,
    section_address: int,
) -> str:
    """Format an FDE entry to a single line for printing.

    This line format is shared by frames and frames-interp formats."""
    pc_begin = fde.abs_pc_begin(section_address)
    return ' '.join((
        format(fde.offset, '08x'),
        format(fde.size, bits.address_format),
        format(fde.cie_ptr, '08x'),
        f'FDE cie={fde.cie.offset:08x}',
        f'pc={_format_address_range(pc_begin, pc_begin + fde.pc_range, bits)}',
    ))


def print_dwarf_frames(
    elf_obj: elf.Elf,
) -> None:
    eh_frame = next((s for s in elf_obj.sections if s.name == '.eh_frame'), None)
    if eh_frame is None:
        return
    print('\nContents of the .eh_frame section:\n')

    def print_cie(cie: dwarf.CieRecord, fmt: dwarf.TargetFormatter) -> None:
        print()
        print(_dwarf_frame_cie_common(cie, fmt.data_format.bits))
        print('  Version:'.ljust(24), cie.version)
        print('  Augmentation:'.ljust(24), f'"{cie.augmentation}"')
        print('  Code alignment factor:'.ljust(24), cie.code_alignment_factor)
        print('  Data alignment factor:'.ljust(24), cie.data_alignment_factor)
        print('  Return address column:'.ljust(24), cie.return_address_register)
        print('  Augmentation data:'.ljust(24), cie.augmentation_data.hex(bytes_per_sep=1, sep=' '))
        init_instr_sr = dwarf.StreamReader(elf_obj.data_format, BytesIO(cie.initial_instructions))
        for cfinstr in dwarf.CfaInstruction.read(init_instr_sr):
            print('  ' + cfinstr.objdump_format(fmt, cie, 0))

    def print_fde(fde: dwarf.FdeRecord, fmt: dwarf.TargetFormatter, section_address: int) -> None:
        print()
        print(_dwarf_frame_fde(fde, fmt.data_format.bits, section_address))
        if fde.augmentation_data:
            print('  Augmentation data:'.ljust(24), fde.augmentation_data.hex(bytes_per_sep=1, sep=' '))

        fde_instr_sr = dwarf.StreamReader(elf_obj.data_format, BytesIO(fde.instructions))
        fde_cftable = dwarf.CallFrameTable(fde.cie).copy(fde.abs_pc_begin(section_address))
        for fde_instr in dwarf.CfaInstruction.read(fde_instr_sr):
            fde_cftable.do_instruction(fde_instr)
            frame_pc = fde_cftable.current_loc()
            print('  ' + fde_instr.objdump_format(fmt, fde.cie, frame_pc))

    stream = BytesIO(elf_obj.section_content(eh_frame.number))
    target_format = dwarf.TargetFormatter(elf_obj.file_header.machine, elf_obj.data_format)
    sr = dwarf.StreamReader(elf_obj.data_format, stream)
    for entry in dwarf.read_eh_frame(sr):
        if isinstance(entry, dwarf.CieRecord):
            print_cie(entry, target_format)
        else:
            print_fde(entry, target_format, eh_frame.header.address)

    # CieRecord.read doesn't return null record explicitly, but it is present in
    # the stream and objdump prints it.
    print(f'\n{sr.current_position:08x} ZERO terminator\n\n')


def print_dwarf_frames_interp(
    elf_obj: elf.Elf,
) -> None:
    eh_frame = next((s for s in elf_obj.sections if s.name == '.eh_frame'), None)
    if eh_frame is None:
        return
    print('\nContents of the .eh_frame section:\n')

    def print_fde(
        fde: dwarf.FdeRecord,
        cftable: dwarf.CallFrameTable,
        fmt: dwarf.TargetFormatter,
        section_address: int,
    ) -> None:
        print()
        print(_dwarf_frame_fde(fde, fmt.data_format.bits, section_address))

        fde_instr_sr = dwarf.StreamReader(elf_obj.data_format, BytesIO(fde.instructions))
        fde_cftable = cftable.copy(fde.abs_pc_begin(section_address))
        fde_cftable.do_instruction(*dwarf.CfaInstruction.read(fde_instr_sr))
        fde_cftable.objdump_print(fmt, sys.stdout)

    target_format = dwarf.TargetFormatter(elf_obj.file_header.machine, elf_obj.data_format)
    stream = BytesIO(elf_obj.section_content(eh_frame.number))
    sr = dwarf.StreamReader(elf_obj.data_format, stream)
    cie_cftables: dict[int, dwarf.CallFrameTable] = {}
    for entry in dwarf.read_eh_frame(sr):
        if isinstance(entry, dwarf.CieRecord):
            print()
            print(' '.join((
                _dwarf_frame_cie_common(entry, target_format.data_format.bits),
                f'"{entry.augmentation}"',
                f'cf={entry.code_alignment_factor}',
                f'df={entry.data_alignment_factor}',
                f'ra={entry.return_address_register}',
            )))
            init_instr_sr = dwarf.StreamReader(elf_obj.data_format, BytesIO(entry.initial_instructions))
            cie_cftable = dwarf.CallFrameTable(entry)
            cie_cftable.do_instruction(*dwarf.CfaInstruction.read(init_instr_sr))
            cie_cftable.objdump_print(target_format, sys.stdout)
            cie_cftables[entry.offset] = cie_cftable
        else:
            print_fde(entry, cie_cftables[entry.cie.offset], target_format, eh_frame.header.address)

    # CieRecord.read doesn't return null record explicitly, but it is present in
    # the stream and objdump prints it.
    print(f'\n{sr.current_position:08x} ZERO terminator\n\n')


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
    if args.notes:
        print_notes(elf_obj)
    if args.relocations:
        print_relocations(elf_obj)
    if args.dynamic:
        print_dynamic_info(elf_obj)
    if args.version_info:
        print_version_info(elf_obj)
    if args.string_dump:
        string_dump(args.string_dump, elf_obj)
    if args.dwarf:
        if 'rawline' in args.dwarf:
            print_dwarf_rawline(elf_obj)
        if 'decodedline' in args.dwarf:
            print_dwarf_decodedline(elf_obj)
        if 'info' in args.dwarf:
            print_dwarf_info(elf_obj)
        if 'frames-interp' in args.dwarf:
            print_dwarf_frames_interp(elf_obj)
        if 'frames' in args.dwarf:
            print_dwarf_frames(elf_obj)

    elf_file.close()
