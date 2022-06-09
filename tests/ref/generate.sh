#!/bin/bash

READELF=readelf
OBJDUMP=objdump

cp -L /usr/bin/gcc test-gcc

for f in test1 test-x86 test-gcc
do
    file=../${f}.x
    $READELF -W --file-header $file &> file-header.${f}.txt
    $READELF -W --program-headers $file &> program-headers.${f}.txt
    $READELF -W --section-headers $file &> section-headers.${f}.txt
    # $READELF -W --section-details $file &> section-details.${f}.txt
    $READELF -W --symbols $file &> symbols.${f}.txt
    $READELF --notes $file &> notes.${f}.txt
    $READELF -W --relocs $file &> relocs.${f}.txt
    $READELF -W --dynamic $file &> dynamic.${f}.txt
    $READELF -W --version-info $file &> version-info.${f}.txt
    $READELF -W --string-dump=.dynstr --string-dump=.strtab --string-dump=.shstrtab $file &> strings.${f}.txt
    $OBJDUMP --dwarf $file &> dwarf.${f}.txt
    # Strip lines that I don't want to generate in parse_elf.py
    $OBJDUMP --dwarf=frames $file |& tail -n+3 > dwarf-frames.${f}.txt
    $OBJDUMP --dwarf=frames-interp $file |& tail -n+3 > dwarf-frames-interp.${f}.txt
done
