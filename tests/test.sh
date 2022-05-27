#!/bin/bash

PYTHON="C:\\Python310\\python.exe"

for f in test1 test-x86
do
    file=$f.x
    $PYTHON ../parse_elf.py --file-header $file &> file-header.${f}.txt
    $PYTHON ../parse_elf.py --program-headers $file &> program-headers.${f}.txt
    $PYTHON ../parse_elf.py --section-headers $file &> section-headers.${f}.txt
    # $PYTHON ../parse_elf.py --section-details $file &> section-details.${f}.txt
    $PYTHON ../parse_elf.py --symbols $file &> symbols.${f}.txt
    $PYTHON ../parse_elf.py --notes $file &> notes.${f}.txt
    $PYTHON ../parse_elf.py --relocs $file &> relocs.${f}.txt
    $PYTHON ../parse_elf.py --dynamic $file &> dynamic.${f}.txt
    $PYTHON ../parse_elf.py --version-info $file &> version-info.${f}.txt
    $PYTHON ../parse_elf.py --string-dump=.dynstr --string-dump=.strtab --string-dump=.shstrtab $file &> strings.${f}.txt
done

for f in test1 test-x86
do
    # Not testing --notes because GNU_PROPERTY_TYPE_0 is currently not supported.
    for t in file-header program-headers section-headers symbols relocs dynamic version-info strings
    do
        diff --strip-trailing-cr -uN ref/$t.$f.txt $t.$f.txt
    done
done
