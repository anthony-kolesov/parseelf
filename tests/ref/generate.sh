#!/bin/bash

READELF=readelf

for f in test1 test-x86
do
    file=../${f}.x
    $READELF -W --file-header $file &> file-header.${f}.txt
    $READELF -W --program-headers $file &> program-headers.${f}.txt
    $READELF -W --section-headers $file &> section-headers.${f}.txt
    # $READELF -W --section-details $file &> section-details.${f}.txt
    $READELF -W --symbols $file &> symbols.${f}.txt
    $READELF -W --relocs $file &> relocs.${f}.txt
    $READELF -W --string-dump=.dynstr --string-dump=.strtab --string-dump=.shstrtab $file &> strings.${f}.txt
done
