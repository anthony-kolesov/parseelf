#!/bin/bash

PYTHON="C:\\Python310\\python.exe"

for f in test1 test-x86 test-gcc
do
    parse=$(pwd)/../parse_elf.py
    file=$(pwd)/$f.x
    odir=$f
    mkdir -p $odir
    cd $odir
    $PYTHON $parse --file-header $file &> file-header.${f}.txt
    $PYTHON $parse --program-headers $file &> program-headers.${f}.txt
    $PYTHON $parse --section-headers $file &> section-headers.${f}.txt
    # $PYTHON $parse --section-details $file &> section-details.${f}.txt
    $PYTHON $parse --symbols $file &> symbols.${f}.txt
    $PYTHON $parse --notes $file &> notes.${f}.txt
    $PYTHON $parse --relocs $file &> relocs.${f}.txt
    $PYTHON $parse --dynamic $file &> dynamic.${f}.txt
    $PYTHON $parse --version-info $file &> version-info.${f}.txt
    $PYTHON $parse --string-dump=.dynstr --string-dump=.strtab --string-dump=.shstrtab $file &> strings.${f}.txt
    $PYTHON $parse --dwarf=frames $file &> dwarf-frames.${f}.txt
    $PYTHON $parse --dwarf=frames-interp $file &> dwarf-frames-interp.${f}.txt
    cd - >/dev/null
done

for f in test1 test-x86 test-gcc
do
    # Not testing --notes because GNU_PROPERTY_TYPE_0 is currently not supported.
    for t in file-header program-headers section-headers symbols relocs dynamic version-info strings dwarf-frames dwarf-frames-interp
    do
        diff --strip-trailing-cr -uN ref/$f/$t.$f.txt $f/$t.$f.txt
    done
done
