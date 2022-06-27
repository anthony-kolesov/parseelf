#!/bin/bash

PYTHON="C:\\Python310\\python.exe"
COVERAGE_FILE=coverage.bin
COVERAGE_RES=coverage-result
PFLAGS="-mtrace --count --file=$COVERAGE_FILE --coverdir=$COVERAGE_RES"
DW_CATEGORIES="--dwarf=rawline --dwarf=info --dwarf=abbrev --dwarf=aranges --dwarf=frames --dwarf=str"
parse=$(pwd)/../parse_elf.py

test=eh_frame

rm -rf $COVERAGE_RES $COVERAGE_FILE
for test in eh_frame test1
do
    $PYTHON $PFLAGS --ignore-dir='C:\Python310\lib' $parse -f -l -S -s -r -d -V -n ${test}.x > ${test}.gen.txt
    $PYTHON $PFLAGS --ignore-dir='C:\Python310\lib' $parse $DW_CATEGORIES ${test}.x >> ${test}.gen.txt
    $PYTHON $PFLAGS --ignore-dir='C:\Python310\lib' $parse --dwarf=frames-interp --dwarf=decodedline ${test}.x >> ${test}.gen.txt
    diff --strip-trailing-cr -uN ${test}.ref.txt ${test}.gen.txt
done
$PYTHON -mtrace --report --file=$COVERAGE_FILE --missing --summary --coverdir=$COVERAGE_RES
