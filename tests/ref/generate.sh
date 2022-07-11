#!/bin/bash

READELF=${READELF:-readelf}
OBJDUMP=${OBJDUMP:-objdump}

cp -L /usr/bin/gcc ../test-gcc.x

for f in test1 test-x86 test-gcc test2
do
    file=$(pwd)/../${f}.x
    odir=$f
    mkdir -p $odir
    cd $odir
    $READELF -W --file-header $file &> file-header.${f}.txt
    $READELF -W --program-headers $file &> program-headers.${f}.txt
    $READELF -W --section-headers $file &> section-headers.${f}.txt
    # $READELF -W --section-details $file &> section-details.${f}.txt
    $READELF -W --symbols $file &> symbols.${f}.txt
    $READELF -W --notes $file &> notes.${f}.txt
    $READELF -W --relocs $file &> relocs.${f}.txt
    $READELF -W --dynamic $file &> dynamic.${f}.txt
    $READELF -W --version-info $file &> version-info.${f}.txt
    $READELF -W --string-dump=.dynstr --string-dump=.strtab --string-dump=.shstrtab $file &> strings.${f}.txt
    $READELF -W --hex-dump=.text --hex-dump=.dynstr --hex-dump=.strtab --hex-dump=.shstrtab $file &> hex.${f}.txt
    $OBJDUMP --dwarf $file &> dwarf.${f}.txt
    # Strip lines that I don't want to generate in parse_elf.py
    $OBJDUMP --dwarf=rawline $file |& tail -n+4 > dwarf-rawline.${f}.txt
    $OBJDUMP --dwarf=decodedline $file |& tail -n+4 > dwarf-decodedline.${f}.txt
    $OBJDUMP --dwarf=info $file |& tail -n+4 > dwarf-info.${f}.txt
    $OBJDUMP --dwarf=abbrev $file |& tail -n+4 > dwarf-abbrev.${f}.txt
    # $OBJDUMP --dwarf=pubnames $file |& tail -n+4 > dwarf-pubnames.${f}.txt
    $OBJDUMP --dwarf=aranges $file |& tail -n+4 > dwarf-aranges.${f}.txt
    # $OBJDUMP --dwarf=macro $file |& tail -n+4 > dwarf-macro.${f}.txt
    $OBJDUMP --dwarf=frames $file |& tail -n+4 > dwarf-frames.${f}.txt
    $OBJDUMP --dwarf=frames-interp $file |& tail -n+4 > dwarf-frames-interp.${f}.txt
    $OBJDUMP --dwarf=str $file |& tail -n+4 > dwarf-str.${f}.txt
    $OBJDUMP --dwarf=loc $file |& tail -n+4 > dwarf-loc.${f}.txt
    # $OBJDUMP --dwarf=Ranges $file |& tail -n+4 > dwarf-Ranges.${f}.txt
    # $OBJDUMP --dwarf=pubtypes $file |& tail -n+4 > dwarf-pubtypes.${f}.txt
    # $OBJDUMP --dwarf=gdb_index $file |& tail -n+4 > dwarf-gdb_index.${f}.txt
    # $OBJDUMP --dwarf=trace_info $file |& tail -n+4 > dwarf-trace_info.${f}.txt
    # $OBJDUMP --dwarf=trace_abbrev $file |& tail -n+4 > dwarf-trace_abbrev.${f}.txt
    # $OBJDUMP --dwarf=trace_aranges $file |& tail -n+4 > dwarf-trace_aranges.${f}.txt
    # $OBJDUMP --dwarf=addr $file |& tail -n+4 > dwarf-addr.${f}.txt
    # $OBJDUMP --dwarf=cu_index $file |& tail -n+4 > dwarf-cu_index.${f}.txt
    # $OBJDUMP --dwarf=links $file |& tail -n+4 > dwarf-links.${f}.txt
    # $OBJDUMP --dwarf=follow-links $file |& tail -n+4 > dwarf-follow-links.${f}.txt
    cd - >/dev/null
done
