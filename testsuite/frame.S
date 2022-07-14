# Hand-written frame descriptions.

#include "dwarf.S"


# Dummy declaration to create a start symbol.
.globl  _start
.type   _start, @function
_start:
    .long 0
    .long 0
    .long 0
    .long 0
.Lend_start:


.section .debug_frame, "", @progbits
.LDWARFv2_CIE_start:
    .4byte .LDWARFv2_CIE_end - .LDWARFv2_CIE_id  # length
.LDWARFv2_CIE_id:
    .4byte 0xffffffff  # cie_id
    .byte 1  # version
    .string ""  # augmentation
    .uleb128 1  # code alignment factor
    .sleb128 -8  # data alignment factor
    .byte 16  # return address register
    # Initial instructions
    .byte DW_CFA_def_cfa  # DW_CFA_def_cfa: r7 (rsp) ofs 8
        .uleb128 7
        .uleb128 8
    .byte DW_CFA_offset + 16  # DW_CFA_offset: r16 (rip) at cfa-8
        .uleb128 8
    .align 8  # padding
.LDWARFv2_CIE_end:
.LDWARFv2_FDE1_start:
    .4byte .LDWARFv2_FDE1_end - .LDWARFv2_FDE1_id  # length
.LDWARFv2_FDE1_id:
    .4byte .LDWARFv2_CIE_start  # CIE pointer
    .8byte _start  # initial location
    .8byte .Lend_start - _start  # address range
    # Instructions
    .byte DW_CFA_advance_loc(4)
    .byte DW_CFA_def_cfa_offset
        .uleb128 32
    .align 8
.LDWARFv2_FDE1_end:

.LDWARFv3_CIE_start:
    .4byte .LDWARFv3_CIE_end - .LDWARFv3_CIE_id  # length
.LDWARFv3_CIE_id:
    .4byte 0xffffffff  # cie_id
    .byte 3  # version
    .string ""  # augmentation
    .uleb128 1  # code alignment factor
    .sleb128 -8  # data alignment factor
    # It would have been nice to use a large number here to test that parsers
    # actually reads ULEB instead of ubyte, however binutils doesn't print CIEs
    # that has an RA number larger than maximum known DWARF register name, and
    # for AMD64 this is a bit lower than 127. So to use larger number it would
    # be needed to use another architecture, the one with either larger DWARF
    # register number, or without known register names at all. Testing with
    # non-native architecture is too much hassle for me, so this will be left
    # untested.
    .uleb128 16  # return address register.
    # Initial instructions
    .byte DW_CFA_def_cfa  # DW_CFA_def_cfa: r7 (rsp) ofs 8
        .uleb128 7
        .uleb128 8
    .byte DW_CFA_offset + 16  # DW_CFA_offset: r16 (rip) at cfa-8
        .uleb128 8
    .align 8  # padding
.LDWARFv3_CIE_end:
.LDWARFv3_FDE1_start:
    .4byte .LDWARFv3_FDE1_end - .LDWARFv3_FDE1_id  # length
.LDWARFv3_FDE1_id:
    .4byte .LDWARFv3_CIE_start  # CIE pointer
    .8byte _start  # initial location
    .8byte .Lend_start - _start  # address range
    # Instructions
    .byte DW_CFA_advance_loc(4)
    .byte DW_CFA_def_cfa_offset
        .uleb128 32
    .align 8
.LDWARFv3_FDE1_end:

# Test a DWARF 64 structure.
.LDWARFv3x64_CIE_start:
    .4byte 0xffffffff
    .8byte .LDWARFv3x64_CIE_end - .LDWARFv3x64_CIE_id  # length
.LDWARFv3x64_CIE_id:
    .8byte 0xffffffffffffffff  # cie_id
    .byte 3  # version
    .string ""  # augmentation
    .uleb128 1  # code alignment factor
    .sleb128 -8  # data alignment factor
    .uleb128 16  # return address register.
    # Initial instructions
    .byte DW_CFA_def_cfa  # DW_CFA_def_cfa: r7 (rsp) ofs 8
        .uleb128 7
        .uleb128 8
    .byte DW_CFA_offset + 16  # DW_CFA_offset: r16 (rip) at cfa-8
        .uleb128 8
    .align 8  # padding
.LDWARFv3x64_CIE_end:
.LDWARFv3x64_FDE1_start:
    .4byte 0xffffffff
    .8byte .LDWARFv3x64_FDE1_end - .LDWARFv3x64_FDE1_id  # length
.LDWARFv3x64_FDE1_id:
    .8byte .LDWARFv3x64_CIE_start  # CIE pointer
    .8byte _start  # initial location
    .8byte .Lend_start - _start  # address range
    # Instructions
    .byte DW_CFA_advance_loc(4)
    .byte DW_CFA_def_cfa_offset
        .uleb128 32
    .align 8
.LDWARFv3x64_FDE1_end:

.LDWARFv4_CIE_start:
    .4byte .LDWARFv4_CIE_end - .LDWARFv4_CIE_id  # length
.LDWARFv4_CIE_id:
    .4byte 0xffffffff  # cie_id
    .byte 4  # version
    .string ""  # augmentation
    .byte 8  # address size
    .byte 0  # segment selector size
    .uleb128 1  # code alignment factor
    .sleb128 -8  # data alignment factor
    .uleb128 16  # return address register.
    # Initial instructions
    .byte DW_CFA_def_cfa  # DW_CFA_def_cfa: r7 (rsp) ofs 8
        .uleb128 7
        .uleb128 8
    .byte DW_CFA_offset + 16  # DW_CFA_offset: r16 (rip) at cfa-8
        .uleb128 8
    .align 8  # padding
.LDWARFv4_CIE_end:
.LDWARFv4_FDE1_start:
    .4byte .LDWARFv4_FDE1_end - .LDWARFv4_FDE1_id  # length
.LDWARFv4_FDE1_id:
    .4byte .LDWARFv4_CIE_start  # CIE pointer
    .8byte _start  # initial location
    .8byte .Lend_start - _start  # address range
    # Instructions
    .byte DW_CFA_advance_loc(4)
    .byte DW_CFA_def_cfa_offset
        .uleb128 32
    .align 8
.LDWARFv4_FDE1_end:

#if 0
# This test doesn't work with binutils because there is a bug in
# binutils/dwarf.c: while it reads pc_begin correctly as a 4-byte pointer, it
# reads pc_range incorrectly as a 8-byte pointer.
# Try a DWARF64 structure with 32-bit addresses.
.LDWARFv4addr4_CIE_start:
    .4byte 0xffffffff
    .8byte .LDWARFv4addr4_CIE_end - .LDWARFv4addr4_CIE_id  # length
.LDWARFv4addr4_CIE_id:
    .8byte 0xffffffffffffffff  # cie_id
    .byte 4  # version
    .string ""  # augmentation
    .byte 4  # address size
    .byte 0  # segment selector size
    .uleb128 1  # code alignment factor
    .sleb128 -8  # data alignment factor
    .uleb128 16  # return address register.
    # Initial instructions
    .byte DW_CFA_def_cfa  # DW_CFA_def_cfa: r7 (rsp) ofs 8
        .uleb128 7
        .uleb128 8
    .byte DW_CFA_offset + 16  # DW_CFA_offset: r16 (rip) at cfa-8
        .uleb128 8
    .align 8  # padding
.LDWARFv4addr4_CIE_end:
.LDWARFv4addr4_FDE1_start:
    .4byte 0xffffffff
    .8byte .LDWARFv4addr4_FDE1_end - .LDWARFv4addr4_FDE1_id  # length
.LDWARFv4addr4_FDE1_id:
    .8byte .LDWARFv4addr4_CIE_start  # CIE pointer
    .4byte _start  # initial location
    .4byte .Lend_start - _start  # address range
    # Instructions
    .byte DW_CFA_nop
    .byte DW_CFA_nop
    .byte DW_CFA_nop
    .byte DW_CFA_nop
    .byte DW_CFA_advance_loc(4)
    .byte DW_CFA_def_cfa_offset
        .uleb128 32
    .align 8
.LDWARFv4addr4_FDE1_end:
#endif

.4byte 0  # ZERO terminator
