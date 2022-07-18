# Tests for .debug_info and sections it depend on.

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

.section .debug_abbrev, "", @progbits
.LCU1_abbrev:
    .uleb128 1  # code
    .uleb128 DW_TAG_compile_unit  # tag
    .byte DW_CHILDREN_no  # has_children
    # Attributes
    .uleb128 DW_AT_low_pc
    .uleb128 DW_FORM_addr
    .uleb128 DW_AT_high_pc
    .uleb128 DW_FORM_data8
    .uleb128 DW_AT_name
    .uleb128 DW_FORM_string  # Use direct string to test this form.
    .uleb128 DW_AT_language
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_stmt_list
    .uleb128 DW_FORM_sec_offset  # Offset into .debug_line
    .uleb128 DW_AT_macros
    .uleb128 DW_FORM_sec_offset  # Offset into .debug_macro
    .uleb128 DW_AT_comp_dir
    .uleb128 DW_FORM_strp
    .uleb128 DW_AT_producer
    .uleb128 DW_FORM_strx
    .uleb128 DW_AT_identifier_case
    .uleb128 DW_FORM_data1
    # .uleb128 DW_AT_base_types
    # Reference into another compilation unit.
    .uleb128 DW_AT_use_UTF8
    .uleb128 DW_FORM_flag_present
    .uleb128 DW_AT_main_subprogram
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_entry_pc
    .uleb128 DW_FORM_addr
    .uleb128 DW_AT_str_offsets_base # Offset into .debug_str_offsets
    .uleb128 DW_FORM_sec_offset
    .uleb128 DW_AT_addr_base  # Offset into .debug_addr
    .uleb128 DW_FORM_sec_offset
    .uleb128 DW_AT_rnglists_base  # Offset into .debug_rnglists
    .uleb128 DW_FORM_sec_offset
    .uleb128 DW_AT_loclists_base  # Offset into .debug_loclists
    .uleb128 DW_FORM_sec_offset
    .uleb128 0
    .uleb128 0

    .uleb128 0 # End of CU abbreviation.


.section .debug_info, "", @progbits
.LDW5_CU1_start:
    .4byte .LDW5_CU1_end - .LDW5_CU1_version  # length, DWARF-32
.LDW5_CU1_version:
    .2byte 5  # version
    .byte DW_UT_compile  # unity type
    .byte 8  # address_size
    .4byte .LCU1_abbrev  # debug_abbrev_offset

.LDW5_CU1_DIE1:
    .uleb128 1  # abbreviation number
    .8byte _start  # DW_AT_low_pc
    .8byte .Lend_start  # DW_AT_high_pc
    .string "start_dw5"  # DW_AT_name
    .byte DW_LANG_C99  # DW_AT_language
    .4byte 0  # DW_AT_stmt_list, TODO: put meaningful value here.
    .4byte 0  # DW_AT_macros, TODO: put meaningful value here.
    .4byte .Lstr_compile_dir  # DW_AT_comp_dir
    .uleb128 1  # DW_AT_producer
    .byte DW_ID_case_sensitive # DW_AT_identifier_case
    .byte 1  # DW_AT_main_subprogram
    .8byte _start  # DW_AT_entry_pc
    # DW_AT_str_offsets_base should be a section offset that points to a first
    # entry in the table, entry specific to this CU. This value would be 8 at
    # least: 4 bytes for length in DWARF32, 4 bytes for header. DWARF64 would
    # have 12 bytes for length. In this example I use DWARF32 and skip the
    # first entry.
    .4byte 12  # DW_AT_str_offsets_base
    .4byte 0 # DW_AT_addr_base, TODO: put meaningful value here.
    .4byte 0 # DW_AT_rnglists_base, TODO: put meaningful value here.
    .4byte 0 # DW_AT_loclists_base, TODO: put meaningful value here.
    .uleb128  0 # End of DIE entries
.LDW5_CU1_end:


.section .debug_str, "S", @progbits
.Lstr_dummy1:
    .string "dummy1"
.Lstr_compile_dir:
    .string "/home/anton"
.Lstr_producer:
    .string "awesome compiler"
.Lstr_dummy2:
    .string "dummy2"


.section .debug_str_offsets, "", @progbits
.LCU1_str_offsets:
    .4byte .LCU1_str_offsets_end - .LCU1_str_offsets_version # length
.LCU1_str_offsets_version:
    .2byte 5  # version
    .2byte 0  # padding
    .4byte .Lstr_dummy1
    .4byte .Lstr_compile_dir
    .4byte .Lstr_producer
    .4byte .Lstr_dummy2
.LCU1_str_offsets_end:
