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
    .uleb128 DW_FORM_strp
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
