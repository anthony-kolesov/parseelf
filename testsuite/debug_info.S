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
    .byte DW_CHILDREN_yes
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

.Lbase_type_abbrev:
    .uleb128 2  # code
    .uleb128 DW_TAG_base_type  # tag
    .byte DW_CHILDREN_no  # has_children
    .uleb128 DW_AT_name
    .uleb128 DW_FORM_strx1
    .uleb128 DW_AT_description
    .uleb128 DW_FORM_strx2
    .uleb128 DW_AT_encoding
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_byte_size
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_endianity
    .uleb128 DW_FORM_data1
    .uleb128 0  # End of abbreviation.
    .uleb128 0

# A tag which contains *all* attributes. Standard doesn't forbid abbreviations
# to have attributes that don't make sense, so I can use it here just to test
# the correctness of attribute printing - so the test is for the presentation,
# not for semantics.
.Lall_attributes_abbrev:
    .uleb128 0xff0  # Abbreviation number.
    .uleb128 DW_TAG_constant
    .byte DW_CHILDREN_yes
    .uleb128 DW_AT_sibling
    .uleb128 DW_FORM_ref4
    # .uleb128 DW_AT_location
    # .uleb128 DW_FORM_loclistx
    .uleb128 DW_AT_name
    .uleb128 DW_FORM_strp
    .uleb128 DW_AT_ordering
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_byte_size
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_bit_size
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_stmt_list
    .uleb128 DW_FORM_sec_offset  # Offset into .debug_line
    .uleb128 DW_AT_low_pc
    .uleb128 DW_FORM_addr
    .uleb128 DW_AT_high_pc
    .uleb128 DW_FORM_data8
    .uleb128 DW_AT_language
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_discr
    .uleb128 DW_FORM_ref4
    .uleb128 DW_AT_discr_value
    .uleb128 DW_FORM_data4
    .uleb128 DW_AT_visibility
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_import
    .uleb128 DW_FORM_ref4
    # .uleb128 DW_AT_string_length
    # .uleb128 DW_FORM_loclistx
    .uleb128 DW_AT_common_reference
    .uleb128 DW_FORM_ref4
    .uleb128 DW_AT_comp_dir
    .uleb128 DW_FORM_strp
    .uleb128 DW_AT_const_value
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_containing_type
    .uleb128 DW_FORM_ref4
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_inline
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_is_optional
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_lower_bound
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_producer
    .uleb128 DW_FORM_strp
    .uleb128 DW_AT_prototyped
    .uleb128 DW_FORM_flag
    # .uleb128 DW_AT_return_addr
    # .uleb128 DW_FORM_loclistx
    .uleb128 DW_AT_start_scope
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_bit_stride
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_upper_bound
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_abstract_origin
    .uleb128 DW_FORM_ref4
    .uleb128 DW_AT_accessibility
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_address_class
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_artificial
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_base_types
    .uleb128 DW_FORM_ref4
    .uleb128 DW_AT_calling_convention
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_count
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_data_member_location
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_decl_column
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_decl_file
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_decl_line
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_declaration
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_discr_list
    .uleb128 DW_FORM_block
    .uleb128 DW_AT_encoding
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_external
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_frame_base
    .uleb128 DW_FORM_exprloc
    .uleb128 DW_AT_friend
    .uleb128 DW_FORM_ref4
    .uleb128 DW_AT_identifier_case
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_namelist_item
    .uleb128 DW_FORM_ref4
    .uleb128 DW_AT_priority
    .uleb128 DW_FORM_ref4
    # .uleb128 DW_AT_segment
    # .uleb128 DW_FORM_loclistx
    .uleb128 DW_AT_specification
    .uleb128 DW_FORM_ref4
    # .uleb128 DW_AT_static_link
    # .uleb128 DW_FORM_loclistx
    .uleb128 DW_AT_type
    .uleb128 DW_FORM_ref4
    # .uleb128 DW_AT_use_location
    # .uleb128 DW_FORM_loclistx
    .uleb128 DW_AT_variable_parameter
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_virtuality
    .uleb128 DW_FORM_data1
    # .uleb128 DW_AT_vtable_elem_location
    # .uleb128 DW_FORM_loclistx
    .uleb128 DW_AT_allocated
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_associated
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_data_location
    .uleb128 DW_FORM_exprloc
    .uleb128 DW_AT_byte_stride
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_entry_pc
    .uleb128 DW_FORM_addr
    .uleb128 DW_AT_use_UTF8
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_extension
    .uleb128 DW_FORM_ref4
    # .uleb128 DW_AT_ranges
    # .uleb128 DW_FORM_rnglistx
    .uleb128 DW_AT_trampoline
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_call_column
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_call_file
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_call_line
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_description
    .uleb128 DW_FORM_strp
    .uleb128 DW_AT_binary_scale
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_decimal_scale
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_small
    .uleb128 DW_FORM_ref4
    .uleb128 DW_AT_decimal_sign
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_digit_count
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_picture_string
    .uleb128 DW_FORM_string
    .uleb128 DW_AT_mutable
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_threads_scaled
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_explicit
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_object_pointer
    .uleb128 DW_FORM_ref4
    .uleb128 DW_AT_endianity
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_elemental
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_pure
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_recursive
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_signature
    .uleb128 DW_FORM_ref4
    .uleb128 DW_AT_main_subprogram
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_data_bit_offset
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_const_expr
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_enum_class
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_linkage_name
    .uleb128 DW_FORM_string
    # DWARFv5
    .uleb128 DW_AT_string_length_bit_size
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_string_length_byte_size
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_rank
    .uleb128 DW_FORM_data1
    # .uleb128 DW_AT_str_offsets_base - duplicates CU attribute
    # .uleb128 DW_FORM_sec_offset
    # .uleb128 DW_AT_addr_base
    # .uleb128 DW_FORM_sec_offset
    # .uleb128 DW_AT_rnglists_base
    # .uleb128 DW_FORM_sec_offset
    # .uleb128 DW_AT_dwo_name - can't test it, requires DWO support.
    # .uleb128 DW_FORM_string
    .uleb128 DW_AT_reference
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_rvalue_reference
    .uleb128 DW_FORM_flag
    # .uleb128 DW_AT_macros
    # .uleb128 DW_FORM_sec_offset
    .uleb128 DW_AT_call_all_calls
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_call_all_source_calls
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_call_all_tail_calls
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_call_return_pc
    .uleb128 DW_FORM_addr
    # .uleb128 DW_AT_call_value
    # .uleb128 DW_FORM_exprloc
    # .uleb128 DW_AT_call_origin
    # .uleb128 DW_FORM_exprloc
    .uleb128 DW_AT_call_parameter
    .uleb128 DW_FORM_ref4
    .uleb128 DW_AT_call_pc
    .uleb128 DW_FORM_addr
    .uleb128 DW_AT_call_tail_call
    .uleb128 DW_FORM_flag
    # .uleb128 DW_AT_call_target
    # .uleb128 DW_FORM_exprloc
    # .uleb128 DW_AT_call_target_clobbered
    # .uleb128 DW_FORM_exprloc
    # .uleb128 DW_AT_call_data_location
    # .uleb128 DW_FORM_exprloc
    # .uleb128 DW_AT_call_data_value
    # .uleb128 DW_FORM_exprloc
    .uleb128 DW_AT_noreturn
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_alignment
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_export_symbols
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_deleted
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_defaulted
    .uleb128 DW_FORM_data1
    # .uleb128 DW_AT_loclists_base  # Offset into .debug_loclists
    # .uleb128 DW_FORM_sec_offset
    .uleb128 0  # End of abbreviation.
    .uleb128 0

# An abbreviation that enumerates through all possible forms. It uses same
# attribute for all forms, which of course doesn't make any semantic sense, but
# the test is for the data presentation, and not for semantic handling, so this
# is ok, and makes test simpler.
.Lall_forms_abbrev:
    .uleb128 0xff1  # Abbreviation number.
    .uleb128 DW_TAG_constant
    .byte DW_CHILDREN_no
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_addr
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_block2
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_block4
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_data2
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_data4
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_data8
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_string
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_block
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_block1
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_data1
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_flag
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_sdata
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_strp
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_udata
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_ref_addr
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_ref1
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_ref2
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_ref4
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_ref8
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_ref_udata
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_indirect
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_sec_offset
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_exprloc
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_flag_present
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_ref_sig8  # Not supported properly yet
    # DWARFv5
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_strx
    # .uleb128 DW_AT_default_value  # debug_addr
    # .uleb128 DW_FORM_addrx        # debug_addr
    # .uleb128 DW_FORM_ref_sup4  # Can't test - needs a supplementary file.
    # .uleb128 DW_FORM_strp_sup  # Can't test - needs a supplementary file.
    # .uleb128 DW_FORM_data16  # 16-byte integers not supported.
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_line_strp
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_implicit_const
    .uleb128 0x5a  # implicit constant value.
    # .uleb128 DW_AT_default_value  # debug_loclists
    # .uleb128 DW_FORM_loclistx     # debug_loclists
    # .uleb128 DW_AT_default_value  # debug_rnglists
    # .uleb128 DW_FORM_rnglistx     # debug_rnglists
    # .uleb128 DW_FORM_ref_sup8  # Can't test - needs a supplementary file.
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_strx1
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_strx2
    # .uleb128 DW_FORM_strx3  # 3-byte integers not supported.
    .uleb128 DW_AT_default_value
    .uleb128 DW_FORM_strx4
    # .uleb128 DW_AT_default_value  # debug_addr
    # .uleb128 DW_FORM_addrx1       # debug_addr
    # .uleb128 DW_AT_default_value  # debug_addr
    # .uleb128 DW_FORM_addrx2       # debug_addr
    # .uleb128 DW_FORM_addrx3  # 3-byte integers not supported.
    # .uleb128 DW_AT_default_value  # debug_addr
    # .uleb128 DW_FORM_addrx4       # debug_addr
    .uleb128 0  # End of .Lall_forms_abbrev abbreviation.
    .uleb128 0

    .uleb128 0  # End of .Lall_attributes_abbrev children.

    .uleb128 0  # End of .LCU1_abbrev children.

    .uleb128 0  # End of CU abbreviation.


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

.LDW5_base_type_DIE:
    .uleb128 2  # abbreviation number
    .byte 3  # DW_AT_name
    .2byte 4  # DW_AT_description
    .byte DW_ATE_unsigned  # DW_AT_encoding
    .byte 4  # DW_AT_byte_size
    .byte DW_END_little

.Lall_attributes_DIE:
    .uleb128 0xff0  # Abbreviation number.
    .4byte .LDW5_base_type_DIE2 - .LDW5_CU1_start  # DW_AT_sibling
        # An offset from the CU header to the referenced DIE. Semantically it
        # should be a forward reference and point to an DIE with higher offset
        # in the file (though this is not technically required).
    # DW_AT_location
    .4byte .Lstr_all_attributes_name  # DW_AT_name
    .byte DW_ORD_row_major  # DW_AT_ordering
    .byte (0xc0 / 8)  # DW_AT_byte_size
    .byte 0xc0  # DW_AT_bit_size
    .4byte 0  # DW_AT_stmt_list, TODO: put meaningful value here.
    .8byte _start  # DW_AT_low_pc
    .8byte .Lend_start  # DW_AT_high_pc
    .byte DW_LANG_C99  # DW_AT_language
    .4byte .LDW5_base_type_DIE - .LDW5_CU1_start  # DW_AT_discr
    .4byte 0x5aa5f00f  # DW_AT_discr_value
    .byte DW_VIS_exported  # DW_AT_visibility
    .4byte .LDW5_base_type_DIE  # DW_AT_import
    # DW_AT_string_length
    .4byte .LDW5_base_type_DIE  # DW_AT_common_reference
    .4byte .Lstr_compile_dir  # DW_AT_comp_dir
    .byte 0xc0  # DW_AT_const_value
    .4byte .LDW5_base_type_DIE  # DW_AT_containing_type
    .byte 0x81  # DW_AT_default_value
    .byte DW_INL_inlined  # DW_AT_inline
    .byte 0  # DW_AT_is_optional
    .byte 5  # DW_AT_lower_bound
    .4byte .Lstr_producer  # DW_AT_producer
    .byte 1  # DW_AT_prototyped
    .byte 12  # DW_AT_start_scope
    .byte 7  # DW_AT_bit_stride
    .byte 19  # DW_AT_upper_bound
    .4byte .LDW5_base_type_DIE  # DW_AT_abstract_origin
    .byte DW_ACCESS_public  # DW_AT_accessibility
    .byte 0  # DW_AT_address_class. Values are arch-specific.
    .byte 1  # DW_AT_artificial
    .4byte .LDW5_base_type_DIE  # DW_AT_base_types
    .byte DW_CC_normal  # DW_AT_calling_convention
    .byte 13  # DW_AT_count
    .byte 7  # DW_AT_data_member_location
    .byte 1  # DW_AT_decl_column
    .byte 1  # DW_AT_decl_file
    .byte 1  # DW_AT_decl_line
    .byte 0  # DW_AT_declaration
    .uleb128 .Lall_attributes_DIE_discr_list_end - .Lall_attributes_DIE_discr_list  # DW_AT_discr_list
.Lall_attributes_DIE_discr_list:
        .byte DW_DSC_label
        .uleb128 4
        .byte DW_DSC_range
        .uleb128 6
        .uleb128 8
        .byte DW_DSC_range
        .uleb128 12
        .uleb128 16
        .byte DW_DSC_label
        .uleb128 20
.Lall_attributes_DIE_discr_list_end:
    .byte DW_ATE_unsigned  # DW_AT_encoding
    .byte 1  # DW_AT_external
    .uleb128 1  # DW_AT_frame_base
        .byte DW_OP_call_frame_cfa
    .4byte .LDW5_base_type_DIE  # DW_AT_friend
    .byte DW_ID_case_sensitive # DW_AT_identifier_case
    .4byte .LDW5_base_type_DIE  # DW_AT_namelist_item
    .4byte .LDW5_base_type_DIE  # DW_AT_priority
    .4byte .LDW5_base_type_DIE  # DW_AT_specification
    .4byte .LDW5_base_type_DIE  # DW_AT_type
    .byte 0  # DW_AT_variable_parameter
    .byte DW_VIRTUALITY_pure_virtual  # DW_AT_virtuality
    .byte 1  # DW_AT_allocated
    .byte 1  # DW_AT_associated
    .uleb128 .Lall_attributes_DIE_data_location_end - .Lall_attributes_DIE_data_location  # DW_AT_data_location
.Lall_attributes_DIE_data_location:
        .byte DW_OP_lit(7)
.Lall_attributes_DIE_data_location_end:
    .byte 3  # DW_AT_byte_stride
    .8byte _start  # DW_AT_entry_pc
    .byte 1  # DW_AT_use_UTF8
    .4byte .LDW5_base_type_DIE  # DW_AT_extension
    .byte 1  # DW_AT_trampoline
    .byte 2  # DW_AT_call_column
    .byte 1  # DW_AT_call_file
    .byte 1  # DW_AT_call_line
    .4byte .Lstr_all_attributes_description  # DW_AT_description
    .byte 2  # DW_AT_binary_scale
    .byte 3  # DW_AT_decimal_scale
    .4byte .LDW5_base_type_DIE  # DW_AT_extension
    .byte DW_DS_unsigned  # DW_AT_decimal_sign
    .byte 3  # DW_AT_digit_count
    .string "x0x0x0x0x0"  # DW_AT_picture_string
    .byte 1  # DW_AT_mutable
    .byte 1  # DW_AT_threads_scaled
    .byte 1  # DW_AT_explicit
    .4byte .LDW5_base_type_DIE  # DW_AT_object_pointer
    .byte DW_END_little  # DW_AT_endianity
    .byte 1  # DW_AT_elemental
    .byte 1  # DW_AT_pure
    .byte 1  # DW_AT_recursive
    .4byte .LDW5_base_type_DIE  # DW_AT_signature
    .byte 1  # DW_AT_main_subprogram
    .byte 2  # DW_AT_data_bit_offset
    .byte 1  # DW_AT_const_expr
    .byte 1  # DW_AT_enum_class
    .string "all_attributes_die_linkage_name"  # DW_AT_linkage_name
    .byte 1  # DW_AT_string_length_bit_size
    .byte 1  # DW_AT_string_length_byte_size
    .byte 3  # DW_AT_rank
    # .4byte 8  # DW_AT_addr_base
    # .4byte 8  # DW_AT_rnglists_base
    # .string "all_attributes_dwo"  # DW_AT_dwo_name
    .byte 1  # DW_AT_reference
    .byte 1  # DW_AT_rvalue_reference
    # .4byte 8  # DW_AT_macros
    .byte 1  # DW_AT_call_all_calls
    .byte 1  # DW_AT_call_all_source_calls
    .byte 1  # DW_AT_call_all_tail_calls
    .8byte _start  # DW_AT_call_return_pc
    # DW_AT_call_value
    # DW_AT_call_origin
    .4byte .LDW5_base_type_DIE  # DW_AT_call_parameter
    .8byte _start  # DW_AT_call_pc
    .byte 1  # DW_AT_call_tail_call
    # DW_AT_call_target
    # DW_AT_call_target_clobbered
    # DW_AT_call_data_location
    # DW_AT_call_data_value
    .byte 1  # DW_AT_noreturn
    .byte 8  # DW_AT_alignment
    .byte 1  # DW_AT_export_symbols
    .byte 1  # DW_AT_deleted
    .byte DW_DEFAULTED_out_of_class  # DW_AT_defaulted
    # .4byte 0 # DW_AT_loclists_base, TODO: put meaningful value here.

.Lall_forms_DIE:
    .uleb128 0xff1  # Abbreviation number.
    .8byte _start  # DW_FORM_addr
    .2byte 1  # # DW_FORM_block2
        .byte DW_OP_lit(12)
    .4byte 1  # # DW_FORM_block4
        .byte DW_OP_lit(14)
    .2byte 0xc0f5  # DW_FORM_data2
    .4byte 0xc0f0a5af  # DW_FORM_data4
    .8byte 0xc0f0a5af11223344  # DW_FORM_data8
    .string "awesome compiler"  # DW_FORM_string
    .uleb128 1  # DW_FORM_block
        .byte DW_OP_lit(19)
    .byte 1  # # DW_FORM_block1
        .byte DW_OP_lit(11)
    .byte 0xc3  # DW_FORM_data1
    .byte 1  # DW_FORM_flag
    .uleb128 0xc0f0a5af  # DW_FORM_sdata
    .4byte .Lstr_producer  # DW_FORM_strp
    .uleb128 0xc0f0a5af  # DW_FORM_udata
    .4byte  .LDW5_base_type_DIE2 # DW_FORM_ref_addr
    .byte .LDW5_base_type_DIE  # DW_FORM_ref1
    .2byte .LDW5_base_type_DIE  # DW_FORM_ref2
    .4byte .LDW5_base_type_DIE  # DW_FORM_ref4
    .8byte .LDW5_base_type_DIE  # DW_FORM_ref8
    .uleb128 .LDW5_base_type_DIE  # DW_FORM_ref_udata
    .uleb128 DW_FORM_strx  # DW_FORM_indirect
        .byte 1
    .4byte 8 # DW_FORM_sec_offset
    .uleb128 1  # DW_FORM_exprloc
        .byte DW_OP_lit(19)
    # DW_FORM_flag_present - implicit value.
    .8byte 0xc0f0a5af11223344  # DW_FORM_ref_sig8 - not supported yet
    .uleb128 1  # DW_FORM_strx
    # .uleb128 1  # DW_FORM_addrx
    .4byte .Lline_str1 + 2  #  DW_FORM_line_strp (offset in the middle of the string)
    # DW_FORM_implicit_const - implicit value.
    .byte 1  # DW_FORM_strx1
    .2byte 1  # DW_FORM_strx2
    .4byte 1  # DW_FORM_strx4
    # .byte 1  # DW_FORM_addrx1
    # .2byte 1  # DW_FORM_addrx2
    # .4byte 1  # DW_FORM_addrx4
.LDW5_base_type_DIE2:
    .uleb128 2  # abbreviation number
    .byte 3  # DW_AT_name
    .2byte 4  # DW_AT_description
    .byte DW_ATE_unsigned  # DW_AT_encoding
    .byte 4  # DW_AT_byte_size
    .byte DW_END_little  # DW_AT_endianity

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
.Lstr_int:
    .string "int"
.Lstr_int_description:
    .string "A simple word-sized integer type."
.Lstr_all_attributes_name:
    .string "all_attributes_die"
.Lstr_all_attributes_description:
    .string "A DIE with all attributes."


# Order of sections is important here, because when passed --dwarf objdump
# iterates over sections and applies correct "section formatting" as it
# encounters sections, but parse_elf.py instead iterates over options and prints
# sections affected by the selected "formatter". Hence, when the option is just
# --dwarf, and order of sections is .debug_str, .debug_str_offsets,
# .debug_line_str, then objdump will print them in that order, while
# parse_elf.py will print in order of .debug_str, .debug_line_str,
# .debug_str_offsets. At this moment I don't want to bother with fixing this
# discrepancy in algorithm, hence test cases shouldn't expose the difference.
.section .debug_line_str, "S", @progbits
.Lline_str1:
    .string "string1"


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
    .4byte .Lstr_int
    .4byte .Lstr_int_description
.LCU1_str_offsets_end:
