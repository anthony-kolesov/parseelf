#include "dwarf.S"

.cfi_sections .eh_frame, .debug_frame

.globl	_start
.type	_start, @function
_start:
	# First FDE for the first CIE.
	.cfi_startproc simple
	.long 0
	.cfi_def_cfa 0, 16
	.cfi_rel_offset 1, 8
	.long 0
	.cfi_adjust_cfa_offset 16
	.cfi_rel_offset 2, 8

	# Try various def_cfa definitions
	.long 0
	.cfi_def_cfa 7, 32
	.long 0
	.cfi_def_cfa_register 6
	.long 0
	.cfi_def_cfa_offset 0
	.long 0
	.cfi_def_cfa_offset 256
	.long 0
	.cfi_def_cfa 7, 32
	.long 0
	.cfi_adjust_cfa_offset 16

	# Try various saved directives.
	.long 0
	.cfi_offset 3, 64
	.long 0
	.cfi_rel_offset 3, 64
	.long 0
	.cfi_val_offset 3, 64
	.long 0
	.cfi_register 4, 5  # r5 stored in r4.
	.long 0
	.cfi_restore 1
	.long 0
	.cfi_undefined 2
	.long 0
	.cfi_same_value 3
	.long 0
	.cfi_remember_state
	.long 0
	.cfi_val_offset 3, 64
	.long 0
	.cfi_restore_state
	.long 0
	.cfi_offset 6, 32
	.long 0
	.cfi_offset 6, 40
	.cfi_endproc

	# Second FDE for the first CIE.
	.cfi_startproc simple
	.long 0
	.cfi_def_cfa 0, 16
	.cfi_rel_offset 1, 8
	.long 0
	.cfi_adjust_cfa_offset 16
	.cfi_rel_offset 2, 8
	.cfi_endproc

	# Signal frame - different augmentation and a separate CIE.
	.cfi_startproc simple
	.cfi_signal_frame
	.long 0
	.cfi_def_cfa 0, 16
	.cfi_rel_offset 1, 8
	.long 0
	.cfi_adjust_cfa_offset 16
	.cfi_rel_offset 2, 8
	.cfi_endproc

	# Different return column - separate CIE.
	.cfi_startproc simple
	.long 0
	.cfi_return_column 6
	.cfi_def_cfa 0, 16
	.cfi_rel_offset 1, 8
	.long 0
	.cfi_adjust_cfa_offset 16
	.cfi_rel_offset 2, 8
	.cfi_endproc

	# Non-simple includes initial instructions in CIE.
	.cfi_startproc
	.long 0
	.cfi_def_cfa 7, 8
	.cfi_rel_offset 1, 8
	.long 0
	.cfi_adjust_cfa_offset 16
	.cfi_rel_offset 2, 8
	.cfi_endproc

	# Hand-written DWARF to test cases that can't be tested with assembler directives.
	.cfi_startproc simple
	.long 0  # Without this .long, .cfi_escape will not generate anything.
	# DW_CFA_set_loc
	.cfi_escape DW_CFA_set_loc, 0x0, 0x1, 0x0, 0x0
	# DW_CFA_advance_loc1
	.cfi_escape DW_CFA_advance_loc1, 0x0c
	.cfi_escape DW_CFA_advance_loc1, 0x01
	.cfi_escape DW_CFA_advance_loc1, 0xff
	# DW_CFA_advance_loc2
	.cfi_escape DW_CFA_advance_loc2, 0x00, 0x04
	.cfi_escape DW_CFA_advance_loc2, 0xff, 0xff
	.cfi_escape DW_CFA_advance_loc2, 0x1, 0x0
	# DW_CFA_advance_loc4
	.cfi_escape DW_CFA_advance_loc4, 0, 0, 1, 0
	# DW_CFA_advance_loc
	.cfi_escape DW_CFA_advance_loc(0xc)

	# DW_CFA_def_cfa
	.long 0
	.cfi_escape DW_CFA_def_cfa, 0xc, 0x8
	# DW_CFA_def_cfa_sf
	.long 0
	.cfi_escape DW_CFA_def_cfa_sf, 0xb, 0x8
	# DW_CFA_def_cfa_register
	.long 0
	.cfi_escape DW_CFA_def_cfa_register, 0xc
	# DW_CFA_def_cfa_offset
	.long 0
	.cfi_escape DW_CFA_def_cfa_offset, 0x8
	# DW_CFA_def_cfa_offset_sf
	.long 0
	.cfi_escape DW_CFA_def_cfa_offset_sf, 0x48
	# DW_CFA_def_cfa_expression, DW_OP_breg7 (rsp): 8
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 0x2, DW_OP_breg(7), 0x8
	# DW_CFA_def_cfa so CFA is not an expression.
	.long 0
	.cfi_escape DW_CFA_def_cfa, 0xc, 0x8

	# DW_CFA_expression
	.long 0
	.cfi_escape DW_CFA_expression, 0x1, 0x2, DW_OP_breg(7), 0x8

	# DW_CFA_val_expression
	.long 0
	.cfi_escape DW_CFA_val_expression, 0x1, 0x2, DW_OP_breg(6), 0xC

	.cfi_endproc

.globl	expression_tests
.type	expression_tests, @function
expression_tests:
	# Test different operations in expressions.
	# The expressions are not evaluated, therefore they are semantically
	# meaningless, the purpose is to only test that they are parsed correctly.
	.cfi_startproc simple

	# This will work only for 32-bit targets.
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 9, DW_OP_addr, 0x2, 0x4, 0x8, 0xc, 0xa4, 0x4a, 0xf0, 0xf0
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_deref

	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_const1u, 0xc1
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_const1s, 0xc1
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_const2u, 0xc1, 0xc1
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_const2s, 0xc1, 0xc1
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 5, DW_OP_const4u, 0xc1, 0xc1, 0xc1, 0xc1
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 5, DW_OP_const4s, 0xc1, 0xc1, 0xc1, 0xc1
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 9, DW_OP_const8u, 0xc1, 0xc2, 0xc3, 0xc4, 0xd5, 0xd6, 0xd7, 0xd8
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 9, DW_OP_const8s, 0xc1, 0xc2, 0xc3, 0xc4, 0xd5, 0xd6, 0xd7, 0x08
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_constu, 0xc1, 0x42
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_consts, 0xc1, 0x42

	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_dup
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_drop
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_over
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_pick, 0xc1
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_swap
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_rot
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_xderef
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_abs
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_and
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_div
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_minus
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_mod
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_mul
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_neg
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_not
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_or
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_plus
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_plus_uconst, 0xc2, 0x43
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_shl
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_shr
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_shra
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_xor
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_bra, 0xc2, 0xc1
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_eq
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_ge
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_gt
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_le
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_lt
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_ne
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_skip, 0xc1, 0xc2

	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_lit(0)
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_lit(1)
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_lit(7)
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_lit(30)
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_lit(31)

	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_reg(0)
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_reg(1)
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_reg(7)
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_reg(30)
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_reg(31)

	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_breg(0), 0
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_breg(1), 1
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_breg(7), 0x60
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_breg(30), 0x20
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_breg(31), 0x40

	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_regx, 0
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_regx, 1
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_regx, 10
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_regx, 31
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_regx, 0x40
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_regx, 0x84, 0x2

	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_fbreg, 0
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_fbreg, 1
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_fbreg, 10
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_fbreg, 0x40

	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_bregx, 0x40, 0x40
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_bregx, 0x1, 0x10
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 5, DW_OP_bregx, 0x84, 0x2, 0x84, 0x2

	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_piece, 0xc1, 0x44
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_deref_size, 0xc5
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 2, DW_OP_xderef_size, 0xc6
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_nop
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_push_object_address
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_call2, 0xc1, 0x72
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 5, DW_OP_call4, 0xc1, 0xc2, 0xc3, 0x74
	# Size depends on DWARF-bits.
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 5, DW_OP_call_ref, 0xc4, 0xc3, 0xc2, 0x71
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_form_tls_address
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_call_frame_cfa
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 5, DW_OP_bit_piece, 0xc1, 0x42, 0xc3, 0x44
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 4, DW_OP_implicit_value, 0x2, 0xc2, 0xc3
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 1, DW_OP_stack_value

	# DWARFv5
	# Size depends on DWARF-bits.
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 7, DW_OP_implicit_pointer, 0xc4, 0xc3, 0xc2, 0xc1, 0xc1, 0x3
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_addrx, 0xc7, 0x48
	# DW_OP_constx is not supported by binutils yet.
	#.long 0
	#.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_constx, 0xc9, 0x4a
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_entry_value, 0x1, DW_OP_reg(6)
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 6, DW_OP_const_type, 0xc1, 0x2, 0x2, 0xC9, 0xC1
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 5, DW_OP_regval_type, 0xC4, 0x45, 0xC6, 0x47
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 4, DW_OP_deref_type, 0xC1, 0xC2, 0x43
	# DW_OP_xderef_type is not supported by binutils yet.
	#.long 0
	# .cfi_escape DW_CFA_def_cfa_expression, 4, DW_OP_xderef_type, 0xC1, 0xC2, 0x43
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_convert, 0xC1, 0x42
	.long 0
	.cfi_escape DW_CFA_def_cfa_expression, 3, DW_OP_reinterpret, 0xC1, 0x42

	.cfi_endproc

