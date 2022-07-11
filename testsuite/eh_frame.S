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

	# Hand-written dwarf, without CFI directives.
	.cfi_startproc simple
	.long 0  # Without this .long, .cfi_escape will not generate anything.
	# DW_CFA_set_loc
	.cfi_escape 0x1, 0x0, 0x1, 0x0, 0x0
	# DW_CFA_advance_loc1
	.cfi_escape 0x2, 0x0c
	.cfi_escape 0x2, 0x01
	.cfi_escape 0x2, 0xff
	# DW_CFA_advance_loc2
	.cfi_escape 0x3, 0x00, 0x04
	.cfi_escape 0x3, 0xff, 0xff
	.cfi_escape 0x3, 0x1, 0x0
	# DW_CFA_advance_loc4
	.cfi_escape 0x4, 0,0,1,0
	# DW_CFA_advance_loc
	.cfi_escape 0x40 + 0xc

	# DW_CFA_def_cfa
	.long 0
	.cfi_escape 0x0c, 0xc, 0x8
	# DW_CFA_def_cfa_sf
	.long 0
	.cfi_escape 0x12, 0xb, 0x8
	# DW_CFA_def_cfa_register
	.long 0
	.cfi_escape 0x0d, 0xc
	# DW_CFA_def_cfa_offset
	.long 0
	.cfi_escape 0x0e, 0x8
	# DW_CFA_def_cfa_offset_sf
	.long 0
	.cfi_escape 0x13, 0x48
	# DW_CFA_def_cfa_expression, DW_OP_breg7 (rsp): 8
	.long 0
	.cfi_escape 0x0f, 0x2, 0x77, 0x8
	# DW_CFA_def_cfa so CFA is not an expression.
	.long 0
	.cfi_escape 0x0c, 0xc, 0x8

	.cfi_endproc
