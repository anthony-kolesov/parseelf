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

	# Different retirn column - separate CIE.
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
