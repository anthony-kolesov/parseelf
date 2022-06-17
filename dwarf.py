# Copyright (c) 2022 Anton Kolesov
# SPDX-License-Identifier: MIT

"""Classes specific to parsing of DWARF."""

__all__ = [
    'StreamReader',
    'TargetFormatter',
    'CfaInstructionCode',
    'CfaInstruction',
    'ExpressionOperationCode',
    'ExpressionOperation',
    'DW_EH_PE_ValueType',
    'DW_EH_PE_Relation',
    'CieAugmentation',
    'CieRecord',
    'FdeRecord',
    'read_eh_frame',
    'CfaDefinition',
    'RegisterRule',
    'CallFrameTableRow',
    'CallFrameTable',
    'LineNumberConst',
    'FileNameEntry',
    'LineNumberStatement',
    'LineNumberProgram',
    'LineNumberStateRow',
    'LineNumberStateMachine',
]

import builtins
from collections import ChainMap
import collections.abc
import dataclasses
from enum import Enum
from io import BytesIO, SEEK_CUR
from typing import BinaryIO, final, Iterable, Iterator, Mapping, \
    MutableMapping, NamedTuple, Optional, Sequence, TextIO

from elf import align_up, DataFormat, ElfClass, ElfMachineType


class StreamReader:
    """A class to read DWARF data from the file stream."""

    def __init__(self, data_format: DataFormat, stream: BinaryIO) -> None:
        self.__df = data_format
        self.__stream = stream

    def bytes(self, size: int) -> bytes:
        """Read the specified amount of bytes from the stream."""
        return self.__stream.read(size)

    def uint1(self) -> int:
        return self.__df.read_uint1(self.__stream.read(1))

    def uint2(self) -> int:
        return self.__df.read_uint2(self.__stream.read(2))

    def uint4(self) -> int:
        return self.__df.read_uint4(self.__stream.read(4))

    def uint8(self) -> int:
        return self.__df.read_uint8(self.__stream.read(8))

    def sint1(self) -> int:
        return self.__df.read_sint1(self.__stream.read(1))

    def sint2(self) -> int:
        return self.__df.read_sint2(self.__stream.read(2))

    def sint4(self) -> int:
        return self.__df.read_sint4(self.__stream.read(4))

    def sint8(self) -> int:
        return self.__df.read_sint8(self.__stream.read(8))

    def pointer(self) -> int:
        if self.__df.bits == ElfClass.ELF64:
            return self.uint8()
        return self.uint4()

    def cstring(self) -> str:
        """Read a zero terminated string from a stream.

        Note the difference from the similar function in the DataFormat, which
        reads from byte buffer instead of a stream."""
        r = []
        while (c := self.__stream.read(1)) != b'\x00':
            r.append(c.decode('ascii'))
        return ''.join(r)

    def uleb128(self) -> int:
        # Algorithm to decode an unsigned LEB128 number from DWARF standard:
        # result = 0;
        # shift = 0;
        # while(true)
        # {
        #     byte = next byte in input;
        #     result |= (low order 7 bits of byte << shift);
        #     if (high order bit of byte == 0)
        #         break;
        #     shift += 7;
        # }

        result = 0
        shift = 0
        while True:
            byte = self.__stream.read(1)[0]
            result |= ((byte & 0x7f) << shift)
            if byte & 0x80 == 0:
                return result
            shift += 7

    def sleb128(self) -> int:
        # Algorithm to decode a signed LEB128 number from DWARF standard:
        # result = 0;
        # shift = 0;
        # size = number of bits in signed integer;
        # while(true)
        # {
        #   byte = next byte in input;
        #   result |= (low order 7 bits of byte << shift);
        #   shift += 7;
        #   /* sign bit of byte is second high order bit (0x40) */
        #   if (high order bit of byte == 0)
        #       break;
        # }
        # if ((shift <size) && (sign bit of byte is set))
        #   /* sign extend */
        #   result |= - (1 << shift);
        result = 0
        shift = 0
        # size = ...
        while True:
            byte = self.__stream.read(1)[0]
            result |= ((byte & 0x7f) << shift)
            shift += 7
            if byte & 0x80 == 0:
                break
        if byte & 0x40:
            result |= - (1 << shift)
        return result

    def block(self) -> builtins.bytes:
        """Read DW_FORM_block: uleb128 length followed by bytes."""
        return self.bytes(self.uleb128())

    @property
    def current_position(self) -> int:
        """Return current position in the stream."""
        return self.__stream.tell()

    def set_abs_position(self, pos: int, alignment: int = 1) -> int:
        """Change stream position to a specified position with given alignment."""
        p = align_up(pos, alignment)
        self.__stream.seek(p)
        return p

    @property
    def at_eof(self) -> bool:
        result = (len(self.bytes(1)) == 0)
        self.__stream.seek(-1, SEEK_CUR)
        return result

    @property
    def data_format(self) -> DataFormat:
        return self.__df


class TargetFormatter:
    """A class to combine data format and architecture information for printing."""

    def __init__(
        self,
        arch: ElfMachineType,
        data_format: DataFormat,
    ) -> None:
        self.__df = data_format
        self.__dw_regs = _dwarf_register_names.get(arch, {})

    def get_dwarf_regname(self, regnum: int) -> str:
        """Get a DWARF register name for the given register name."""
        if regnum in self.__dw_regs:
            return self.__dw_regs.get(regnum, '')
        else:
            return 'r' + str(regnum)

    def get_full_regname(self, regnum: int) -> str:
        """Get a full name of the register: number and DWARF name.

        For example, for RAX on amd64 returns `r0 (rax)` and `r52` for some
        unknown register number 52."""
        if regnum in self.__dw_regs:
            return f'r{regnum} ({self.get_dwarf_regname(regnum)})'
        else:
            return 'r' + str(regnum)

    @property
    def data_format(self) -> DataFormat:
        return self.__df

    @property
    def pointer_format(self) -> str:
        """Return a format string for pointers in this architecture."""
        return self.__df.bits.address_format

    @property
    def pointer_char_width(self) -> int:
        return self.__df.bits.address_string_width


class CfaInstructionCode(Enum):
    operand_types: Sequence[type]

    def __new__(cls, value: int, operand_types: Sequence[type] = tuple()):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.operand_types = operand_types
        return obj

    DW_CFA_advance_loc = 0xFF01
    DW_CFA_offset = (0xFF02, (StreamReader.uleb128,))
    DW_CFA_restore = 0xFF03
    DW_CFA_nop = 0x00
    DW_CFA_set_loc = (0x01, (StreamReader.pointer,))
    DW_CFA_advance_loc1 = (0x02, (StreamReader.uint1,))
    DW_CFA_advance_loc2 = (0x03, (StreamReader.uint2,))
    DW_CFA_advance_loc4 = (0x04, (StreamReader.uint4,))
    DW_CFA_offset_extended = (0x05, (StreamReader.uleb128, StreamReader.uleb128))
    DW_CFA_restore_extended = (0x06, (StreamReader.uleb128,))
    DW_CFA_undefined = (0x07, (StreamReader.uleb128,))
    DW_CFA_same_value = (0x08, (StreamReader.uleb128,))
    DW_CFA_register = (0x09, (StreamReader.uleb128, StreamReader.uleb128))
    DW_CFA_remember_state = 0x0A
    DW_CFA_restore_state = 0x0B
    DW_CFA_def_cfa = (0x0C, (StreamReader.uleb128, StreamReader.uleb128))
    DW_CFA_def_cfa_register = (0x0D, (StreamReader.uleb128,))
    DW_CFA_def_cfa_offset = (0x0E, (StreamReader.uleb128,))
    DW_CFA_def_cfa_expression = (0x0F, (StreamReader.block,))
    DW_CFA_expression = (0x10, (StreamReader.uleb128, StreamReader.block))
    DW_CFA_offset_extended_sf = (0x11, (StreamReader.uleb128, StreamReader.sleb128))
    DW_CFA_def_cfa_sf = (0x12, (StreamReader.uleb128, StreamReader.sleb128))
    DW_CFA_def_cfa_offset_sf = (0x13, (StreamReader.sleb128,))
    DW_CFA_val_offset = (0x14, (StreamReader.uleb128, StreamReader.uleb128))
    DW_CFA_val_offset_sf = (0x15, (StreamReader.uleb128, StreamReader.sleb128))
    DW_CFA_val_expression = (0x16, (StreamReader.uleb128, StreamReader.block))


class CfaInstruction(NamedTuple):
    """A class to represent call frame instruction with operands."""
    instruction: CfaInstructionCode
    operands: tuple

    @staticmethod
    def read(sr: StreamReader) -> Iterator['CfaInstruction']:
        """Read a sequence of CFA instructions from a stream reader until reader's end."""
        while not sr.at_eof:
            b = sr.uint1()
            # Argument is inside of opcode
            match b >> 6:
                case 0:
                    # 'Normal' instructions.
                    instr = CfaInstructionCode(b & 0x3F)
                    op_values = tuple(operand_type(sr) for operand_type in instr.operand_types)
                    match instr:
                        case CfaInstructionCode.DW_CFA_def_cfa_expression:
                            expr = tuple(ExpressionOperation.read(StreamReader(sr.data_format, BytesIO(op_values[0]))))
                            yield CfaInstruction(instr, (expr, ))
                        case CfaInstructionCode.DW_CFA_expression | CfaInstructionCode.DW_CFA_val_expression:
                            expr = tuple(ExpressionOperation.read(StreamReader(sr.data_format, BytesIO(op_values[1]))))
                            yield CfaInstruction(instr, (op_values[0], expr))
                        case _:
                            yield CfaInstruction(instr, op_values)
                case 1:
                    yield CfaInstruction(CfaInstructionCode.DW_CFA_advance_loc, (b & 0x3F,))
                case 2:
                    yield CfaInstruction(CfaInstructionCode.DW_CFA_offset, (b & 0x3F, sr.uleb128()))
                case 3:
                    yield CfaInstruction(CfaInstructionCode.DW_CFA_restore, (b & 0x3F,))
                case _:
                    raise NotImplementedError('Unsupported call frame instruction.')

    def objdump_format(
            self,
            fmt: TargetFormatter,
            cie: 'CieRecord',
            frame_pc: int,
    ) -> str:
        """Format instruction in the style of objdump.

        :params args: Instruction operands."""
        # That is not a good function and needs a redesign pass.
        caf = cie.code_alignment_factor
        daf = cie.data_alignment_factor

        name = self.instruction.name
        args = self.operands
        match self.instruction:
            case CfaInstructionCode.DW_CFA_set_loc:
                return f'{name}: {args[0]:016x}'
            case (CfaInstructionCode.DW_CFA_advance_loc |
                  CfaInstructionCode.DW_CFA_advance_loc1 |
                  CfaInstructionCode.DW_CFA_advance_loc2 |
                  CfaInstructionCode.DW_CFA_advance_loc4):
                return f'{name}: {args[0] * caf} to {frame_pc:{fmt.pointer_format}}'

            case CfaInstructionCode.DW_CFA_def_cfa:
                return f'{name}: {fmt.get_full_regname(args[0])} ofs {args[1]}'
            case CfaInstructionCode.DW_CFA_def_cfa_sf:
                return f'{name}: {fmt.get_full_regname(args[0])} ofs {args[1] * daf}'
            case CfaInstructionCode.DW_CFA_def_cfa_register:
                return f'{name}: {fmt.get_full_regname(args[0])}'
            case CfaInstructionCode.DW_CFA_def_cfa_offset:
                return f'{name}: {args[0]}'
            case CfaInstructionCode.DW_CFA_def_cfa_offset_sf:
                return f'{name}: {args[0] * daf}'
            case CfaInstructionCode.DW_CFA_def_cfa_expression:
                expr_str = ExpressionOperation.objdump_format_seq(fmt, args[0])
                return f'{name} ({expr_str})'

            case (CfaInstructionCode.DW_CFA_undefined |
                  CfaInstructionCode.DW_CFA_same_value):
                return f'{name}: {fmt.get_full_regname(args[0])}'

            case (CfaInstructionCode.DW_CFA_offset |
                  CfaInstructionCode.DW_CFA_offset_extended |
                  CfaInstructionCode.DW_CFA_offset_extended_sf):
                return f'{name}: {fmt.get_full_regname(args[0])} at cfa{args[1] * daf:+}'

            case (CfaInstructionCode.DW_CFA_val_offset |
                  CfaInstructionCode.DW_CFA_val_offset_sf):
                return f'{name}: {fmt.get_full_regname(args[0])} at cfa{args[1] * daf:+}'

            case CfaInstructionCode.DW_CFA_register:
                return f'{name}: {fmt.get_full_regname(args[0])} in {fmt.get_full_regname(args[1])}'

            case CfaInstructionCode.DW_CFA_expression:
                expr_str = ExpressionOperation.objdump_format_seq(fmt, args[1])
                return f'{name}: {fmt.get_full_regname(args[0])} ({expr_str})'
            case CfaInstructionCode.DW_CFA_val_expression:
                expr_str = ExpressionOperation.objdump_format_seq(fmt, args[1])
                return f'{name}: {fmt.get_full_regname(args[0])} ({expr_str})'

            case (CfaInstructionCode.DW_CFA_restore |
                  CfaInstructionCode.DW_CFA_restore_extended):
                return f'{name}: {fmt.get_full_regname(args[0])}'

            case (CfaInstructionCode.DW_CFA_remember_state |
                  CfaInstructionCode.DW_CFA_restore_state |
                  CfaInstructionCode.DW_CFA_nop |
                  _):
                return name


class ExpressionOperationCode(Enum):
    """A class to represent DWARF expression operations.

    Contains operation code and argument types (if any).

    See ``ExpressionData`` for type that combines operation with operand values."""
    operand_types: Sequence[type]

    def __new__(cls, value: int, operand_types: Sequence[type] = tuple()):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.operand_types = operand_types
        return obj

    DW_OP_addr = (0x03, (StreamReader.pointer, ))
    DW_OP_deref = 0x06
    DW_OP_const1u = (0x08, (StreamReader.uint1, ))
    DW_OP_const1s = (0x09, (StreamReader.sint1, ))
    DW_OP_const2u = (0x0a, (StreamReader.uint2, ))
    DW_OP_const2s = (0x0b, (StreamReader.sint2, ))
    DW_OP_const4u = (0x0c, (StreamReader.uint4, ))
    DW_OP_const4s = (0x0d, (StreamReader.sint4, ))
    DW_OP_const8u = (0x0e, (StreamReader.uint8, ))
    DW_OP_const8s = (0x0f, (StreamReader.sint8, ))
    DW_OP_constu = (0x10, (StreamReader.uleb128, ))
    DW_OP_consts = (0x11, (StreamReader.sleb128, ))
    DW_OP_dup = 0x12
    DW_OP_drop = 0x13
    DW_OP_over = 0x14
    DW_OP_pick = (0x15, (StreamReader.uint1, ))
    DW_OP_swap = 0x16
    DW_OP_rot = 0x17
    DW_OP_xderef = 0x18
    DW_OP_abs = 0x19
    DW_OP_and = 0x1a
    DW_OP_div = 0x1b
    DW_OP_minus = 0x1c
    DW_OP_mod = 0x1d
    DW_OP_mul = 0x1e
    DW_OP_neg = 0x1f
    DW_OP_not = 0x20
    DW_OP_or = 0x21
    DW_OP_plus = 0x22
    DW_OP_plus_uconst = (0x23, (StreamReader.uleb128, ))
    DW_OP_shl = 0x24
    DW_OP_shr = 0x25
    DW_OP_shra = 0x26
    DW_OP_xor = 0x27
    DW_OP_skip = (0x2f, (StreamReader.sint2, ))
    DW_OP_bra = (0x28, (StreamReader.sint2, ))
    DW_OP_eq = 0x29
    DW_OP_ge = 0x2a
    DW_OP_gt = 0x2b
    DW_OP_le = 0x2c
    DW_OP_lt = 0x2d
    DW_OP_ne = 0x2e
    DW_OP_lit0 = 0x30
    DW_OP_lit1 = 0x31
    DW_OP_lit2 = 0x32
    DW_OP_lit3 = 0x33
    DW_OP_lit4 = 0x34
    DW_OP_lit5 = 0x35
    DW_OP_lit6 = 0x36
    DW_OP_lit7 = 0x37
    DW_OP_lit8 = 0x38
    DW_OP_lit9 = 0x39
    DW_OP_lit10 = 0x3a
    DW_OP_lit11 = 0x3b
    DW_OP_lit12 = 0x3c
    DW_OP_lit13 = 0x3d
    DW_OP_lit14 = 0x3e
    DW_OP_lit15 = 0x3f
    DW_OP_lit16 = 0x40
    DW_OP_lit17 = 0x41
    DW_OP_lit18 = 0x41
    DW_OP_lit19 = 0x42
    DW_OP_lit20 = 0x43
    DW_OP_lit21 = 0x44
    DW_OP_lit22 = 0x45
    DW_OP_lit23 = 0x46
    DW_OP_lit24 = 0x47
    DW_OP_lit25 = 0x48
    DW_OP_lit26 = 0x49
    DW_OP_lit27 = 0x4a
    DW_OP_lit28 = 0x4b
    DW_OP_lit29 = 0x4c
    DW_OP_lit30 = 0x4d
    DW_OP_lit31 = 0x4e
    DW_OP_lit32 = 0x4f
    DW_OP_reg0 = 0x50
    DW_OP_reg1 = 0x51
    DW_OP_reg2 = 0x52
    DW_OP_reg3 = 0x53
    DW_OP_reg4 = 0x54
    DW_OP_reg5 = 0x55
    DW_OP_reg6 = 0x56
    DW_OP_reg7 = 0x57
    DW_OP_reg8 = 0x58
    DW_OP_reg9 = 0x59
    DW_OP_reg10 = 0x5a
    DW_OP_reg11 = 0x5b
    DW_OP_reg12 = 0x5c
    DW_OP_reg13 = 0x5d
    DW_OP_reg14 = 0x5e
    DW_OP_reg15 = 0x5f
    DW_OP_reg16 = 0x60
    DW_OP_reg17 = 0x61
    DW_OP_reg18 = 0x61
    DW_OP_reg19 = 0x62
    DW_OP_reg20 = 0x63
    DW_OP_reg21 = 0x64
    DW_OP_reg22 = 0x65
    DW_OP_reg23 = 0x66
    DW_OP_reg24 = 0x67
    DW_OP_reg25 = 0x68
    DW_OP_reg26 = 0x69
    DW_OP_reg27 = 0x6a
    DW_OP_reg28 = 0x6b
    DW_OP_reg29 = 0x6c
    DW_OP_reg30 = 0x6d
    DW_OP_reg31 = 0x6e
    DW_OP_reg32 = 0x6f
    DW_OP_breg0 = (0x70, (StreamReader.sleb128, ))
    DW_OP_breg1 = (0x71, (StreamReader.sleb128, ))
    DW_OP_breg2 = (0x72, (StreamReader.sleb128, ))
    DW_OP_breg3 = (0x73, (StreamReader.sleb128, ))
    DW_OP_breg4 = (0x74, (StreamReader.sleb128, ))
    DW_OP_breg5 = (0x75, (StreamReader.sleb128, ))
    DW_OP_breg6 = (0x76, (StreamReader.sleb128, ))
    DW_OP_breg7 = (0x77, (StreamReader.sleb128, ))
    DW_OP_breg8 = (0x78, (StreamReader.sleb128, ))
    DW_OP_breg9 = (0x79, (StreamReader.sleb128, ))
    DW_OP_breg10 = (0x7a, (StreamReader.sleb128, ))
    DW_OP_breg11 = (0x7b, (StreamReader.sleb128, ))
    DW_OP_breg12 = (0x7c, (StreamReader.sleb128, ))
    DW_OP_breg13 = (0x7d, (StreamReader.sleb128, ))
    DW_OP_breg14 = (0x7e, (StreamReader.sleb128, ))
    DW_OP_breg15 = (0x7f, (StreamReader.sleb128, ))
    DW_OP_breg16 = (0x80, (StreamReader.sleb128, ))
    DW_OP_breg17 = (0x81, (StreamReader.sleb128, ))
    DW_OP_breg18 = (0x81, (StreamReader.sleb128, ))
    DW_OP_breg19 = (0x82, (StreamReader.sleb128, ))
    DW_OP_breg20 = (0x83, (StreamReader.sleb128, ))
    DW_OP_breg21 = (0x84, (StreamReader.sleb128, ))
    DW_OP_breg22 = (0x85, (StreamReader.sleb128, ))
    DW_OP_breg23 = (0x86, (StreamReader.sleb128, ))
    DW_OP_breg24 = (0x87, (StreamReader.sleb128, ))
    DW_OP_breg25 = (0x88, (StreamReader.sleb128, ))
    DW_OP_breg26 = (0x89, (StreamReader.sleb128, ))
    DW_OP_breg27 = (0x8a, (StreamReader.sleb128, ))
    DW_OP_breg28 = (0x8b, (StreamReader.sleb128, ))
    DW_OP_breg29 = (0x8c, (StreamReader.sleb128, ))
    DW_OP_breg30 = (0x8d, (StreamReader.sleb128, ))
    DW_OP_breg31 = (0x8e, (StreamReader.sleb128, ))
    DW_OP_breg32 = (0x8f, (StreamReader.sleb128, ))
    DW_OP_regx = (0x90, (StreamReader.uleb128, ))
    DW_OP_fbreg = (0x91, (StreamReader.sleb128, ))
    DW_OP_bregx = (0x92, (StreamReader.uleb128, StreamReader.sleb128))
    DW_OP_piece = (0x93, (StreamReader.uleb128, ))
    DW_OP_deref_size = (0x94, (StreamReader.uint1, ))
    DW_OP_xderef_size = (0x95, (StreamReader.uint1, ))
    DW_OP_nop = 0x96
    DW_OP_push_object_address = 0x97
    DW_OP_call2 = (0x98, (StreamReader.uint2, ))
    DW_OP_call4 = (0x99, (StreamReader.uint4, ))
    DW_OP_call_ref = (0x9a, (StreamReader.pointer, ))
    DW_OP_form_tls_address = 0x9b
    DW_OP_call_frame_cfa = 0x9c
    DW_OP_bit_piece = (0x9d, (StreamReader.uleb128, StreamReader.uleb128))
    DW_OP_implicit_value = (0x9e, (StreamReader.block, ))
    DW_OP_stack_value = 0x9f


class ExpressionOperation(NamedTuple):
    """A class to represent DWARF expression operation and operand values."""
    operation: ExpressionOperationCode
    operands: tuple

    @staticmethod
    def read(sr: StreamReader) -> Iterable['ExpressionOperation']:
        while not sr.at_eof:
            code = sr.uint1()
            op = ExpressionOperationCode(code)
            operand_values = tuple(operand_type(sr) for operand_type in op.operand_types)
            yield ExpressionOperation(op, operand_values)

    def objdump_format(
        self,
        fmt: TargetFormatter,
    ) -> str:
        """Format operation in the style of objdump.

        :params args: Operation operands."""
        def rn(regnum: int) -> str:
            dwname = fmt.get_dwarf_regname(regnum)
            if dwname:
                return f'reg{regnum} ({dwname})'
            return f'reg{regnum}'

        if ExpressionOperationCode.DW_OP_reg0.value < self.operation.value < ExpressionOperationCode.DW_OP_reg31.value:
            regnum = self.operation.value - 0x50
            return f'DW_OP_{rn(regnum)}'
        elif (ExpressionOperationCode.DW_OP_breg0.value < self.operation.value
              < ExpressionOperationCode.DW_OP_breg31.value):
            regnum = self.operation.value - 0x70
            return f'DW_OP_b{rn(regnum)}: {self.operands[0]}'
        elif ExpressionOperationCode.DW_OP_implicit_value == self:
            return f'{self.operation.name}: {self.operands[0].hex()}'
        operands_str = operands_str = ': ' + ' '.join(self.operands) if len(self.operands) > 0 else ''
        return self.operation.name + operands_str

    @staticmethod
    def objdump_format_seq(
        fmt: TargetFormatter,
        operations: Iterable['ExpressionOperation'],
    ) -> str:
        return '; '.join(op.objdump_format(fmt) for op in operations)


class DW_EH_PE_ValueType(Enum):
    absptr = 0  # Size is determined by the architecture.
    uleb128 = 1
    udata2 = 2
    udata4 = 3
    udata8 = 4
    sleb128 = 9
    sdata2 = 0xA
    sdata4 = 0xB
    sdata8 = 0xC

    def read_value(self, sr: StreamReader) -> int:
        # Why this function is in this class instead of in StreamReader itself?
        # I think this logic is too peculiar to this class and it doesn't make
        # sense to split it between enum definition and StreamReader.
        match self:
            case DW_EH_PE_ValueType.absptr:
                return sr.pointer()
            case DW_EH_PE_ValueType.uleb128:
                return sr.uleb128()
            case DW_EH_PE_ValueType.udata2:
                return sr.uint2()
            case DW_EH_PE_ValueType.udata4:
                return sr.uint4()
            case DW_EH_PE_ValueType.udata8:
                return sr.uint8()
            case DW_EH_PE_ValueType.sleb128:
                return sr.sleb128()
            case DW_EH_PE_ValueType.sdata2:
                return sr.sint2()
            case DW_EH_PE_ValueType.sdata4:
                return sr.sint4()
            case DW_EH_PE_ValueType.sdata8:
                return sr.uint8()
        raise ValueError(f'Unsupported DW_EH_PE value type: `{self.value}`.')


class DW_EH_PE_Relation(Enum):
    pcrel = 1
    "Value is relative to the current program counter."
    textrel = 2
    "Value is relative to the beginning of the .text section."
    datarel = 3
    "Value is relative to the beginning of the .got or .eh_frame_hdr section."
    funcrel = 4
    "Value is relative to the beginning of the function."
    aligned = 5
    "Value is aligned to an address unit sized boundary."

    # It might make sense to extract "indirect" as a separate bitfield, but it
    # will make code somewhat more complex, and it is not clear if this makes
    # sense in this parser, at least for now.
    indirect_pcrel = 0x9
    indirect_textrel = 0xA
    indirect_datarel = 0xB
    indirect_funcrel = 0xC
    indirect_aligned = 0xD


@dataclasses.dataclass(frozen=True)
class CieAugmentation:
    """Container for CIE augmentation data allowed in .eh_frame."""
    lsda_pointer_encoding: DW_EH_PE_ValueType | None = None
    lsda_pointer_adjust: DW_EH_PE_Relation | None = None
    personality_routine_pointer: int | None = None
    personality_routine_adjust: DW_EH_PE_Relation | None = None
    fde_pointer_encoding: DW_EH_PE_ValueType | None = None
    fde_pointer_adjust: DW_EH_PE_Relation | None = None

    @staticmethod
    def read(
        augmentation: str,
        data: bytes,
        offset: int,
        data_format: DataFormat,
    ) -> 'CieAugmentation':
        """Parse augmentation information from a byte stream.

        :param augmentation: the augmentation string that describes content of
            the buffer.
        :param data: the byte buffer with raw augmentation data.
        :param offset: the initial offset of the augmentation data in the
            original stream. Needed because augmentation data may contain data
            that is PC-relative, i.e. relative to the position of the data.
        :param data_format: the data format of the byte buffer."""
        sr = StreamReader(data_format, BytesIO(data))

        # Parse augmentation data.
        lsda_encoding: DW_EH_PE_ValueType | None = None
        lsda_adjust: DW_EH_PE_Relation | None = None
        pers_pointer: int | None = None
        pers_adjust: DW_EH_PE_Relation | None = None
        fde_pointer_encoding: DW_EH_PE_ValueType | None = None
        fde_pointer_adjust: DW_EH_PE_Relation | None = None
        for augmentatation_char in augmentation:
            match augmentatation_char:
                case 'z':
                    pass
                case 'L':
                    b = sr.uint1()
                    lsda_encoding = DW_EH_PE_ValueType(b & 0xF)
                    lsda_adjust = DW_EH_PE_Relation(b >> 4)
                case 'P':
                    b = sr.uint1()
                    pers_encoding = DW_EH_PE_ValueType(b & 0xF)
                    pers_adjust = DW_EH_PE_Relation(b >> 4)
                    pers_offset = sr.current_position
                    pers_pointer = pers_encoding.read_value(sr)
                    if pers_adjust == DW_EH_PE_Relation.pcrel:
                        pers_pointer = offset + pers_offset + pers_pointer
                case 'R':
                    b = sr.uint1()
                    fde_pointer_encoding = DW_EH_PE_ValueType(b & 0xF)
                    fde_pointer_adjust = DW_EH_PE_Relation(b >> 4)
        return CieAugmentation(
            lsda_pointer_encoding=lsda_encoding,
            lsda_pointer_adjust=lsda_adjust,
            personality_routine_pointer=pers_pointer,
            personality_routine_adjust=pers_adjust,
            fde_pointer_encoding=fde_pointer_encoding,
            fde_pointer_adjust=fde_pointer_adjust,
        )


@dataclasses.dataclass(frozen=True)
class CieRecord:
    offset: int
    size: int
    version: int
    augmentation: str
    code_alignment_factor: int
    data_alignment_factor: int
    return_address_register: int
    initial_instructions: bytes
    augmentation_data: bytes = b''
    augmentation_info: CieAugmentation = CieAugmentation()

    @staticmethod
    def read(sr: StreamReader) -> Optional['CieRecord']:
        # Note that this implements Linux .eh_frame structure, which is
        # slightly different from .debug_frame.
        offset = sr.current_position

        length = sr.uint4()
        if length == 0:
            # Null terminator CIE.
            # Reset cursor, so offset of the null record can be evaluated.
            sr.set_abs_position(offset)
            return None
        if length == 0xffffffff:
            # Read extended length.
            length = sr.uint8()

        # Needed to read initial instructions field. Length fields are not
        # included in the length count.
        cie_start = sr.current_position
        cie_id = sr.uint4()
        assert cie_id == 0, "CIE record has non-zero ID field."

        version = sr.uint1()
        assert version == 1, "CIE record version is not 1."

        augmentation_str = sr.cstring()
        caf = sr.uleb128()
        daf = sr.sleb128()
        ra = sr.uleb128()

        if 'z' in augmentation_str:
            augmentation_sz = sr.uleb128()
            augmentation_offset = sr.current_position
            augmentation_data = sr.bytes(augmentation_sz)
            cie_augmentation = CieAugmentation.read(
                augmentation_str,
                augmentation_data,
                augmentation_offset,
                sr.data_format,
            )
        else:
            augmentation_data = b''
            cie_augmentation = CieAugmentation()

        # Length of initial instructions field is defined as size of CIE minus
        # already read bytes.
        bytes_read = sr.current_position - cie_start
        init_instr = sr.bytes(length - bytes_read)

        return CieRecord(
            offset,
            length,
            version,
            augmentation_str,
            caf,
            daf,
            ra,
            init_instr,
            augmentation_data,
            cie_augmentation,
        )


@dataclasses.dataclass(frozen=True)
class FdeRecord:
    offset: int
    size: int
    cie_ptr: int
    cie: CieRecord
    pc_begin_offset: int
    "Offset of pc_begin field in the stream."
    pc_begin: int
    pc_range: int
    # The pc_begin_offset field is needed to handle the DW_EH_PE_pcrel
    # augmentations, since the value there is relative to the location of
    # pc_begin field itself. Alternative solution would be to pass Elf object
    # into the `read` function so it could fully resolve the pc_begin to an
    # effective address, but that seems like an overcomplication, since it
    # creates a new dependency on elf module.
    augmentation_data: bytes
    instructions: bytes

    @staticmethod
    def read(
        sr: StreamReader,
        cie_records: Mapping[int, CieRecord],
    ) -> Iterator['FdeRecord']:
        """Read FDE records from the stream.

        :param sr: stream reader.
        :param cie_records: Mapping of section offsets to CIE records."""
        # Note that this implements Linux .eh_frame structure, which is
        # slightly different from .debug_frame.
        fde_start = sr.set_abs_position(sr.current_position)

        # Length 0 means a null terminator FDE.
        while (length := sr.uint4()) != 0:
            if length == 0xffffffff:
                # Read extended length.
                length = sr.uint8()

            id_offset = sr.current_position
            cie_ptr = sr.uint4()

            if cie_ptr == 0:
                # This is actually the next CIE, stop iterating.
                break

            assert cie_ptr != 0, "FDE record has a zero CIE pointer field."
            cie_abs_position = sr.current_position - 4 - cie_ptr
            cie = cie_records[cie_abs_position]
            assert cie_abs_position == cie.offset
            # FDE always follows it's CIE so we don't have to try to search for
            # CIE using the CIE pointer - we already have CIE.

            pc_begin_offset = sr.current_position
            # The following condition might (?) actually be false, but this
            # code assumes that `R` augmentation is always present.
            assert cie.augmentation_info.fde_pointer_encoding is not None
            pc_begin = cie.augmentation_info.fde_pointer_encoding.read_value(sr)
            pc_range = cie.augmentation_info.fde_pointer_encoding.read_value(sr)

            augmentation_sz = 0
            augmentation_data = b''
            if 'z' in cie.augmentation:
                augmentation_sz = sr.uleb128()
                if augmentation_sz > 0:
                    augmentation_data = sr.bytes(augmentation_sz)

            # Remember that length doesn't count the `length` fields, hence
            # substract id_offset, instead of fde_start.
            bytes_read = sr.current_position - id_offset
            instr = sr.bytes(length - bytes_read)

            yield FdeRecord(
                fde_start,
                length,
                cie_ptr,
                cie,
                pc_begin_offset,
                pc_begin,
                pc_range,
                augmentation_data,
                instr,
            )

            fde_start = sr.set_abs_position(id_offset + length)
        # The loop can stop on two conditions:
        # 1. Loop encountered the next CIE with a zero cie_ptr
        # 2. Loop encountered the zero terminator.
        # Loop terminator here is treated as a special type of CIE (similar to
        # how it is treated in the spec), so either way this function restores
        # cursor position to the before length field, so then the higher-order
        # loop can safely read the CIE, whether it is a real CIE or null
        # terminator.
        sr.set_abs_position(fde_start)

    def abs_pc_begin(self, section_address: int = 0) -> int:
        """Evaluate real absolute value of PC begin based on augmentation.

        :param section_address: An address of the .eh_frame section in the memory."""
        # Meaning of pc_begin depends on CIE augmentation, but for now only one
        # type of adjust is supported.
        assert self.cie.augmentation_info.fde_pointer_adjust == DW_EH_PE_Relation.pcrel, \
            'This type of DW_EH_PE relation is not supported.'
        return section_address + self.pc_begin_offset + self.pc_begin


def read_eh_frame(sr: StreamReader) -> Iterator[CieRecord | FdeRecord]:
    """Read an .eh_frame section as a sequence of CIE and FDE records.

    :param sr: The stream reader for the .eh_frame section."""
    # Mapping of offsets to CIE records. Needed because FDE records can
    # reference any of the previous CIE records.
    cie_records: dict[int, CieRecord] = {}
    while cie := CieRecord.read(sr):
        cie_records[cie.offset] = cie
        yield cie
        yield from FdeRecord.read(sr, cie_records)


_dwarf_register_names = {
    ElfMachineType.EM_X86_64: {
        0: 'rax',
        1: 'rdx',
        2: 'rcx',
        3: 'rbx',
        4: 'rsi',
        5: 'rdi',
        6: 'rbp',
        7: 'rsp',
        **{i: f'r{i}' for i in range(8, 16)},  # r8-r15, 8-15
        16: 'rip',
        **{(17 + i): f'xmm{i}' for i in range(16)},  # xmm0-xmm15, 17-32
    },
    ElfMachineType.EM_386: {
        0: 'eax',
        1: 'ecx',
        2: 'edx',
        3: 'ebx',
        4: 'esp',
        5: 'ebp',
        6: 'esi',
        7: 'edi',
        8: 'eip',
        9: 'eflags',
        **{(11 + i): f'st{i}' for i in range(8)},  # st0 - st7, 11 - 18
        **{(21 + i): f'xmm{i}' for i in range(8)},  # xmm0 - xmm7, 21 - 28
        **{(29 + i): f'mm{i}' for i in range(8)},  # mm0 - mm7, 29 - 36
        37: 'fcw',
        38: 'fsw',
        39: 'mxcsr',
        40: 'es',
        41: 'cs',
        42: 'ss',
        43: 'ds',
        44: 'fs',
        45: 'gs',
        48: 'tr',
        49: 'ldtr',
        **{(93 + i): f'k{i}' for i in range(8)},  # k0 - k7, 93 - 100
    },
}


@dataclasses.dataclass(frozen=True)
class CfaDefinition:
    """A class to represent a CFA definition for the frame's row."""
    reg: int
    offset: int
    _: dataclasses.KW_ONLY
    # Either expression is present or reg+offset.
    # Expression is the collection of tuples, where first item is the
    # expression operation and second is the tuple of operation arguments.
    expression: Sequence[ExpressionOperation] = dataclasses.field(default_factory=tuple)


@dataclasses.dataclass(frozen=True)
class RegisterRule:
    """A class to represent a single register rule in the frame's unwind table."""
    instruction: CfaInstructionCode = CfaInstructionCode.DW_CFA_undefined

    _: dataclasses.KW_ONLY
    reg: int = 0
    offset: int = 0
    expression: Sequence[ExpressionOperation] = dataclasses.field(default_factory=tuple)

    def objdump_format(self, fmt: TargetFormatter) -> str:
        """Print this register rule as a table cell in style of objdump."""
        match self.instruction:
            case CfaInstructionCode.DW_CFA_undefined:
                return 'u'
            case CfaInstructionCode.DW_CFA_same_value:
                return 's'
            case CfaInstructionCode.DW_CFA_expression:
                return 'exp'
            case CfaInstructionCode.DW_CFA_register:
                return fmt.get_full_regname(self.reg)
            case (CfaInstructionCode.DW_CFA_val_offset |
                  CfaInstructionCode.DW_CFA_val_offset_sf |
                  CfaInstructionCode.DW_CFA_val_expression |
                  CfaInstructionCode.DW_CFA_restore |
                  CfaInstructionCode.DW_CFA_restore_extended):
                raise NotImplementedError()
            case _:
                return f'c{self.offset:+}'


@dataclasses.dataclass(frozen=True)
class CallFrameTableRow:
    # Each row is identified by a PC value as a unique key (aka LOC).
    # Each row has a defined CFA value.
    # Each row has at least one register definition.
    loc: int

    # CFA could be: reg+offset (most often) or an expression.
    # For now we don't support the latter.
    cfa: CfaDefinition = CfaDefinition(0, 0)

    register_rules: MutableMapping[int, RegisterRule] = dataclasses.field(default_factory=dict)


class CallFrameTable(collections.abc.Iterable[CallFrameTableRow]):
    __initial: CallFrameTableRow
    "Initial register rules defined by CIE initial instructions."
    __rows: list[CallFrameTableRow]
    __state_stack: list[CallFrameTableRow]
    __cie: CieRecord

    def __init__(self, cie: CieRecord) -> None:
        self.__initial = CallFrameTableRow(0)
        self.__rows = list()
        self.__state_stack = list()
        self.__cie = cie

    def do_instruction(self, *instructions: CfaInstruction) -> None:
        """Execute specified instructions on the call frame table."""
        for instr in instructions:
            if instr.instruction == CfaInstructionCode.DW_CFA_nop:
                continue

            current_row = self.__rows[-1] if len(self.__rows) else self.__initial
            next_row = self.__next_row(current_row, instr)
            if next_row.loc != current_row.loc or len(self.__rows) == 0:
                self.__rows.append(next_row)
            else:
                self.__rows[-1] = next_row

    def __next_row(
        self,
        current_row: CallFrameTableRow,
        instr: CfaInstruction,
    ) -> 'CallFrameTableRow':
        args = instr.operands
        match instr.instruction:
            # Location Instructions.
            case CfaInstructionCode.DW_CFA_set_loc:
                return dataclasses.replace(current_row, loc=args[0])
            case (CfaInstructionCode.DW_CFA_advance_loc |
                  CfaInstructionCode.DW_CFA_advance_loc1 |
                  CfaInstructionCode.DW_CFA_advance_loc2 |
                  CfaInstructionCode.DW_CFA_advance_loc4):
                new_loc = current_row.loc + args[0] * self.__cie.code_alignment_factor
                return dataclasses.replace(current_row, loc=new_loc)

            # CFA Definition Instructions.
            case CfaInstructionCode.DW_CFA_def_cfa:
                return dataclasses.replace(current_row, cfa=CfaDefinition(args[0], args[1]))
            case CfaInstructionCode.DW_CFA_def_cfa_sf:
                cfa = CfaDefinition(args[0], args[1] * self.__cie.data_alignment_factor)
                return dataclasses.replace(current_row, cfa=cfa)
            case CfaInstructionCode.DW_CFA_def_cfa_register:
                cfa = dataclasses.replace(current_row.cfa, reg=args[0])
                return dataclasses.replace(current_row, cfa=cfa)
            case CfaInstructionCode.DW_CFA_def_cfa_offset:
                cfa = dataclasses.replace(current_row.cfa, offset=args[0])
                return dataclasses.replace(current_row, cfa=cfa)
            case CfaInstructionCode.DW_CFA_def_cfa_offset_sf:
                cfa = dataclasses.replace(current_row.cfa, offset=args[0] * self.__cie.data_alignment_factor)
                return dataclasses.replace(current_row, cfa=cfa)
            case CfaInstructionCode.DW_CFA_def_cfa_expression:
                cfa = CfaDefinition(0, 0, expression=args[0])
                return dataclasses.replace(current_row, cfa=cfa)

            # Register_rules
            case CfaInstructionCode.DW_CFA_undefined:
                return self.__set_rule(current_row, args[0], RegisterRule())
            case (CfaInstructionCode.DW_CFA_offset |
                  CfaInstructionCode.DW_CFA_offset_extended |
                  CfaInstructionCode.DW_CFA_offset_extended_sf):
                return self.__set_rule(
                    current_row,
                    args[0],
                    RegisterRule(instr.instruction, offset=args[1] * self.__cie.data_alignment_factor)
                )
            case CfaInstructionCode.DW_CFA_register:
                return self.__set_rule(current_row, args[0], RegisterRule(instr.instruction, reg=args[1]))
            case (CfaInstructionCode.DW_CFA_val_offset |
                  CfaInstructionCode.DW_CFA_val_offset_sf):
                raise NotImplementedError(str(instr))
            case CfaInstructionCode.DW_CFA_expression:
                return self.__set_rule(current_row, args[0], RegisterRule(instr.instruction, expression=args[1]))
            case (CfaInstructionCode.DW_CFA_restore |
                  CfaInstructionCode.DW_CFA_restore_extended):
                return self.__set_rule(
                    current_row,
                    args[0],
                    self.__initial.register_rules.get(args[0], RegisterRule()),
                )

            case CfaInstructionCode.DW_CFA_remember_state:
                self.__state_stack.append(current_row)
                return current_row

            case CfaInstructionCode.DW_CFA_restore_state:
                stored_row = self.__state_stack.pop()
                new_rules = ChainMap(stored_row.register_rules).new_child()
                return dataclasses.replace(current_row, cfa=stored_row.cfa, register_rules=new_rules)

            case CfaInstructionCode.DW_CFA_nop | _:
                return current_row

    def __set_rule(
        self,
        current_row: CallFrameTableRow,
        regnum: int,
        register_rule: RegisterRule,
    ) -> CallFrameTableRow:
        """Add a new register rule to the row.

        The row itself is not modified - a modified copy is returned."""
        new_rules = ChainMap(current_row.register_rules).new_child()
        new_rules[regnum] = register_rule
        # Original implementation assumed that if register has a rule defined in
        # CIE, then the is always active at the start of the FDE table. However
        # the behaviour should be different - if FDE describes any rule for the
        # register then the initial rule is not applicable at all.
        #
        # I don't fully understand why it is so, and where in the specification
        # this is required - I've discovered this by comparing outputs with
        # objdump. This behaviour doesn't make a lot of sense to me, because it
        # above else also means that to properly build a table the parse should
        # read the table completely, since the register rule can be defined at any
        # moment in the middle of the FDE entry. It also creates weird tables,
        # like this:
        #
        # 00000018 00000010 0000001c FDE cie=00000000 pc=00001090..000010ca
        # LOC   CFA        ra
        # 00001090 esp+4    u
        # 00001094 esp+4    u
        #
        # So there are two lines, but they are identical, so it looks strange.
        # Nevertheless I will stick to the objdump behavior because I compare
        # parse_elf's output with it, and also the default assumption would be
        # that binutils developers are more likely to be correct than not.
        if regnum in self.__initial.register_rules.keys():
            del self.__initial.register_rules[regnum]
        return dataclasses.replace(current_row, register_rules=new_rules)

    def __iter__(self) -> Iterator[CallFrameTableRow]:
        if len(self.__rows) and self.__initial.loc != self.__rows[0].loc:
            yield self.__initial
        yield from self.__rows

    def mentioned_registers(self) -> Sequence[int]:
        result: set[int] = set()
        for row in self.__rows:
            result.update(row.register_rules.keys())
        return tuple(sorted(result))

    def current_loc(self) -> int:
        """Return current location of the last row or 0 if there are no rows.

        This is a function instead of property, because it's value changes over
        time (note that this design rule isn't applied very consistently in this
        code)."""
        if len(self.__rows):
            return self.__rows[-1].loc
        else:
            return 0

    def objdump_print(self, fmt: TargetFormatter, stream: TextIO) -> None:
        """Print this table to the provided stream."""
        # Don't print anything if there are no rows.
        if len(self.__rows) == 0:
            return

        def rn(regnum: int) -> str:
            if regnum == self.__cie.return_address_register:
                return 'ra'
            return fmt.get_dwarf_regname(regnum)

        regs = self.mentioned_registers()
        regnames = (format(rn(r), '5') for r in regs)
        print(f'{"   LOC  ":{fmt.pointer_char_width}} CFA      {" ".join(regnames)} ', file=stream)

        for row in self:
            if len(row.cfa.expression):
                cfa = 'exp'
            else:
                cfa = f'{rn(row.cfa.reg)}{row.cfa.offset:+}'

            rules_str = []
            for regnum in regs:
                rule = row.register_rules.get(regnum, RegisterRule())
                rules_str.append(f'{rule.objdump_format(fmt):5}')
            print(f'{row.loc:{fmt.pointer_format}} {cfa:8} {" ".join(rules_str)} ', file=stream)

    def copy(self, offset: int) -> 'CallFrameTable':
        """Create a new table that uses current as initial.

        This function makes sense to create individual frame tables based on
        FDE, assuming that self is a table created from CIE initial
        instructions. The ruleset of the current table will become initial
        ruleset of the new table, and the new table's frames offset will be set
        to the value specified in arguments."""
        r = CallFrameTable(self.__cie)
        if len(self.__rows):
            r.__initial = CallFrameTableRow(
                loc=offset,
                cfa=self.__rows[-1].cfa,
                register_rules=dict[int, RegisterRule](self.__rows[-1].register_rules),
            )
        else:
            r.__initial = CallFrameTableRow(loc=offset)
        return r


#
# .debug_line support
#
class LineNumberConst:
    """A container for line number constants."""
    DW_LNS_copy = 1
    DW_LNS_advance_pc = 2
    DW_LNS_advance_line = 3
    DW_LNS_set_file = 4
    DW_LNS_set_column = 5
    DW_LNS_negate_stm = 6
    DW_LNS_set_basic_block = 7
    DW_LNS_const_add_pc = 8
    DW_LNS_fixed_advance_pc = 9
    DW_LNS_set_prologue_end = 10
    DW_LNS_set_epilogue_begin = 11
    DW_LNS_set_isa = 12

    DW_LNE_end_sequence = 1
    DW_LNE_set_address = 2
    DW_LNE_define_file = 3


@dataclasses.dataclass(frozen=True)
class FileNameEntry:
    name: str
    directory_index: int
    modification_time: int
    file_size: int

    @staticmethod
    def read(sr: StreamReader) -> Iterator['FileNameEntry']:
        while not sr.at_eof:
            name = sr.cstring()
            if len(name) == 0:
                return  # Null entry
            dir_index = sr.uleb128()
            mtime = sr.uleb128()
            file_sz = sr.uleb128()
            yield FileNameEntry(name, dir_index, mtime, file_sz)


@dataclasses.dataclass(frozen=True)
class LineNumberStatement:
    offset: int
    opcode: int
    operands: Sequence[int]


@dataclasses.dataclass(frozen=True)
class LineNumberProgram:
    """Representation of line number programs in .debug_line section."""
    offset: int
    length: int
    version: int
    header_length: int
    minimum_instruction_length: int
    default_is_stmt: int
    line_base: int
    line_range: int
    opcode_base: int
    standard_opcode_operands: Sequence[int]
    """Specifies the number of LEB128 operands for each of the standard opcodes."""
    include_directories: Sequence[str]
    include_directories_offset: int
    files: Sequence[FileNameEntry]
    file_table_offset: int
    statements: Sequence[LineNumberStatement]

    @staticmethod
    def read(sr: StreamReader) -> Iterator['LineNumberProgram']:
        while not sr.at_eof:
            offset = sr.current_position
            length = sr.uint4()
            if length == 0xffffffff:
                # Read extended length.
                length = sr.uint8()
                is_dwarf32 = False
            else:
                is_dwarf32 = True
                assert length < 0xfffffff0  # Reserved values.

            version = sr.uint2()
            assert version == 3, "Only DWARF v3 .debug_line is supported."

            header_length = sr.uint4() if is_dwarf32 else sr.uint8()
            minimum_instruction_length = sr.uint1()
            default_is_stmt = sr.uint1()
            line_base = sr.sint1()
            line_range = sr.uint1()
            opcode_base = sr.uint1()
            opcode_operands = tuple(sr.uint1() for v in range(1, opcode_base))

            include_dirs_offset = sr.current_position
            include_dirs = []
            while dir := sr.cstring():
                include_dirs.append(dir)

            file_table_offset = sr.current_position
            file_table = tuple(FileNameEntry.read(sr))

            statements: list[LineNumberStatement] = []
            while sr.current_position < offset + 4 + length:
                stmt_offset = sr.current_position
                opcode = sr.uint1()
                operands: list[int] = []
                if opcode == 0:
                    # Extended opcode.
                    instr_sz = sr.uleb128()
                    # Handle known xopcodes.
                    xopcode = sr.uint1()
                    operands.append(xopcode)
                    match xopcode:
                        case LineNumberConst.DW_LNE_end_sequence:
                            pass  # No arguments.
                        case LineNumberConst.DW_LNE_set_address:
                            operands.append(sr.pointer())
                        case LineNumberConst.DW_LNE_define_file:
                            operands.append(next(FileNameEntry.read(sr)))
                        case _:
                            # Read remaining bytes, minus xopcode
                            operands.append(sr.bytes(instr_sz - 1))
                elif opcode < opcode_base:
                    # Standard opcodes.
                    if opcode == LineNumberConst.DW_LNS_fixed_advance_pc:
                        operands.append(sr.uint2())  # Special case opcode.
                    else:
                        for x in range(opcode_operands[opcode-1]):
                            operands.append(sr.uleb128())
                statements.append(LineNumberStatement(
                    stmt_offset,
                    opcode,
                    operands,
                ))

            # Ensure that cursor is at the next entry no matter what.
            sr.set_abs_position(offset + 4 + length)
            yield LineNumberProgram(
                offset,
                length,
                version,
                header_length,
                minimum_instruction_length,
                default_is_stmt,
                line_base,
                line_range,
                opcode_base,
                opcode_operands,
                include_dirs,
                include_dirs_offset,
                file_table,
                file_table_offset,
                statements,
            )


@dataclasses.dataclass(frozen=True)
class LineNumberStateRow:
    """Represents a single row in line number table."""
    address: int
    file: int
    line: int
    column: int
    is_stmt: bool
    basic_block: bool
    end_sequence: bool
    prologue_end: bool
    epilogue_begins: bool
    isa: int


class LineNumberStateMachine:
    address: int
    file: int
    line: int
    column: int
    is_stmt: bool
    basic_block: bool
    end_sequence: bool
    prologue_end: bool
    epilogue_begins: bool
    isa: int
    file_names: Sequence[FileNameEntry]

    def __init__(self, header: LineNumberProgram) -> None:
        self.__header = header
        self.__rows: list[LineNumberStateRow] = list()
        self.file_names = list(header.files)
        self.__reset()

    @final
    def __reset(self) -> None:
        # This function is called from the constructor, therefore shall not be
        # overriden.
        self.address = 0
        self.file = 1
        self.line = 1
        self.column = 0
        self.is_stmt = bool(self.__header.default_is_stmt)
        self.basic_block = False
        self.end_sequence = False
        self.prologue_end = False
        self.epilogue_begins = False
        self.isa = 0

    def __special_opcode_address_delta(self, adjusted_opcode: int) -> int:
        """Evaluate address delta for the special opcode.

        :param adjusted_opcode: An already adjusted special opcode."""
        return adjusted_opcode // self.__header.line_range * self.__header.minimum_instruction_length

    def __special_opcode_line_delta(self, adjusted_opcode: int) -> int:
        """Evaluate address delta for the special opcode.

        :param adjusted_opcode: An already adjusted special opcode."""
        return self.__header.line_base + adjusted_opcode % self.__header.line_range

    def do_statement(self, lns: LineNumberStatement) -> str:
        """Execute a statement and return textual description of the instruction.

        Returned description is needed to generate rawline output."""
        # Extended opcode?
        if lns.opcode == 0:
            match lns.operands[0]:
                case LineNumberConst.DW_LNE_end_sequence:
                    self.end_sequence = True
                    self.__append_row()
                    self.__reset()
                    return f'Extended opcode {lns.operands[0]}: End of Sequence'
                case LineNumberConst.DW_LNE_set_address:
                    self.address = lns.operands[1]
                    return f'Extended opcode {lns.operands[0]}: set Address to {lns.operands[1]:#x}'
                case LineNumberConst.DW_LNE_define_file:
                    self.file_names.append(lns.operands[1])
                    return (
                        f'Extended opcode {lns.operands[0]}: define new File Table entry\n'
                        '  Entry\tDir\tTime\tSize\tName)\n'
                        '\t'.join((
                            f'  {len(self.file_names) - 1}',
                            str(lns.operands[1].directory_index),
                            str(lns.operands[1].modification_time),
                            str(lns.operands[1].file_size),
                            lns.operands[1].name,
                        ))
                    )
                case _:
                    raise NotImplementedError(f'Extended opcode {lns.operands[0]}')

        # Special opcode?
        if lns.opcode >= self.__header.opcode_base:
            special_opcode = lns.opcode - self.__header.opcode_base
            addr_delta = self.__special_opcode_address_delta(special_opcode)
            self.address += addr_delta
            line_delta = self.__special_opcode_line_delta(special_opcode)
            self.line += line_delta
            self.__append_row()
            self.basic_block = False
            self.prologue_end = False
            self.epilogue_begins = False
            return (
                f'Special opcode {special_opcode}: '
                f'advance Address by {addr_delta} to {self.address:#x} '
                f'and Line by {line_delta} to {self.line}'
            )

        # Standard opcode?
        match lns.opcode:
            case LineNumberConst.DW_LNS_copy:
                self.__append_row()
                self.basic_block = self.prologue_end = self.epilogue_begins = False
                return 'Copy'
            case LineNumberConst.DW_LNS_advance_pc:
                addr_delta = lns.operands[0] * self.__header.minimum_instruction_length
                self.address += addr_delta
                return f'Advance PC by {addr_delta} to {self.address:#x}'
            case LineNumberConst.DW_LNS_advance_line:
                self.line += lns.operands[0]
                return f'Advance Line by {lns.operands[0]} to {self.line}'
            case LineNumberConst.DW_LNS_set_file:
                self.file = lns.operands[0]
                return f'Set File Name to entry {lns.operands[0]} in the File Name Table'
            case LineNumberConst.DW_LNS_set_column:
                self.column = lns.operands[0]
                return f'Set column to {lns.operands[0]}'
            case LineNumberConst.DW_LNS_negate_stm:
                self.is_stmt = not self.is_stmt
                return f'Set is_stmt to {self.is_stmt:d}'
            case LineNumberConst.DW_LNS_set_basic_block:
                self.basic_block = True
                return 'Set basic block'
            case LineNumberConst.DW_LNS_const_add_pc:
                # It is not abundantly clear from the spec if opcode 255 is an
                # adjusted opcode value or not. I assume it is not adjusted,
                # hence it is adjusted in th the __special_opcode_address_delta.
                addr_delta = self.__special_opcode_address_delta(255 - self.__header.opcode_base) \
                    * self.__header.minimum_instruction_length
                self.address += addr_delta
                return f'Advance PC by constant {addr_delta} to {self.address:#x}'
            case LineNumberConst.DW_LNS_fixed_advance_pc:
                self.address += lns.operands[0]
                return f'Advance PC by fixed size amount {lns.operands[0]} to {self.address:#x}'
            case LineNumberConst.DW_LNS_set_prologue_end:
                self.prologue_end = True
                return 'Set prologue_end to true'
            case LineNumberConst.DW_LNS_set_epilogue_begin:
                self.epilogue_begins = True
                return 'Set epilogue_begin to true'
            case LineNumberConst.DW_LNS_set_isa:
                self.isa = lns.operands[0]
                return f'Set ISA to {self.isa}'
            case _:
                operands = self.__header.standard_opcode_operands[lns.opcode]
                return f'Unknown opcode {lns.opcode} with operands:' + ', '.join(format(op, '#x') for op in operands)

    def __append_row(self) -> None:
        """Append a new row to the table based on current state of registers."""
        self.__rows.append(LineNumberStateRow(
            self.address,
            self.file,
            self.line,
            self.column,
            self.is_stmt,
            self.basic_block,
            self.end_sequence,
            self.prologue_end,
            self.epilogue_begins,
            self.isa,
        ))

    @property
    def rows(self) -> Sequence[LineNumberStateRow]:
        return self.__rows
