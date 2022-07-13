# Copyright (c) 2022 Anton Kolesov
# SPDX-License-Identifier: MIT

"""Classes specific to parsing of DWARF."""

__all__ = [
    'StreamReader',
    'TargetFormatter',
    'CfaInstructionEncoding',
    'CfaInstruction',
    'ExpressionOperationEncoding',
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
    'LineNumberEncoding',
    'AttributeTypeEncoding',
    'LanguageEncoding',
    'TagEncoding',
    'AttributeEncoding',
    'FormEncoding',
    'FileNameEntry',
    'LineNumberStatement',
    'LineNumberProgram',
    'LineNumberStateRow',
    'LineNumberStateMachine',
    'ArangeEntry',
]

import builtins
from collections import ChainMap
import collections.abc
import dataclasses
from enum import Enum
from io import BytesIO, SEEK_CUR
from typing import BinaryIO, final, Iterable, Iterator, \
    MutableMapping, NamedTuple, Sequence, TextIO

from elf import align_up, DataFormat, ElfClass, ElfMachineType


class StreamReader:
    """A class to read DWARF data from the file stream."""

    def __init__(self, data_format: DataFormat, stream: BinaryIO) -> None:
        self.__df = data_format
        self.__stream = stream
        self.__is_dwarf32 = True

    def bytes(self, size: int) -> bytes:
        """Read the specified amount of bytes from the stream."""
        return self.__stream.read(size)

    def uint(self, sz: int) -> int:
        match sz:
            case 1: return self.uint1()
            case 2: return self.uint2()
            case 4: return self.uint4()
            case 8: return self.uint8()
            case _: raise NotImplementedError('Unsupported integer size.')

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
        """Return a pointer value with size depending on the target bitness.

        Note that this function depends on the target bitness, while ``offset``
        depends on the DWARF-bitness, which could be different."""
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

    def block1(self) -> builtins.bytes:
        """Read DW_FORM_block1: 1 byte length followed by bytes."""
        return self.bytes(self.uint1())

    def block2(self) -> builtins.bytes:
        """Read DW_FORM_block2: 2 byte length followed by bytes."""
        return self.bytes(self.uint2())

    def block4(self) -> builtins.bytes:
        """Read DW_FORM_block1: 4 byte length followed by bytes."""
        return self.bytes(self.uint4())

    def length(self) -> int:
        """Read a DWARF length field and set bitness accordingly.

        The length field can be used to dynamically identify if this is the
        32-bit or 64-bit DWARF."""
        length = self.uint4()
        if length == 0xffffffff:
            self.__is_dwarf32 = False
            return self.uint8()
        else:
            self.__is_dwarf32 = True
            assert length < 0xfffffff0  # Reserved values.
            return length

    def offset(self) -> int:
        """Return DWARF offset depending on whether it is 32-bit DWARF or 64-bit.

        Note that unlike ``pointer`` it depends on the DWARF content bitness,
        not on the target bitness."""
        if self.__is_dwarf32:
            return self.uint4()
        else:
            return self.uint8()

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

    @property
    def is_dwarf32(self) -> bool:
        """Return whether the stream is DWARF 32-bit or 64-bit.

        The value can change after reading the ``length()`` field. Streams are
        always considered 32-bit by default, read a ``length()`` field to
        initialize this property correctly."""
        return self.__is_dwarf32


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


#
# .eh_frame
#
class CfaInstructionEncoding(Enum):
    operand_types: Sequence[type]

    def __new__(cls, value: int, operand_types: Sequence[type] = tuple()):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.operand_types = operand_types
        return obj

    DW_CFA_advance_loc = 0x40
    DW_CFA_offset = (0x80, (StreamReader.uleb128,))
    DW_CFA_restore = 0xC0
    DW_CFA_nop = 0x00
    DW_CFA_set_loc = 0x01  # Size of an argument depends on CIE augmentation.
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
    instruction: CfaInstructionEncoding
    operands: tuple

    @staticmethod
    def read_with_augmentation(
        sr: StreamReader,
        augmentation_info: 'CieAugmentation',
        stream_base_address: int,
    ) -> Iterator['CfaInstruction']:
        """Read a sequence of CFA instructions from a stream reader until reader's end.

        :param stream_base_address: The base address of the stream in the memory. This is
            needed to handle PC-relative pointers if specified by augmentation.
            This must be a memory address, not offset in the section of file."""
        while not sr.at_eof:
            b = sr.uint1()
            # Argument is inside of opcode
            match b >> 6:
                case 0:
                    # 'Normal' instructions.
                    instr = CfaInstructionEncoding(b & 0x3F)
                    op_values = tuple(operand_type(sr) for operand_type in instr.operand_types)
                    match instr:
                        case CfaInstructionEncoding.DW_CFA_set_loc:
                            loc = augmentation_info.read_pointer(sr, stream_base_address)
                            yield CfaInstruction(instr, (loc, ))
                        case CfaInstructionEncoding.DW_CFA_def_cfa_expression:
                            expr = tuple(ExpressionOperation.read(StreamReader(sr.data_format, BytesIO(op_values[0]))))
                            yield CfaInstruction(instr, (expr, ))
                        case CfaInstructionEncoding.DW_CFA_expression | CfaInstructionEncoding.DW_CFA_val_expression:
                            expr = tuple(ExpressionOperation.read(StreamReader(sr.data_format, BytesIO(op_values[1]))))
                            yield CfaInstruction(instr, (op_values[0], expr))
                        case _:
                            yield CfaInstruction(instr, op_values)
                case 1:
                    yield CfaInstruction(CfaInstructionEncoding.DW_CFA_advance_loc, (b & 0x3F,))
                case 2:
                    yield CfaInstruction(CfaInstructionEncoding.DW_CFA_offset, (b & 0x3F, sr.uleb128()))
                case 3:
                    yield CfaInstruction(CfaInstructionEncoding.DW_CFA_restore, (b & 0x3F,))
                case _:
                    raise NotImplementedError('Unsupported call frame instruction.')

    @staticmethod
    def read(sr: StreamReader) -> Iterator['CfaInstruction']:
        """Read a sequence of CFA instructions from a stream reader until reader's end.

        This implementation doesn't consider augmentation info."""
        yield from CfaInstruction.read_with_augmentation(sr, CieAugmentation(), 0)

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
            case CfaInstructionEncoding.DW_CFA_set_loc:
                return f'{name}: {args[0]:016x}'
            case (CfaInstructionEncoding.DW_CFA_advance_loc |
                  CfaInstructionEncoding.DW_CFA_advance_loc1 |
                  CfaInstructionEncoding.DW_CFA_advance_loc2 |
                  CfaInstructionEncoding.DW_CFA_advance_loc4):
                return f'{name}: {args[0] * caf} to {frame_pc:{fmt.pointer_format}}'

            case CfaInstructionEncoding.DW_CFA_def_cfa:
                return f'{name}: {fmt.get_full_regname(args[0])} ofs {args[1]}'
            case CfaInstructionEncoding.DW_CFA_def_cfa_sf:
                return f'{name}: {fmt.get_full_regname(args[0])} ofs {args[1] * daf}'
            case CfaInstructionEncoding.DW_CFA_def_cfa_register:
                return f'{name}: {fmt.get_full_regname(args[0])}'
            case CfaInstructionEncoding.DW_CFA_def_cfa_offset:
                return f'{name}: {args[0]}'
            case CfaInstructionEncoding.DW_CFA_def_cfa_offset_sf:
                return f'{name}: {args[0] * daf}'
            case CfaInstructionEncoding.DW_CFA_def_cfa_expression:
                expr_str = ExpressionOperation.objdump_format_seq(fmt, args[0])
                return f'{name} ({expr_str})'

            case (CfaInstructionEncoding.DW_CFA_undefined |
                  CfaInstructionEncoding.DW_CFA_same_value):
                return f'{name}: {fmt.get_full_regname(args[0])}'

            case (CfaInstructionEncoding.DW_CFA_offset |
                  CfaInstructionEncoding.DW_CFA_offset_extended |
                  CfaInstructionEncoding.DW_CFA_offset_extended_sf):
                return f'{name}: {fmt.get_full_regname(args[0])} at cfa{args[1] * daf:+}'

            case (CfaInstructionEncoding.DW_CFA_val_offset |
                  CfaInstructionEncoding.DW_CFA_val_offset_sf):
                return f'{name}: {fmt.get_full_regname(args[0])} is cfa{args[1] * daf:+}'

            case CfaInstructionEncoding.DW_CFA_register:
                return f'{name}: {fmt.get_full_regname(args[0])} in {fmt.get_full_regname(args[1])}'

            case CfaInstructionEncoding.DW_CFA_expression:
                expr_str = ExpressionOperation.objdump_format_seq(fmt, args[1])
                return f'{name}: {fmt.get_full_regname(args[0])} ({expr_str})'
            case CfaInstructionEncoding.DW_CFA_val_expression:
                expr_str = ExpressionOperation.objdump_format_seq(fmt, args[1])
                return f'{name}: {fmt.get_full_regname(args[0])} ({expr_str})'

            case (CfaInstructionEncoding.DW_CFA_restore |
                  CfaInstructionEncoding.DW_CFA_restore_extended):
                return f'{name}: {fmt.get_full_regname(args[0])}'

            case (CfaInstructionEncoding.DW_CFA_remember_state |
                  CfaInstructionEncoding.DW_CFA_restore_state |
                  CfaInstructionEncoding.DW_CFA_nop |
                  _):
                return name


class ExpressionOperationEncoding(Enum):
    """A class to represent DWARF expression operations.

    Contains operation code and argument types (if any).

    See ``ExpressionData`` for type that combines operation with operand values."""
    operand_types: Sequence[type]

    def __new__(cls, value: int, operand_types: Sequence[type] = tuple()):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.operand_types = operand_types
        return obj

    # This function must be defined before it is used in static field declaration.
    @staticmethod
    def read_from_block(sr: StreamReader) -> Sequence['ExpressionOperation']:
        """Read a DWARF block from the stream and then parse expression in the block.

        This function returns sequence only because the function is called on
        only one place and that place will have much simpler code if doesn't
        have to convert iterable to sequence itself."""
        buffer = BytesIO(sr.block())
        expression_reader = StreamReader(sr.data_format, buffer)
        return tuple(ExpressionOperation.read(expression_reader))

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
    DW_OP_lit18 = 0x42
    DW_OP_lit19 = 0x43
    DW_OP_lit20 = 0x44
    DW_OP_lit21 = 0x45
    DW_OP_lit22 = 0x46
    DW_OP_lit23 = 0x47
    DW_OP_lit24 = 0x48
    DW_OP_lit25 = 0x49
    DW_OP_lit26 = 0x4a
    DW_OP_lit27 = 0x4b
    DW_OP_lit28 = 0x4c
    DW_OP_lit29 = 0x4d
    DW_OP_lit30 = 0x4e
    DW_OP_lit31 = 0x4f
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
    DW_OP_reg18 = 0x62
    DW_OP_reg19 = 0x63
    DW_OP_reg20 = 0x64
    DW_OP_reg21 = 0x65
    DW_OP_reg22 = 0x66
    DW_OP_reg23 = 0x67
    DW_OP_reg24 = 0x68
    DW_OP_reg25 = 0x69
    DW_OP_reg26 = 0x6a
    DW_OP_reg27 = 0x6b
    DW_OP_reg28 = 0x6c
    DW_OP_reg29 = 0x6d
    DW_OP_reg30 = 0x6e
    DW_OP_reg31 = 0x6f
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
    DW_OP_breg18 = (0x82, (StreamReader.sleb128, ))
    DW_OP_breg19 = (0x83, (StreamReader.sleb128, ))
    DW_OP_breg20 = (0x84, (StreamReader.sleb128, ))
    DW_OP_breg21 = (0x85, (StreamReader.sleb128, ))
    DW_OP_breg22 = (0x86, (StreamReader.sleb128, ))
    DW_OP_breg23 = (0x87, (StreamReader.sleb128, ))
    DW_OP_breg24 = (0x88, (StreamReader.sleb128, ))
    DW_OP_breg25 = (0x89, (StreamReader.sleb128, ))
    DW_OP_breg26 = (0x8a, (StreamReader.sleb128, ))
    DW_OP_breg27 = (0x8b, (StreamReader.sleb128, ))
    DW_OP_breg28 = (0x8c, (StreamReader.sleb128, ))
    DW_OP_breg29 = (0x8d, (StreamReader.sleb128, ))
    DW_OP_breg30 = (0x8e, (StreamReader.sleb128, ))
    DW_OP_breg31 = (0x8f, (StreamReader.sleb128, ))
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
    DW_OP_call_ref = (0x9a, (StreamReader.offset, ))
    DW_OP_form_tls_address = 0x9b
    DW_OP_call_frame_cfa = 0x9c
    DW_OP_bit_piece = (0x9d, (StreamReader.uleb128, StreamReader.uleb128))
    DW_OP_implicit_value = (0x9e, (StreamReader.block, ))
    DW_OP_stack_value = 0x9f
    # DWARF 5
    DW_OP_implicit_pointer = (0xa0, (StreamReader.offset, StreamReader.sleb128))
    DW_OP_addrx = (0xa1, (StreamReader.uleb128, ))
    DW_OP_constx = (0xa2, (StreamReader.uleb128, ))
    # DW_OP_entry_value has two operands: ULEB size and block of that size.
    DW_OP_entry_value = (0xa3, (read_from_block, ))
    # DW_OP_const_type has two operands: 1-byte size and block of that size.
    DW_OP_const_type = (0xa4, (StreamReader.uleb128, StreamReader.block1))
    DW_OP_regval_type = (0xa5, (StreamReader.uleb128, StreamReader.uleb128))
    DW_OP_deref_type = (0xa6, (StreamReader.uint1, StreamReader.uleb128))
    DW_OP_xderef_type = (0xa7, (StreamReader.uint1, StreamReader.uleb128))
    DW_OP_convert = (0xa8, (StreamReader.uleb128, ))
    DW_OP_reinterpret = (0xa9, (StreamReader.uleb128, ))


class ExpressionOperation(NamedTuple):
    """A class to represent DWARF expression operation and operand values."""
    operation: ExpressionOperationEncoding
    operands: tuple

    @staticmethod
    def read(sr: StreamReader) -> Iterable['ExpressionOperation']:
        while not sr.at_eof:
            code = sr.uint1()
            op = ExpressionOperationEncoding(code)
            operand_values = tuple(operand_type(sr) for operand_type in op.operand_types)
            yield ExpressionOperation(op, operand_values)

    def objdump_format(
        self,
        fmt: TargetFormatter,
    ) -> str:
        """Format operation in the style of objdump.

        :params args: Operation operands."""
        def rn(regnum: int) -> str:
            return f'{regnum} ({fmt.get_dwarf_regname(regnum)})'

        if (ExpressionOperationEncoding.DW_OP_reg0.value <= self.operation.value
           and self.operation.value <= ExpressionOperationEncoding.DW_OP_reg31.value):
            regnum = self.operation.value - 0x50
            return f'DW_OP_reg{rn(regnum)}'
        elif (ExpressionOperationEncoding.DW_OP_breg0.value <= self.operation.value
              <= ExpressionOperationEncoding.DW_OP_breg31.value):
            regnum = self.operation.value - 0x70
            return f'DW_OP_breg{rn(regnum)}: {self.operands[0]}'

        match self.operation:
            case ExpressionOperationEncoding.DW_OP_addr:
                return f'{self.operation.name}: {self.operands[0]:x}'
            # For some reasons binutils prints const8 as two 4 byte words.
            # Also lower word comes first.
            case ExpressionOperationEncoding.DW_OP_const8u:
                return f'{self.operation.name}: {self.operands[0] & 0xffffffff} {self.operands[0] >> 32}'
            case ExpressionOperationEncoding.DW_OP_const8s:
                upper_word = self.operands[0] >> 32
                lower_word = self.operands[0] & 0xffffffff
                if (lower_word >> 31) & 1:
                    lower_word = -(0x100000000 - lower_word)
                return f'{self.operation.name}: {lower_word} {upper_word}'
            case ExpressionOperationEncoding.DW_OP_regx:
                return f'{self.operation.name}: {rn(self.operands[0])}'
            case ExpressionOperationEncoding.DW_OP_bregx:
                return f'{self.operation.name}: {rn(self.operands[0])} {self.operands[1]}'
            case (ExpressionOperationEncoding.DW_OP_call2 |
                  ExpressionOperationEncoding.DW_OP_call4):
                # Operands for 'call' are unsigned (see DWARFv5 2.5.1.5), yet
                # binutils treats them as signed. That seems like a mistake on
                # binutils side, so I don't do the same here, but also I don't
                # include "negative" values in tests.
                return f'{self.operation.name}: <{self.operands[0]:#x}>'
            case (ExpressionOperationEncoding.DW_OP_call_ref |
                  ExpressionOperationEncoding.DW_OP_implicit_pointer):
                # Apparantly binutils doesn't support this.
                return f'({self.operation.name} in frame info)'
            case ExpressionOperationEncoding.DW_OP_bit_piece:
                return f'{self.operation.name}: size: {self.operands[0]} offset: {self.operands[1]} '
            case ExpressionOperationEncoding.DW_OP_implicit_value:
                byte_data = self.operands[0].hex(sep=" ", bytes_per_sep=1)
                return f'{self.operation.name} {len(self.operands[0])} byte block: {byte_data} '
            case (ExpressionOperationEncoding.DW_OP_addrx |
                  ExpressionOperationEncoding.DW_OP_convert |
                  ExpressionOperationEncoding.DW_OP_reinterpret):
                return f'{self.operation.name} <{self.operands[0]:#x}>'
            case ExpressionOperationEncoding.DW_OP_entry_value:
                subexpression = ExpressionOperation.objdump_format_seq(fmt, self.operands[0])
                return f'{self.operation.name}: ({subexpression})'
            case (ExpressionOperationEncoding.DW_OP_const_type):
                byte_data = self.operands[1].hex(sep=" ", bytes_per_sep=1)
                return (f'{self.operation.name}: <{self.operands[0]:#x}>  '
                        f'{len(self.operands[1])} byte block: {byte_data} ')
            case (ExpressionOperationEncoding.DW_OP_regval_type):
                return f'{self.operation.name}: {rn(self.operands[0])} <{self.operands[1]:#x}>'
            case (ExpressionOperationEncoding.DW_OP_deref_type):
                return f'{self.operation.name}: {self.operands[0]} <{self.operands[1]:#x}>'

        operands_str = operands_str = ': ' + ' '.join(str(x) for x in self.operands) if len(self.operands) > 0 else ''
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
    lsda_pointer_encoding: DW_EH_PE_ValueType = DW_EH_PE_ValueType.absptr
    lsda_pointer_adjust: DW_EH_PE_Relation | None = None
    personality_routine_pointer: int | None = None
    personality_routine_adjust: DW_EH_PE_Relation | None = None
    fde_pointer_encoding: DW_EH_PE_ValueType = DW_EH_PE_ValueType.absptr
    fde_pointer_adjust: DW_EH_PE_Relation | None = None

    def read_pointer(self, sr: StreamReader, stream_base_address: int) -> int:
        """Read and adjust pointer from the stream.

        :param stream_address: The base address of the stream in the memory."""
        # I think formally this assert is not fully correct - .eh_frame section
        # might be at address 0, but I don't think this will happen in real life.
        assert stream_base_address != 0 or self.fde_pointer_encoding == DW_EH_PE_ValueType.absptr
        offset = sr.current_position
        loc = self.fde_pointer_encoding.read_value(sr)
        if self.fde_pointer_adjust is None:
            return loc
        elif self.fde_pointer_adjust == DW_EH_PE_Relation.pcrel:
            return loc + offset + stream_base_address
        else:
            assert False

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
        lsda_encoding = DW_EH_PE_ValueType.absptr
        lsda_adjust: DW_EH_PE_Relation | None = None
        pers_pointer: int | None = None
        pers_adjust: DW_EH_PE_Relation | None = None
        fde_pointer_encoding = DW_EH_PE_ValueType.absptr
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
    cie_id: int
    version: int
    augmentation: str
    code_alignment_factor: int
    data_alignment_factor: int
    return_address_register: int
    initial_instructions: Sequence[CfaInstruction]
    augmentation_data: bytes = b''
    augmentation_info: CieAugmentation = CieAugmentation()

    @property
    def is_zero_record(self) -> bool:
        return self.size == 0

    @staticmethod
    def read_eh_frame(
        sr: StreamReader,
        entry_offset: int,
        length: int,
        cie_id: int,
        post_length_offset: int,
        eh_frame_offset: int,
    ) -> 'CieRecord':
        """Read an CIE record from the .eh_frame.

        :param sr: The stream reader to read from.
        :param entry_offset: The offset of the CIE beggining.
        :param length: The CIE size without the length field itself.
        :param cie_id: The value of cie_id field as read from the file.
        :param post_length_offset: The offset of the CIE pointer field.
        :param eh_frame_offset: The offset of the .eh_frame section in the file.
            This is needed to handle PC-relative pointers if specified by
            augmentation."""
        # Note that this implements Linux .eh_frame structure, which is
        # slightly different from .debug_frame.
        version = sr.uint1()
        assert version == 1, f'CIE record version should be 1, is {version}.'

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
        init_instr_offset = sr.current_position
        bytes_read = init_instr_offset - post_length_offset
        init_instr = sr.bytes(length - bytes_read)
        init_instr_sr = StreamReader(sr.data_format, BytesIO(init_instr))
        init_instructions = tuple(CfaInstruction.read_with_augmentation(
            init_instr_sr,
            cie_augmentation,
            eh_frame_offset + init_instr_offset,
        ))

        return CieRecord(
            entry_offset,
            length,
            cie_id,
            version,
            augmentation_str,
            caf,
            daf,
            ra,
            init_instructions,
            augmentation_data,
            cie_augmentation,
        )

    @staticmethod
    def read_dwarf(
        sr: StreamReader,
        entry_offset: int,
        length: int,
        cie_id: int,
        post_length_offset: int,
    ) -> 'CieRecord':
        """Read an CIE record from the .debug_frame.

        In theory it would be good to merge dwarf/eh_frame implementation, the
        main problem right now is the best way to handle augmentation and
        information that is needed for them to work, and for no I punt this
        issue into the future - there is an implementation that supports only
        specific augmentations that are needed to test executables built with
        default set of GCC flags, but not the full .eh_frame support. And then
        there is a DWARF version that ignores augmentations and is somewhat
        simpler because of that.

        :param sr: The stream reader to read from.
        :param entry_offset: The offset of the CIE beggining.
        :param length: The CIE size without the length field itself.
        :param cie_id: The value of cie_id field as read from the file.
        :param post_length_offset: The offset of the CIE pointer field."""
        # Note that this implements Linux .debug_frame structure, which is
        # slightly different from .eh_frame.
        version = sr.uint1()
        assert version == 1, f'CIE record version should be 1, is {version}.'

        augmentation_str = sr.cstring()
        # According to spec we should ignore records with unknown augmentations
        # but for now I just abort immediately.
        # `S` means a signal frame and doesn't change record layout.
        assert len(augmentation_str) == 0 or augmentation_str == 'S'
        caf = sr.uleb128()
        daf = sr.sleb128()
        ra = sr.uleb128()

        # Length of initial instructions field is defined as size of CIE minus
        # already read bytes.
        init_instr_offset = sr.current_position
        bytes_read = init_instr_offset - post_length_offset
        init_instr = sr.bytes(length - bytes_read)
        init_instr_sr = StreamReader(sr.data_format, BytesIO(init_instr))
        init_instructions = tuple(CfaInstruction.read(init_instr_sr))

        return CieRecord(
            entry_offset,
            length,
            cie_id,
            version,
            augmentation_str,
            caf,
            daf,
            ra,
            init_instructions,
        )

    @staticmethod
    def zero_record(offset: int) -> 'CieRecord':
        return CieRecord(offset, 0, 0, 0, '', 0, 0, 0, tuple())


@dataclasses.dataclass(frozen=True)
class FdeRecord:
    offset: int
    size: int
    cie_ptr: int
    cie: CieRecord
    pc_begin: int
    pc_range: int
    augmentation_data: bytes
    instructions: Sequence[CfaInstruction]

    @staticmethod
    def read_eh_frame(
        sr: StreamReader,
        cie: CieRecord,
        entry_offset: int,
        length: int,
        post_length_offset: int,
        eh_frame_offset: int,
        cie_ptr: int,
    ) -> 'FdeRecord':
        """Read an FDE record from the .eh_frame.

        :param sr: The stream reader to read from.
        :param cie: Parent CIE record.
        :param entry_offset: The offset of the CIE beggining.
        :param length: The CIE size without the length field itself.
        :param post_length_offset: The offset of the CIE pointer field.
        :param eh_frame_offset: The offset of the .eh_frame section in the file.
            This is needed to handle PC-relative pointers if specified by
            augmentation.
        :param cie_ptr: The value of the CIE pointer field in the file."""
        # The following condition might (?) actually be false, but this
        # code assumes that `R` augmentation is always present.
        assert cie.augmentation_info.fde_pointer_encoding is not None
        pc_begin = cie.augmentation_info.read_pointer(sr, eh_frame_offset)
        pc_range = cie.augmentation_info.fde_pointer_encoding.read_value(sr)

        augmentation_sz = 0
        augmentation_data = b''
        if 'z' in cie.augmentation:
            augmentation_sz = sr.uleb128()
            if augmentation_sz > 0:
                augmentation_data = sr.bytes(augmentation_sz)

        # Remember that length doesn't count the `length` fields, hence
        # substract id_offset, instead of fde_start.
        instr_offset = sr.current_position
        bytes_read = instr_offset - post_length_offset
        instr = sr.bytes(length - bytes_read)
        instr_sr = StreamReader(sr.data_format, BytesIO(instr))
        instructions = tuple(CfaInstruction.read_with_augmentation(
            instr_sr,
            cie.augmentation_info,
            eh_frame_offset + instr_offset,
        ))

        return FdeRecord(
            entry_offset,
            length,
            cie_ptr,
            cie,
            pc_begin,
            pc_range,
            augmentation_data,
            instructions,
        )

    @staticmethod
    def read_dwarf(
        sr: StreamReader,
        cie: CieRecord,
        entry_offset: int,
        length: int,
        post_length_offset: int,
        cie_ptr: int,
    ) -> 'FdeRecord':
        """Read an FDE record from the .debug_frame.

        :param sr: The stream reader to read from.
        :param cie: Parent CIE record.
        :param entry_offset: The offset of the CIE beggining.
        :param length: The CIE size without the length field itself.
        :param post_length_offset: The offset of the CIE pointer field.
        :param cie_ptr: The value of the CIE pointer field in the file."""
        pc_begin = sr.pointer()
        pc_range = sr.pointer()

        # Remember that length doesn't count the `length` fields, hence
        # substract id_offset, instead of fde_start.
        instr_offset = sr.current_position
        bytes_read = instr_offset - post_length_offset
        instr = sr.bytes(length - bytes_read)
        instr_sr = StreamReader(sr.data_format, BytesIO(instr))
        instructions = tuple(CfaInstruction.read(instr_sr))

        return FdeRecord(
            entry_offset,
            length,
            cie_ptr,
            cie,
            pc_begin,
            pc_range,
            b'',  # augmentation_data
            instructions,
        )


def read_eh_frame(
    sr: StreamReader,
    eh_frame_offset: int,
) -> Iterator[CieRecord | FdeRecord]:
    """Read an .eh_frame section as a sequence of CIE and FDE records.

    :param sr: The stream reader for the .eh_frame section.
    :param eh_frame_offset: The offset of the .eh_frame section in the file.
        This is needed to handle PC-relative pointers if specified by
        augmentation."""
    # Mapping of offsets to CIE records. Needed because FDE records can
    # reference any of the previous CIE records.
    cie_records: dict[int, CieRecord] = {}

    # Read length and cie_ptr fields and then call respective reader function:
    # CIEs have a zero-value cie_ptr, while FDEs have a non-zero cie_ptr.
    while not sr.at_eof:
        entry_offset = sr.current_position
        length = sr.length()

        if length == 0:
            # Null terminator CIE.
            yield CieRecord.zero_record(entry_offset)
            continue

        post_length_offset = sr.current_position
        cie_ptr = sr.uint4()

        if cie_ptr == 0:
            cie = CieRecord.read_eh_frame(sr, entry_offset, length, cie_ptr, post_length_offset, eh_frame_offset)
            cie_records[entry_offset] = cie
            yield cie
        else:
            parent_cie = cie_records[post_length_offset - cie_ptr]
            yield FdeRecord.read_eh_frame(
                sr,
                parent_cie,
                entry_offset,
                length,
                post_length_offset,
                eh_frame_offset,
                cie_ptr,
            )
        # Set position just to ensure entry is skipped whether it was properly parsed or not.
        sr.set_abs_position(post_length_offset + length)


def read_dwarf_frame(
    sr: StreamReader,
) -> Iterator[CieRecord | FdeRecord]:
    """Read an .debug_frame section as a sequence of CIE and FDE records.

    .eh_frame is similar to DWARFv2 .debug_frame, but there are substantial
    differences. For example CIE pointer of FDE record in .eh_frame is an offset
    from the FDE record, while in DWARF it is an offset from the beginning of
    the .debug_frame section.

    :param sr: The stream reader for the .eh_frame section."""
    # Mapping of offsets to CIE records. Needed because FDE records can
    # reference any of the previous CIE records.
    cie_records: dict[int, CieRecord] = {}

    # Read length and cie_ptr fields and then call respective reader function:
    # CIEs have a 0xffffffff cie_ptr, while FDEs have a cie_ptr that is an
    # offset into the section. I don't think that specification in any form
    # explicitly specifies that 0xffffffff is a "distinguished" value, rather it
    # seems to me that since .debug_frame always starts with CIE, then the
    # reading algorith should treat the whatever value set in the cie_id field
    # as a distinguished for any further CIE records. But that seems like a
    # complication, at least for this library, so I will consider that just
    # 0xffffffff is a distinguished value, since that is what is used in DWARF
    # specification examples and by GCC.
    while not sr.at_eof:
        entry_offset = sr.current_position
        length = sr.length()

        if length == 0:
            # Null terminator CIE.
            yield CieRecord.zero_record(entry_offset)
            continue

        post_length_offset = sr.current_position
        cie_ptr = sr.offset()

        if cie_ptr == 0xffffffff:
            cie = CieRecord.read_dwarf(sr, entry_offset, length, cie_ptr, post_length_offset)
            cie_records[entry_offset] = cie
            yield cie
        else:
            parent_cie = cie_records[cie_ptr]
            yield FdeRecord.read_dwarf(sr, parent_cie, entry_offset, length, post_length_offset, cie_ptr)
        # Set position just to ensure entry is skipped whether it was properly parsed or not.
        sr.set_abs_position(post_length_offset + length)


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
        **{(33 + i): f'st{i}' for i in range(8)},  # st0 - st7, 33 - 40
        **{(41 + i): f'mm{i}' for i in range(8)},  # mm0 - mm7, 41 - 48
        49: 'rflags',
        50: 'es',
        51: 'cs',
        52: 'ss',
        53: 'ds',
        54: 'fs',
        55: 'gs',
        # 56, 57
        58: 'fs.base',
        59: 'gs.base',
        # 60, 61
        62: 'tr',
        63: 'ldtr',
        64: 'mxcsr',
        65: 'fcw',
        66: 'fsw',
        **{(67 + i): f'xmm{i}' for i in range(16, 32)},  # xmm16-xmm31, 67-82
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
    instruction: CfaInstructionEncoding = CfaInstructionEncoding.DW_CFA_undefined

    _: dataclasses.KW_ONLY
    reg: int = 0
    offset: int = 0
    expression: Sequence[ExpressionOperation] = dataclasses.field(default_factory=tuple)

    def objdump_format(self, fmt: TargetFormatter) -> str:
        """Print this register rule as a table cell in style of objdump."""
        match self.instruction:
            case CfaInstructionEncoding.DW_CFA_undefined:
                return 'u'
            case CfaInstructionEncoding.DW_CFA_same_value:
                return 's'
            case CfaInstructionEncoding.DW_CFA_expression:
                return 'exp'
            case CfaInstructionEncoding.DW_CFA_val_expression:
                return 'vexp'
            case CfaInstructionEncoding.DW_CFA_register:
                return fmt.get_full_regname(self.reg)
            case (CfaInstructionEncoding.DW_CFA_val_offset |
                  CfaInstructionEncoding.DW_CFA_val_offset_sf):
                return f'v{self.offset:+}'
            case (CfaInstructionEncoding.DW_CFA_val_expression |
                  CfaInstructionEncoding.DW_CFA_restore |
                  CfaInstructionEncoding.DW_CFA_restore_extended):
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
            if instr.instruction == CfaInstructionEncoding.DW_CFA_nop:
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
            case CfaInstructionEncoding.DW_CFA_set_loc:
                return dataclasses.replace(current_row, loc=args[0])
            case (CfaInstructionEncoding.DW_CFA_advance_loc |
                  CfaInstructionEncoding.DW_CFA_advance_loc1 |
                  CfaInstructionEncoding.DW_CFA_advance_loc2 |
                  CfaInstructionEncoding.DW_CFA_advance_loc4):
                new_loc = current_row.loc + args[0] * self.__cie.code_alignment_factor
                return dataclasses.replace(current_row, loc=new_loc)

            # CFA Definition Instructions.
            case CfaInstructionEncoding.DW_CFA_def_cfa:
                return dataclasses.replace(current_row, cfa=CfaDefinition(args[0], args[1]))
            case CfaInstructionEncoding.DW_CFA_def_cfa_sf:
                cfa = CfaDefinition(args[0], args[1] * self.__cie.data_alignment_factor)
                return dataclasses.replace(current_row, cfa=cfa)
            case CfaInstructionEncoding.DW_CFA_def_cfa_register:
                cfa = dataclasses.replace(current_row.cfa, reg=args[0])
                return dataclasses.replace(current_row, cfa=cfa)
            case CfaInstructionEncoding.DW_CFA_def_cfa_offset:
                cfa = dataclasses.replace(current_row.cfa, offset=args[0])
                return dataclasses.replace(current_row, cfa=cfa)
            case CfaInstructionEncoding.DW_CFA_def_cfa_offset_sf:
                cfa = dataclasses.replace(current_row.cfa, offset=args[0] * self.__cie.data_alignment_factor)
                return dataclasses.replace(current_row, cfa=cfa)
            case CfaInstructionEncoding.DW_CFA_def_cfa_expression:
                cfa = CfaDefinition(0, 0, expression=args[0])
                return dataclasses.replace(current_row, cfa=cfa)

            # Register_rules
            case CfaInstructionEncoding.DW_CFA_undefined:
                return self.__set_rule(current_row, args[0], RegisterRule())
            case (CfaInstructionEncoding.DW_CFA_offset |
                  CfaInstructionEncoding.DW_CFA_offset_extended |
                  CfaInstructionEncoding.DW_CFA_offset_extended_sf):
                return self.__set_rule(
                    current_row,
                    args[0],
                    RegisterRule(instr.instruction, offset=args[1] * self.__cie.data_alignment_factor)
                )
            case CfaInstructionEncoding.DW_CFA_register:
                return self.__set_rule(current_row, args[0], RegisterRule(instr.instruction, reg=args[1]))
            case (CfaInstructionEncoding.DW_CFA_val_offset |
                  CfaInstructionEncoding.DW_CFA_val_offset_sf):
                return self.__set_rule(
                    current_row,
                    args[0],
                    RegisterRule(instr.instruction, offset=args[1] * self.__cie.data_alignment_factor)
                )
            case CfaInstructionEncoding.DW_CFA_same_value:
                return self.__set_rule(current_row, args[0], RegisterRule(instr.instruction))
            case CfaInstructionEncoding.DW_CFA_expression:
                return self.__set_rule(current_row, args[0], RegisterRule(instr.instruction, expression=args[1]))
            case CfaInstructionEncoding.DW_CFA_val_expression:
                return self.__set_rule(
                    current_row,
                    args[0],
                    RegisterRule(instr.instruction, expression=args[1])
                )
            case (CfaInstructionEncoding.DW_CFA_restore |
                  CfaInstructionEncoding.DW_CFA_restore_extended):
                return self.__set_rule(
                    current_row,
                    args[0],
                    self.__initial.register_rules.get(args[0], RegisterRule()),
                )

            case CfaInstructionEncoding.DW_CFA_remember_state:
                self.__state_stack.append(current_row)
                return current_row

            case CfaInstructionEncoding.DW_CFA_restore_state:
                stored_row = self.__state_stack.pop()
                new_rules = ChainMap(stored_row.register_rules).new_child()
                return dataclasses.replace(current_row, cfa=stored_row.cfa, register_rules=new_rules)

            case CfaInstructionEncoding.DW_CFA_nop | _:
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
        regnames = (format(rn(r), '6') for r in regs)
        print(f'{"   LOC  ":{fmt.pointer_char_width}} CFA      {"".join(regnames)}', file=stream)

        for row in self:
            if len(row.cfa.expression):
                cfa = 'exp'
            else:
                cfa = f'{rn(row.cfa.reg)}{row.cfa.offset:+}'

            rules_str = []
            for regnum in regs:
                rule = row.register_rules.get(regnum, RegisterRule())
                rules_str.append(format(rule.objdump_format(fmt) + ' ', '6'))
            print(f'{row.loc:{fmt.pointer_format}} {cfa:8} {"".join(rules_str)}', file=stream)

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
class LineNumberEncoding:
    """A container for line number opcodes."""
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


class LineNumberExtendedEncoding:
    DW_LNE_end_sequence = 1
    DW_LNE_set_address = 2
    DW_LNE_define_file = 3
    DW_LNE_set_descriminator = 4
    DW_LNE_lo_user = 0x80
    DW_LNE_hi_user = 0xff


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
            length = sr.length()

            ln_offset = sr.current_position
            version = sr.uint2()
            assert version == 3, "Only DWARF v3 .debug_line is supported."

            header_length = sr.offset()
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
                        case LineNumberExtendedEncoding.DW_LNE_end_sequence:
                            pass  # No arguments.
                        case LineNumberExtendedEncoding.DW_LNE_set_address:
                            operands.append(sr.pointer())
                        case LineNumberExtendedEncoding.DW_LNE_define_file:
                            operands.append(next(FileNameEntry.read(sr)))
                        case _:
                            # Read remaining bytes, minus xopcode
                            operands.append(sr.bytes(instr_sz - 1))
                elif opcode < opcode_base:
                    # Standard opcodes.
                    if opcode == LineNumberEncoding.DW_LNS_fixed_advance_pc:
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
            sr.set_abs_position(ln_offset + length)
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
                case LineNumberExtendedEncoding.DW_LNE_end_sequence:
                    self.end_sequence = True
                    # This is somewhat confusing - DWARF specification doesn't
                    # specify that DW_LNE_end_sequence should set `is statement`
                    # to False, however binutils 2.38.50 does that, while 2.34
                    # didn't do that. To enable testing against 2.38.50 I
                    # implement the same logic as it, even though it is not
                    # technically in the specification (perhaps somewhere in the
                    # binutils/dwarf.c there is an explanation, I haven't
                    # checked).
                    self.is_stmt = False
                    self.__append_row()
                    self.__reset()
                    return f'Extended opcode {lns.operands[0]}: End of Sequence'
                case LineNumberExtendedEncoding.DW_LNE_set_address:
                    self.address = lns.operands[1]
                    return f'Extended opcode {lns.operands[0]}: set Address to {lns.operands[1]:#x}'
                case LineNumberExtendedEncoding.DW_LNE_define_file:
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
            case LineNumberEncoding.DW_LNS_copy:
                self.__append_row()
                self.basic_block = self.prologue_end = self.epilogue_begins = False
                return 'Copy'
            case LineNumberEncoding.DW_LNS_advance_pc:
                addr_delta = lns.operands[0] * self.__header.minimum_instruction_length
                self.address += addr_delta
                return f'Advance PC by {addr_delta} to {self.address:#x}'
            case LineNumberEncoding.DW_LNS_advance_line:
                self.line += lns.operands[0]
                return f'Advance Line by {lns.operands[0]} to {self.line}'
            case LineNumberEncoding.DW_LNS_set_file:
                self.file = lns.operands[0]
                return f'Set File Name to entry {lns.operands[0]} in the File Name Table'
            case LineNumberEncoding.DW_LNS_set_column:
                self.column = lns.operands[0]
                return f'Set column to {lns.operands[0]}'
            case LineNumberEncoding.DW_LNS_negate_stm:
                self.is_stmt = not self.is_stmt
                return f'Set is_stmt to {self.is_stmt:d}'
            case LineNumberEncoding.DW_LNS_set_basic_block:
                self.basic_block = True
                return 'Set basic block'
            case LineNumberEncoding.DW_LNS_const_add_pc:
                # It is not abundantly clear from the spec if opcode 255 is an
                # adjusted opcode value or not. I assume it is not adjusted,
                # hence it is adjusted in th the __special_opcode_address_delta.
                addr_delta = self.__special_opcode_address_delta(255 - self.__header.opcode_base) \
                    * self.__header.minimum_instruction_length
                self.address += addr_delta
                return f'Advance PC by constant {addr_delta} to {self.address:#x}'
            case LineNumberEncoding.DW_LNS_fixed_advance_pc:
                self.address += lns.operands[0]
                return f'Advance PC by fixed size amount {lns.operands[0]} to {self.address:#x}'
            case LineNumberEncoding.DW_LNS_set_prologue_end:
                self.prologue_end = True
                return 'Set prologue_end to true'
            case LineNumberEncoding.DW_LNS_set_epilogue_begin:
                self.epilogue_begins = True
                return 'Set epilogue_begin to true'
            case LineNumberEncoding.DW_LNS_set_isa:
                self.isa = lns.operands[0]
                return f'Set ISA to {self.isa}'
            case _:
                operands = self.__header.standard_opcode_operands[lns.opcode]
                return f'Unknown opcode {lns.opcode} with {operands} operands.'

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


#
# .debug_info
#
class AttributeTypeEncoding(Enum):
    human_name: str

    def __new__(cls, value: int, human_name: str = ''):
        assert len(human_name)
        obj = object.__new__(cls)
        obj._value_ = value
        obj.human_name = human_name
        return obj

    DW_ATE_address = (0x01, 'address')
    DW_ATE_boolean = (0x02, 'boolean')
    DW_ATE_complex_float = (0x03, 'complex float')
    DW_ATE_float = (0x04, 'float')
    DW_ATE_signed = (0x05, 'signed')
    DW_ATE_signed_char = (0x06, 'signed char')
    DW_ATE_unsigned = (0x07, 'unsigned')
    DW_ATE_unsigned_char = (0x08, 'unsigned char')
    DW_ATE_imaginary_float = (0x09, 'imaginary float')
    DW_ATE_packed_decimal = (0x0a, 'packed decimal')
    DW_ATE_numeric_string = (0x0b, 'numeric string')
    DW_ATE_edited = (0x0c, 'edited')
    DW_ATE_signed_fixed = (0x0d, 'signed fixed')
    DW_ATE_unsigned_fixed = (0x0e, 'unsigned fixed')
    DW_ATE_decimal_float = (0x0f, 'decimal float')
    DW_ATE_UTF = (0x10, 'unicode string')
    DW_ATE_UCS = (0x11, 'UCS')
    DW_ATE_ASCII = (0x12, 'ASCII')
    DW_ATE_lo_user = (0x80, 'lo_user')
    DW_ATE_hi_user = (0xff, 'hi_user')


class LanguageEncoding(Enum):
    human_name: str

    def __new__(cls, value: int, human_name: str = ''):
        assert len(human_name)
        obj = object.__new__(cls)
        obj._value_ = value
        obj.human_name = human_name
        return obj

    DW_LANG_C89 = (0x0001, 'ANSI C')
    DW_LANG_C = (0x0002, 'non-ANSI C')
    DW_LANG_Ada83 = (0x0003, 'Ada')
    DW_LANG_C_plus_plus = (0x0004, 'C++')
    DW_LANG_Cobol74 = (0x0005, 'Cobol 74')
    DW_LANG_Cobol85 = (0x0006, 'Cobol 85')
    DW_LANG_Fortran77 = (0x0007, 'FORTRAN 77')
    DW_LANG_Fortran90 = (0x0008, 'Fortran 90')
    DW_LANG_Pascal83 = (0x0009, 'ANSI Pascal')
    DW_LANG_Modula2 = (0x000a, 'Modula 2')
    DW_LANG_Java = (0x000b, 'Java')
    DW_LANG_C99 = (0x000c, 'ANSI C99')
    DW_LANG_Ada95 = (0x000d, 'ADA 95')
    DW_LANG_Fortran95 = (0x000e, 'Fortran 95')
    DW_LANG_PLI = (0x000f, 'PLI')
    DW_LANG_ObjC = (0x0010, 'Objective C')
    DW_LANG_ObjC_plus_plus = (0x0011, 'Objective C++')
    DW_LANG_UPC = (0x0012, 'Unified Parallel C')
    DW_LANG_D = (0x0013, 'D')
    DW_LANG_Python = (0x0014, 'Python')
    DW_LANG_OpenCL = (0x0015, 'OpenCL')
    DW_LANG_Go = (0x0016, 'Go')
    DW_LANG_Modula3 = (0x0017, 'Modula 3')
    DW_LANG_Haskell = (0x0018, 'Haskell')
    DW_LANG_C_plus_plus_03 = (0x0019, 'C++03')
    DW_LANG_C_plus_plus_11 = (0x001a, 'C++11')
    DW_LANG_OCaml = (0x001b, 'OCaml')
    DW_LANG_Rust = (0x001c, 'Rust')
    DW_LANG_C11 = (0x001d, 'C11')
    DW_LANG_Swift = (0x001e, 'Swift')
    DW_LANG_Julia = (0x001f, 'Julia')
    DW_LANG_Dylan = (0x0020, 'Dylan')
    DW_LANG_C_plus_plus_14 = (0x0021, 'C++14')
    DW_LANG_Fortran03 = (0x0022, 'Fortran 03')
    DW_LANG_Fortran08 = (0x0023, 'Fortran 08')
    DW_LANG_RenderScript = (0x0024, 'RenderScript')
    DW_LANG_BLISS = (0x0025, 'BLISS')
    DW_LANG_lo_user = (0x8000, 'lo_user')
    DW_LANG_hi_user = (0xffff, 'hi_user')


class TagEncoding(Enum):
    DW_TAG_array_type = 0x01
    DW_TAG_class_type = 0x02
    DW_TAG_entry_point = 0x03
    DW_TAG_enumeration_type = 0x04
    DW_TAG_formal_parameters = 0x05
    DW_TAG_imported_declaration = 0x08
    DW_TAG_label = 0x0a
    DW_TAG_lexical_block = 0x0b
    DW_TAG_member = 0x0d
    DW_TAG_pointer_type = 0x0f
    DW_TAG_reference_type = 0x10
    DW_TAG_compile_unit = 0x11
    DW_TAG_string_type = 0x12
    DW_TAG_structure_type = 0x13
    DW_TAG_subrouting_type = 0x15
    DW_TAG_typedef = 0x16
    DW_TAG_union_type = 0x17
    DW_TAG_unspecified_parameters = 0x18
    DW_TAG_variant = 0x19
    DW_TAG_common_block = 0x1a
    DW_TAG_common_inclusion = 0x1b
    DW_TAG_inheritance = 0x1c
    DW_TAG_inlined_subroutine = 0x1d
    DW_TAG_module = 0x1e
    DW_TAG_ptr_to_member_type = 0x1f
    DW_TAG_set_type = 0x20
    DW_TAG_subrange_type = 0x21
    DW_TAG_with_stmt = 0x22
    DW_TAG_access_declaration = 0x23
    DW_TAG_base_type = 0x24
    DW_TAG_catch_block = 0x25
    DW_TAG_const_type = 0x26
    DW_TAG_constant = 0x27
    DW_TAG_enumerator = 0x28
    DW_TAG_file_type = 0x29
    DW_TAG_friend = 0x2a
    DW_TAG_namelist = 0x2b
    DW_TAG_namelist_item = 0x2c
    DW_TAG_packed_type = 0x2d
    DW_TAG_subprogram = 0x2e
    DW_TAG_template_type_parameter = 0x2f
    DW_TAG_template_value_parameter = 0x30
    DW_TAG_throw_type = 0x31
    DW_TAG_try_block = 0x32
    DW_TAG_variant_part = 0x33
    DW_TAG_variable = 0x34
    DW_TAG_volatile_type = 0x35
    DW_TAG_dwarf_procedure = 0x36
    DW_TAG_restrict_type = 0x37
    DW_TAG_interface_type = 0x38
    DW_TAG_namespace = 0x39
    DW_TAG_imported_module = 0x3a
    DW_TAG_unspecified_type = 0x3b
    DW_TAG_partial_unit = 0x3c
    DW_TAG_imported_unit = 0x3d
    DW_TAG_condition = 0x3f
    DW_TAG_shared_type = 0x40
    DW_TAG_type_unit = 0x41
    DW_TAG_rvalue_reference_type = 0x42
    DW_TAG_template_alias = 0x43


class AttributeEncoding(Enum):
    DW_AT_sibling = 0x01
    DW_AT_location = 0x02
    DW_AT_name = 0x03
    DW_AT_ordering = 0x09
    DW_AT_byte_size = 0x0b
    DW_AT_bit_offset = 0x0c
    DW_AT_bit_size = 0x0d
    DW_AT_stmt_list = 0x10
    DW_AT_low_pc = 0x11
    DW_AT_high_pc = 0x12
    DW_AT_language = 0x13
    DW_AT_discr = 0x15
    DW_AT_discr_value = 0x16
    DW_AT_visibility = 0x17
    DW_AT_import = 0x18
    DW_AT_string_length = 0x19
    DW_AT_common_reference = 0x1a
    DW_AT_comp_dir = 0x1b
    DW_AT_const_value = 0x1c
    DW_AT_containing_type = 0x1d
    DW_AT_default_value = 0x1e
    DW_AT_inline = 0x20
    DW_AT_is_optional = 0x21
    DW_AT_lower_bound = 0x22
    DW_AT_producer = 0x25
    DW_AT_prototyped = 0x27
    DW_AT_return_addr = 0x2a
    DW_AT_start_scope = 0x2c
    DW_AT_bit_stride = 0x2e
    DW_AT_upper_bound = 0x2f
    DW_AT_abstract_origin = 0x31
    DW_AT_accessibility = 0x32
    DW_AT_address_class = 0x33
    DW_AT_artificial = 0x34
    DW_AT_base_type = 0x35
    DW_AT_calling_convention = 0x36
    DW_AT_count = 0x37
    DW_AT_data_member_location = 0x38
    DW_AT_decl_column = 0x39
    DW_AT_decl_file = 0x3a
    DW_AT_decl_line = 0x3b
    DW_AT_declaration = 0x3c
    DW_AT_discr_list = 0x3d
    DW_AT_encoding = 0x3e
    DW_AT_external = 0x3f
    DW_AT_frame_base = 0x40
    DW_AT_friend = 0x41
    DW_AT_identifier_case = 0x42
    DW_AT_macro_info = 0x43
    DW_AT_namelist_item = 0x44
    DW_AT_priority = 0x45
    DW_AT_segment = 0x46
    DW_AT_specification = 0x47
    DW_AT_static_link = 0x48
    DW_AT_type = 0x49
    DW_AT_use_location = 0x4a
    DW_AT_variable_parameter = 0x4b
    DW_AT_virtuality = 0x4c
    DW_AT_vtable_elem_location = 0x4d
    DW_AT_allocated = 0x4e
    DW_AT_associated = 0x4f
    DW_AT_data_location = 0x50
    DW_AT_byte_stride = 0x51
    DW_AT_entry_pc = 0x52
    DW_AT_use_UTF8 = 0x53
    DW_AT_extension = 0x54
    DW_AT_ranges = 0x55
    DW_AT_trampoline = 0x56
    DW_AT_call_column = 0x57
    DW_AT_call_file = 0x58
    DW_AT_call_line = 0x59
    DW_AT_description = 0x5a
    DW_AT_binary_scale = 0x5b
    DW_AT_decimal_scale = 0x5c
    DW_AT_small = 0x5d
    DW_AT_decimal_sign = 0x5e
    DW_AT_digit_count = 0x5f
    DW_AT_picture_string = 0x60
    DW_AT_mutable = 0x61
    DW_AT_threads_scaled = 0x62
    DW_AT_explicit = 0x63
    DW_AT_object_pointer = 0x64
    DW_AT_endianity = 0x65
    DW_AT_elemental = 0x66
    DW_AT_pure = 0x67
    DW_AT_recursive = 0x68
    DW_AT_signature = 0x69
    DW_AT_main_subprogram = 0x6a
    DW_AT_data_bit_offset = 0x6b
    DW_AT_const_expr = 0x6c
    DW_AT_enum_class = 0x6d
    DW_AT_linkage_name = 0x6e
    DW_AT_GNU_all_tail_call_sites = 0x2116


class FormEncoding(Enum):
    reader: type

    def __new__(cls, value: int, reader: type = None):
        assert reader is not None
        obj = object.__new__(cls)
        obj._value_ = value
        obj.reader = reader
        return obj

    @staticmethod
    def _read_indirect(sr: StreamReader) -> tuple['FormEncoding', object]:
        """Read an indirect form.

        Returns a tuple of a FormEncoding and corresponding value."""
        form_id = sr.uleb128()
        form = FormEncoding(form_id)
        return form, form.reader(sr)

    DW_FORM_addr = (0x01, StreamReader.pointer)
    DW_FORM_block2 = (0x03, StreamReader.block2)
    DW_FORM_block4 = (0x04, StreamReader.block4)
    DW_FORM_data2 = (0x05, StreamReader.uint2)
    DW_FORM_data4 = (0x06, StreamReader.uint4)
    DW_FORM_data8 = (0x07, StreamReader.uint8)
    DW_FORM_string = (0x08, StreamReader.cstring)
    DW_FORM_block = (0x09, StreamReader.block)
    DW_FORM_block1 = (0x0a, StreamReader.block1)
    DW_FORM_data1 = (0x0b, StreamReader.uint1)
    DW_FORM_flag = (0x0c, StreamReader.uint1)
    DW_FORM_sdata = (0x0d, StreamReader.sleb128)
    DW_FORM_strp = (0x0e, StreamReader.offset)
    DW_FORM_udata = (0x0f, StreamReader.uleb128)
    DW_FORM_ref_addr = (0x10, StreamReader.offset)
    DW_FORM_ref1 = (0x11, StreamReader.uint1)
    DW_FORM_ref2 = (0x12, StreamReader.uint2)
    DW_FORM_ref4 = (0x13, StreamReader.uint4)
    DW_FORM_ref8 = (0x14, StreamReader.uint8)
    DW_FORM_ref_udata = (0x15, StreamReader.uleb128)
    DW_FORM_indirect = (0x16, _read_indirect)
    DW_FORM_sec_offset = (0x17,  StreamReader.offset)
    DW_FORM_exprloc = (0x18, StreamReader.block)
    DW_FORM_flag_present = (0x19, lambda _: 1)
    DW_FORM_ref_sig8 = (0x20, StreamReader.uint8)


@dataclasses.dataclass(frozen=True)
class DieAttributeValue:
    """A representation of a single attribute value in DIE."""
    attribute: AttributeEncoding
    """An attribute taken from .debug_abbrev section."""
    form: FormEncoding
    """The form of the attribute value."""
    value: int | bytes
    """The attribute value."""
    offset: int
    """An offset of the value in the .debug_info section."""

    @staticmethod
    def read(
        sr: StreamReader,
        attributes: Sequence['AbbreviationAttribute'],
    ) -> Iterator['DieAttributeValue']:
        for attr in attributes:
            if attr.attribute_id == 0 and attr.form_id == 0:
                break
            form = FormEncoding(attr.form_id)
            attr_offset = sr.current_position
            attr_value = form.reader(sr)
            yield DieAttributeValue(
                AttributeEncoding(attr.attribute_id),
                form,
                attr_value,
                attr_offset,
            )


@dataclasses.dataclass(frozen=True)
class DebugInformationEntry:
    """An representation of the DIE from .debug_info section.

    In general DIEs can be nested - an DIE could have levels of multiple child
    DIEs. Currently this class doesn't represent this relationship - the DIEs
    are represented as a sequence, not as a tree. To reconstruct hierarchy,
    check the `level` field, when it increases by one, then this DIE is the
    child of the previous one."""
    abbreviation_number: int
    """A number of the abbreviation in the sequence defined in .debug_abbrev."""
    tag_id: int
    """An id of the DIE tag."""
    attributes: Sequence[DieAttributeValue]
    """A sequence of attributes in the DIE."""
    offset: int
    """An offset of the DIE in the .debug_info section."""
    level: int
    """A level of nesting of this DIE."""

    @staticmethod
    def read(
        sr: StreamReader,
        abbreviations: Sequence['AbbreviationDeclaration'],
    ) -> Iterator['DebugInformationEntry']:
        level = 0
        while not sr.at_eof:
            die_offset = sr.current_position
            abbrev_number = sr.uleb128()
            if abbrev_number == 0 and level > 0:
                # A null entry indicates and end of a children-sequence.
                # After yielding it, reduce level by one.
                yield DebugInformationEntry(
                    abbrev_number,
                    0,
                    tuple(),
                    die_offset,
                    level,
                )
                level -= 1
                continue
            if abbrev_number > len(abbreviations):
                break
            abbreviation = abbreviations[abbrev_number - 1]
            attributes = tuple(DieAttributeValue.read(sr, abbreviation.attributes))
            yield DebugInformationEntry(
                abbrev_number,
                abbreviation.tag,
                attributes,
                die_offset,
                level,
            )
            if abbreviation.has_children:
                level += 1


@dataclasses.dataclass(frozen=True)
class CompilationUnit:
    offset: int
    length: int
    is_dwarf32: bool
    version: int
    debug_abbrev_offset: int
    address_size: int
    die_entries: Sequence[DebugInformationEntry]

    @staticmethod
    def read(
        sr: StreamReader,
        debug_abbrev_sr: StreamReader,
    ) -> Iterator['CompilationUnit']:
        """Read compulation unit entries from a .debug_info section.

        CU's are in .debug_info, and contain a reference into .debug_abbrev
        section, which describes the structure of the individual DIEs - which
        attributes are in them.

        :param sr: The stream reader for the .debug_info section.
        :param debug_abbrev_sr: The stream reader for the .debug_abbrev section."""
        while not sr.at_eof:
            offset = sr.current_position
            length = sr.length()

            cu_offset = sr.current_position
            version = sr.uint2()
            assert version == 4, "Only DWARF v4 .debug_info is supported."

            debug_abbrev_offset = sr.offset()
            address_size = sr.uint1()

            def flatten(a: AbbreviationDeclaration) -> Iterator[AbbreviationDeclaration]:
                """Flatten a tree of abbreviation declarations into a single-level iterator."""
                yield a
                for c in a.children:
                    yield from flatten(c)

            # Get abbreviations for this CU.
            debug_abbrev_sr.set_abs_position(debug_abbrev_offset)
            cu_abbrev = next(AbbreviationDeclaration.read(debug_abbrev_sr, True))
            # Flatten abbreviations.
            abbreviations = tuple(flatten(cu_abbrev))

            die_entries: list[DebugInformationEntry] = list(DebugInformationEntry.read(sr, abbreviations))

            sr.set_abs_position(cu_offset + length)
            yield CompilationUnit(
                offset,
                length,
                sr.is_dwarf32,
                version,
                debug_abbrev_offset,
                address_size,
                die_entries,
            )


#
# .debug_abbrev
#
@dataclasses.dataclass(frozen=True)
class AbbreviationAttribute:
    """A representation of the attribute as it is in the .debug_abbrev.

    Can contain zero values, as those can be encountered in the raw data."""
    attribute_id: int
    form_id: int

    @staticmethod
    def read(sr: StreamReader) -> Iterator['AbbreviationAttribute']:
        while not sr.at_eof:
            name = sr.uleb128()
            form = sr.uleb128()
            yield AbbreviationAttribute(name, form)
            if name == 0 and form == 0:
                return


@dataclasses.dataclass(frozen=True)
class AbbreviationDeclaration:
    code: int
    tag: int
    has_children: bool
    attributes: Sequence[AbbreviationAttribute]
    children: Sequence['AbbreviationDeclaration']
    offset: int
    level: int

    @staticmethod
    def read(sr: StreamReader, level: int = 0) -> Iterator['AbbreviationDeclaration']:
        while not sr.at_eof:
            offset = sr.current_position
            code = sr.uleb128()
            if code == 0:
                # An end of the compilation unit abbreviation.
                return
            tag = sr.uleb128()
            has_children = bool(sr.uint1())
            attributes = tuple(AbbreviationAttribute.read(sr))

            if has_children:
                children = tuple(AbbreviationDeclaration.read(sr, level + 1))
            else:
                children = tuple()

            yield AbbreviationDeclaration(
                code,
                tag,
                has_children,
                attributes,
                children,
                offset,
                level,
            )


#
# .debug_aranges
#
@dataclasses.dataclass(frozen=True)
class ArangeEntry:
    length: int
    version: int
    debug_info_offset: int
    address_size: int
    segment_selector_size: int
    descriptors: Sequence[tuple[int, int]]

    @staticmethod
    def read(sr: StreamReader) -> Iterator['ArangeEntry']:
        while not sr.at_eof:
            length = sr.length()
            end_pos = sr.current_position + length
            version = sr.uint2()
            debug_info_offset = sr.offset()
            address_size = sr.uint1()
            segment_selector_size = sr.uint1()
            assert segment_selector_size == 0, "Non-zero segment size is not supported."

            # Must pad to an alignment boundary that is twice the address size.
            # This aligns with output from gcc/binutils and how objdump treats
            # input data, but I can't fully understand where this requirement
            # is in the specification.
            sr.set_abs_position(sr.current_position, address_size * 2)
            descriptors = list()
            while sr.current_position < end_pos:
                descr_address = sr.uint(address_size)
                descr_length = sr.uint(address_size)
                descriptors.append((descr_address, descr_length))
                if descr_address == 0 and descr_length == 0:
                    break

            yield ArangeEntry(
                length,
                version,
                debug_info_offset,
                address_size,
                segment_selector_size,
                descriptors,
            )
            sr.set_abs_position(end_pos)
