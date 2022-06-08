# Copyright (c) 2022 Anton Kolesov
# SPDX-License-Identifier: MIT

"""Classes specific to parsing of DWARF."""

__all__ = [
    'StreamReader',
    'CallFrameInstruction',
    'DW_EH_PE_ValueType',
    'DW_EH_PE_Relation',
    'CieRecord',
    'FdeRecord',
]

import builtins
import collections.abc
import dataclasses
from enum import Enum
from io import BytesIO, SEEK_CUR
from typing import BinaryIO, Iterable, Iterator, Mapping, NamedTuple, Optional, Sequence

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


class CallFrameInstruction(Enum):
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

    @staticmethod
    def read(sr: StreamReader) -> tuple['CallFrameInstruction', tuple]:
        b = sr.uint1()
        # Argument is inside of opcode
        match b >> 6:
            case 0:
                # 'Normal' instructions.
                instr = CallFrameInstruction(b & 0x3F)
                op_values = tuple(operand_type(sr) for operand_type in instr.operand_types)
                match instr:
                    case CallFrameInstruction.DW_CFA_def_cfa_expression:
                        expr = tuple(ExpressionOperation.read(StreamReader(sr.data_format, BytesIO(op_values[0]))))
                        return instr, (expr, )
                    case CallFrameInstruction.DW_CFA_expression | CallFrameInstruction.DW_CFA_val_expression:
                        expr = tuple(ExpressionOperation.read(StreamReader(sr.data_format, BytesIO(op_values[1]))))
                        return instr, (op_values[0], expr)
                return instr, op_values
            case 1:
                return CallFrameInstruction.DW_CFA_advance_loc, (b & 0x3F,)
            case 2:
                return CallFrameInstruction.DW_CFA_offset, (b & 0x3F, sr.uleb128())
            case 3:
                return CallFrameInstruction.DW_CFA_restore, (b & 0x3F,)
            case _:
                raise NotImplementedError('Unsupported call frame instruction.')

    def objdump_print(
            self,
            arch: ElfMachineType,
            data_format: DataFormat,
            cie: 'CieRecord',
            frame_pc: int,
            *args,
    ) -> str:
        """Format instruction in the style of objdump.

        :params args: Instruction operands."""
        # That is not a good function and needs a redesign pass.
        caf = cie.code_alignment_factor
        daf = cie.data_alignment_factor
        regs = _dwarf_register_names.get(arch, {})

        def rn(regnum: int) -> str:
            if regnum in regs:
                return f'r{regnum} ({regs[regnum]})'
            return f'r{regnum}'

        match self:
            case CallFrameInstruction.DW_CFA_set_loc:
                return f'{self.name}: {args[0]:016x}'
            case (CallFrameInstruction.DW_CFA_advance_loc |
                  CallFrameInstruction.DW_CFA_advance_loc1 |
                  CallFrameInstruction.DW_CFA_advance_loc2 |
                  CallFrameInstruction.DW_CFA_advance_loc4):
                return f'{self.name}: {args[0] * caf} to {frame_pc:{data_format.bits.address_format}}'

            case CallFrameInstruction.DW_CFA_def_cfa:
                return f'{self.name}: {rn(args[0])} ofs {args[1]}'
            case CallFrameInstruction.DW_CFA_def_cfa_sf:
                return f'{self.name}: {rn(args[0])} ofs {args[1] * daf}'
            case CallFrameInstruction.DW_CFA_def_cfa_register:
                return f'{self.name}: {rn(args[0])}'
            case CallFrameInstruction.DW_CFA_def_cfa_offset:
                return f'{self.name}: {args[0]}'
            case CallFrameInstruction.DW_CFA_def_cfa_offset_sf:
                return f'{self.name}: {args[0] * daf}'
            case CallFrameInstruction.DW_CFA_def_cfa_expression:
                expr_str = ExpressionOperation.objdump_print_seq(arch, args[0])
                return f'{self.name} ({expr_str})'

            case (CallFrameInstruction.DW_CFA_undefined |
                  CallFrameInstruction.DW_CFA_same_value):
                return f'{self.name}: {rn(args[0])}'

            case (CallFrameInstruction.DW_CFA_offset |
                  CallFrameInstruction.DW_CFA_offset_extended |
                  CallFrameInstruction.DW_CFA_offset_extended_sf):
                return f'{self.name}: {rn(args[0])} at cfa{args[1] * daf:+}'

            case (CallFrameInstruction.DW_CFA_val_offset |
                  CallFrameInstruction.DW_CFA_val_offset_sf):
                return f'{self.name}: {rn(args[0])} at cfa{args[1] * daf:+}'

            case CallFrameInstruction.DW_CFA_register:
                return f'{self.name}: {rn(args[0])} in {rn(args[1])}'

            case CallFrameInstruction.DW_CFA_expression:
                expr_str = ExpressionOperation.objdump_print_seq(arch, args[1])
                return f'{self.name}: {rn(args[0])} ({expr_str})'
            case CallFrameInstruction.DW_CFA_val_expression:
                expr_str = ExpressionOperation.objdump_print_seq(arch, args[1])
                return f'{self.name}: {rn(args[0])} ({expr_str})'

            case (CallFrameInstruction.DW_CFA_restore |
                  CallFrameInstruction.DW_CFA_restore_extended):
                return f'{self.name}: {rn(args[0])}'

            case (CallFrameInstruction.DW_CFA_remember_state |
                  CallFrameInstruction.DW_CFA_restore_state |
                  CallFrameInstruction.DW_CFA_nop |
                  _):
                return self.name


class ExpressionOperation(Enum):
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

    @staticmethod
    def read(sr: StreamReader) -> Iterable[tuple['ExpressionOperation', tuple]]:
        while not sr.at_eof:
            code = sr.uint1()
            op = ExpressionOperation(code)
            operand_values = tuple(operand_type(sr) for operand_type in op.operand_types)
            yield op, operand_values

    def objdump_print(
            self: 'ExpressionOperation',
            arch: ElfMachineType,
            *args,
    ) -> str:
        """Format operation in the style of objdump.

        :params args: Operation operands."""
        regs = _dwarf_register_names.get(arch, {})

        def rn(regnum: int) -> str:
            if regnum in regs:
                return f'reg{regnum} ({regs[regnum]})'
            return f'reg{regnum}'

        if ExpressionOperation.DW_OP_reg0.value < self.value < ExpressionOperation.DW_OP_reg31.value:
            regnum = self.value - 0x50
            return f'DW_OP_{rn(regnum)}'
        elif ExpressionOperation.DW_OP_breg0.value < self.value < ExpressionOperation.DW_OP_breg31.value:
            regnum = self.value - 0x70
            return f'DW_OP_b{rn(regnum)}: {args[0]}'
        elif ExpressionOperation.DW_OP_implicit_value == self:
            return f'{self.name}: {args[0].hex()}'
        operands_str = operands_str = ': ' + ' '.join(args) if len(args) > 0 else ''
        return self.name + operands_str

    @staticmethod
    def objdump_print_seq(
        arch: ElfMachineType,
        operations: Iterable[tuple['ExpressionOperation', tuple]],
    ):
        return '; '.join(op.objdump_print(arch, *args) for op, args in operations)


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

    _: dataclasses.KW_ONLY
    lsda_pointer_encoding: DW_EH_PE_ValueType | None = None
    lsda_pointer_adjust: DW_EH_PE_Relation | None = None
    personality_routine_pointer: int | None = None
    personality_routine_adjust: DW_EH_PE_Relation | None = None
    fde_pointer_encoding: DW_EH_PE_ValueType | None = None
    fde_pointer_adjust: DW_EH_PE_Relation | None = None

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

        augmentation_data: bytes = b''
        if 'z' in augmentation_str:
            augmentation_sz = sr.uleb128()
            augmentation_offset = sr.current_position
            # Read raw data and reset cursor to read again.
            # Can't parse augmentations from augmentation_data, because
            # personality_routine_pointer may have value dependant on a PC of
            # that field (pcrel adjustment).
            augmentation_data = sr.bytes(augmentation_sz)
            sr.set_abs_position(augmentation_offset)

            # Parse augmentation data.
            lsda_encoding: DW_EH_PE_ValueType | None = None
            lsda_adjust: DW_EH_PE_Relation | None = None
            pers_pointer: int | None = None
            pers_adjust: DW_EH_PE_Relation | None = None
            fde_pointer_encoding: DW_EH_PE_ValueType | None = None
            fde_pointer_adjust: DW_EH_PE_Relation | None = None
            for augmentatation_char in augmentation_str:
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
                            pers_pointer = pers_offset + pers_pointer
                    case 'R':
                        b = sr.uint1()
                        fde_pointer_encoding = DW_EH_PE_ValueType(b & 0xF)
                        fde_pointer_adjust = DW_EH_PE_Relation(b >> 4)

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
            lsda_pointer_encoding=lsda_encoding,
            lsda_pointer_adjust=lsda_adjust,
            personality_routine_pointer=pers_pointer,
            personality_routine_adjust=pers_adjust,
            fde_pointer_encoding=fde_pointer_encoding,
            fde_pointer_adjust=fde_pointer_adjust,
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
            assert cie.fde_pointer_encoding is not None
            pc_begin = cie.fde_pointer_encoding.read_value(sr)
            pc_range = cie.fde_pointer_encoding.read_value(sr)

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
        # cursor position to the before length field, so then the hihger-order
        # loop can safely read the CIE, whether it is real CIE or null
        # terminator.
        sr.set_abs_position(fde_start)


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
    reg: int
    offset: int
    # Either expression is present or reg+offset.
    # Expression is the collection of tuples, where first item is the
    # expression operation and second is the tuple of operation arguments.
    expression: Sequence[tuple[ExpressionOperation, tuple]] = dataclasses.field(default_factory=tuple)


class Expression(NamedTuple):
    op: ExpressionOperation
    operands: tuple


@dataclasses.dataclass(frozen=True)
class RegisterRule:
    instruction: CallFrameInstruction = CallFrameInstruction.DW_CFA_undefined

    _: dataclasses.KW_ONLY
    reg: int = 0
    offset: int = 0
    expression: Sequence[Expression] = dataclasses.field(default_factory=tuple)

    def __str__(self) -> str:
        match self.instruction:
            case CallFrameInstruction.DW_CFA_undefined:
                return 'u'
            case CallFrameInstruction.DW_CFA_same_value:
                # return 's'
                raise NotImplementedError()
            case CallFrameInstruction.DW_CFA_expression:
                return 'exp'
            case CallFrameInstruction.DW_CFA_register:
                return f'r{self.reg}'
            case (CallFrameInstruction.DW_CFA_val_offset |
                  CallFrameInstruction.DW_CFA_val_offset_sf |
                  # CallFrameInstruction.DW_CFA_register |
                  CallFrameInstruction.DW_CFA_val_expression |
                  CallFrameInstruction.DW_CFA_restore |
                  CallFrameInstruction.DW_CFA_restore_extended):
                raise NotImplementedError()
            case _:
                return f'c{self.offset:+}'


@dataclasses.dataclass(frozen=True)
class CallFrameLine:
    # Each line is identified by a PC value as a unique key (aka LOC).
    # Each line has a defined CFA value.
    # Each line has at least one register definition.
    loc: int

    # CFA could be: reg+offset (most often) or an expression.
    # For now we don't support the latter.
    cfa: CfaDefinition = CfaDefinition(0, 0)

    register_rules: Mapping[int, RegisterRule] = dataclasses.field(default_factory=dict)


class CallFrameTable(collections.abc.Iterable[CallFrameLine]):
    __initial: list[CallFrameLine]
    __rows: list[CallFrameLine]
    __state_stack: list[CallFrameLine]
    __cie: CieRecord

    def __init__(self, cie: CieRecord) -> None:
        self.__initial = list()
        self.__rows = list()
        self.__state_stack = list()
        self.__cie = cie

    def do_instruction(self, instr: CallFrameInstruction, *args) -> None:
        if instr == CallFrameInstruction.DW_CFA_nop:
            return

        prev = (self.__rows[-1] if len(self.__rows)
                else (self.__initial[-1] if len(self.__initial) else CallFrameLine(0)))
        n = self.__next_line(prev, instr, *args)
        if n.loc != prev.loc or len(self.__rows) == 0:
            self.__rows.append(n)
        else:
            self.__rows[-1] = n

    def __next_line(
        self,
        line: CallFrameLine,
        instr: CallFrameInstruction,
        *args,
    ) -> 'CallFrameLine':
        match instr:
            # Location Instructions.
            case CallFrameInstruction.DW_CFA_set_loc:
                return dataclasses.replace(line, loc=args[0])
            case (CallFrameInstruction.DW_CFA_advance_loc |
                  CallFrameInstruction.DW_CFA_advance_loc1 |
                  CallFrameInstruction.DW_CFA_advance_loc2 |
                  CallFrameInstruction.DW_CFA_advance_loc4):
                new_loc = line.loc + args[0] * self.__cie.code_alignment_factor
                return dataclasses.replace(line, loc=new_loc)

            # CFA Definition Instructions.
            case CallFrameInstruction.DW_CFA_def_cfa:
                return dataclasses.replace(line, cfa=CfaDefinition(args[0], args[1]))
            case CallFrameInstruction.DW_CFA_def_cfa_sf:
                cfa = CfaDefinition(args[0], args[1] * self.__cie.data_alignment_factor)
                return dataclasses.replace(line, cfa=cfa)
            case CallFrameInstruction.DW_CFA_def_cfa_register:
                cfa = dataclasses.replace(line.cfa, reg=args[0])
                return dataclasses.replace(line, cfa=cfa)
            case CallFrameInstruction.DW_CFA_def_cfa_offset:
                cfa = dataclasses.replace(line.cfa, offset=args[0])
                return dataclasses.replace(line, cfa=cfa)
            case CallFrameInstruction.DW_CFA_def_cfa_offset_sf:
                cfa = dataclasses.replace(line.cfa, offset=args[0] * self.__cie.data_alignment_factor)
                return dataclasses.replace(line, cfa=cfa)
            case CallFrameInstruction.DW_CFA_def_cfa_expression:
                cfa = CfaDefinition(0, 0, args[0])
                return dataclasses.replace(line, cfa=cfa)

            # Register_rules
            case CallFrameInstruction.DW_CFA_undefined:
                reg = args[0]
                new_rules = dict(line.register_rules)
                new_rules[reg] = RegisterRule()
                return dataclasses.replace(line, register_rules=new_rules)
            case CallFrameInstruction.DW_CFA_undefined:
                reg = args[0]
                new_rules = dict(line.register_rules)
                new_rules[reg] = RegisterRule(instruction=instr)
                return dataclasses.replace(line, register_rules=new_rules)
            case (CallFrameInstruction.DW_CFA_offset |
                  CallFrameInstruction.DW_CFA_offset_extended |
                  CallFrameInstruction.DW_CFA_offset_extended_sf):
                reg = args[0]
                off = args[1] * self.__cie.data_alignment_factor
                rr = RegisterRule(instr, offset=off)
                new_rules = dict(line.register_rules)
                new_rules[reg] = rr
                return dataclasses.replace(line, register_rules=new_rules)
            case CallFrameInstruction.DW_CFA_register:
                reg = args[0]
                where_stored_reg = args[1]
                rr = RegisterRule(instr, reg=where_stored_reg)
                new_rules = dict(line.register_rules)
                new_rules[reg] = rr
                return dataclasses.replace(line, register_rules=new_rules)
            case (CallFrameInstruction.DW_CFA_val_offset |
                  CallFrameInstruction.DW_CFA_val_offset_sf):
                raise NotImplementedError(str(instr))
            case CallFrameInstruction.DW_CFA_expression:
                reg = args[0]
                rr = RegisterRule(instr, expression=args[1])
                new_rules = dict(line.register_rules)
                new_rules[reg] = rr
                return dataclasses.replace(line, register_rules=new_rules)
            case (CallFrameInstruction.DW_CFA_restore |
                  CallFrameInstruction.DW_CFA_restore_extended):
                reg = args[0]
                rr = self.__initial[-1].register_rules.get(reg, RegisterRule())
                new_rules = dict(line.register_rules)
                new_rules[reg] = rr
                return dataclasses.replace(line, register_rules=new_rules)

            case CallFrameInstruction.DW_CFA_remember_state:
                self.__state_stack.append(line)
                return line

            case CallFrameInstruction.DW_CFA_restore_state:
                state_line = self.__state_stack.pop()
                return dataclasses.replace(line, cfa=state_line.cfa, register_rules=dict(state_line.register_rules))

            case CallFrameInstruction.DW_CFA_nop | _:
                return line

    def __iter__(self) -> Iterator[CallFrameLine]:
        if len(self.__initial) and (len(self.__rows) and self.__initial[-1].loc != self.__rows[0].loc):
            yield from self.__initial
        yield from self.__rows

    def mentioned_registers(self) -> Sequence[int]:
        result: set[int] = set()
        for row in self.__rows:
            result.update(row.register_rules.keys())
        return tuple(sorted(result))

    def objdump_format(self, arch: ElfMachineType, data_format: DataFormat) -> str:
        # Don't print anything if there are no rows.
        if len(self.__rows) == 0:
            return ''

        def rn(regnum: int) -> str:
            if regnum == self.__cie.return_address_register:
                return 'ra'
            regs = _dwarf_register_names.get(arch, {})
            return regs.get(regnum, 'r' + str(regnum))

        regs = self.mentioned_registers()
        result = []

        regnames = (format(rn(r), '5') for r in regs)
        result.append(f'{"   LOC  ":{data_format.bits.address_string_width}} CFA      {" ".join(regnames)} ')

        for row in self:
            if len(row.cfa.expression):
                cfa = 'exp'
            else:
                cfa = f'{rn(row.cfa.reg)}{row.cfa.offset:+}'

            rules_str = []
            for regnum in regs:
                rule = row.register_rules.get(regnum, RegisterRule())
                rules_str.append(f'{str(rule):5}')

            result.append(f'{row.loc:{data_format.bits.address_format}} {cfa:8} {" ".join(rules_str)} ')
        return '\n'.join(result)

    def copy(self, offset: int) -> 'CallFrameTable':
        r = CallFrameTable(self.__cie)
        r.__initial = list(self.__rows)
        if len(r.__initial):
            r.__initial[-1] = dataclasses.replace(r.__initial[-1], loc=offset)
        return r
