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
import dataclasses
from enum import Enum
from io import SEEK_CUR
from typing import BinaryIO, Iterator, Optional, Sequence

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
                return f'{self.name}: ({args[0].hex()})'

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
                return f'{self.name}: {rn(args[0])} ({args[1].hex()})'
            case CallFrameInstruction.DW_CFA_val_expression:
                return f'{self.name}: {rn(args[0])} ({args[1].hex()})'

            case (CallFrameInstruction.DW_CFA_restore |
                  CallFrameInstruction.DW_CFA_restore_extended):
                return f'{self.name}: {rn(args[0])}'

            case (CallFrameInstruction.DW_CFA_remember_state |
                  CallFrameInstruction.DW_CFA_restore_state |
                  CallFrameInstruction.DW_CFA_nop |
                  _):
                return self.name


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

    @property
    def eh_frame_value_type(self) -> DW_EH_PE_ValueType:
        if len(self.augmentation) > 0 and self.augmentation[0] == 'z' and 'R' in self.augmentation:
            return DW_EH_PE_ValueType(self.augmentation_data[0] & 0xF)
        raise BaseException('This CIE doesn\'t have augmentation that specifies use of .eh_frame value types.')

    @property
    def eh_frame_relation(self) -> DW_EH_PE_Relation:
        if len(self.augmentation) > 0 and self.augmentation[0] == 'z' and 'R' in self.augmentation:
            return DW_EH_PE_Relation(self.augmentation_data[0] >> 4)
        raise BaseException('This CIE doesn\'t have augmentation that specifies use of .eh_frame value types.')

    @staticmethod
    def read(sr: StreamReader) -> Optional['CieRecord']:
        # Note that this implements Linux .eh_frame structure, which is
        # slightly different from .debug_frame.
        offset = sr.current_position

        length = sr.uint4()
        if length == 0:
            # Null terminator CIE.
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
            augmentation_data = sr.bytes(augmentation_sz)

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
        cie: CieRecord,
    ) -> Iterator['FdeRecord']:
        """Read FDE records from the stream.

        :param sr: stream reader.
        :param cie: CIE for this FDE."""
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
            assert cie_abs_position == cie.offset
            # FDE always follows it's CIE so we don't have to try to search for
            # CIE using the CIE pointer - we already have CIE.

            pc_begin_offset = sr.current_position
            pc_begin = cie.eh_frame_value_type.read_value(sr)
            pc_range = cie.eh_frame_value_type.read_value(sr)

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
        1: 'rcx',
        2: 'rdx',
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
