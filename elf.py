# Copyright (c) 2022 Anton Kolesov
# SPDX-License-Identifier: MIT

"""Classes specific to parsing of ELF files.

For documentation see http://www.sco.com/developers/gabi/latest/contents.html."""

__all__ = [
    'align_up',
    'ElfClass',
    'DataFormat',
    'Endianness',
    'ElfOsAbi',
    'ElfType',
    'ElfMachineType',
    'ElfHeader',
    'ProgramHeaderType',
    'SectionType',
    'SectionFlags',
    'SectionHeader',
    'StringTable',
    'SymbolTableEntry',
    'RelocationEntry',
    'RelocationEntryWithAddend',
    'RelocationTypeI386',
    'RelocationTypeAmd64',
    'DynamicEntryFlags',
    'DynamicEntryFlags1',
    'DynamicEntryTag',
    'DynamicEntry',
    'VersionFlags',
    'VersionNeededEntry',
    'VersionNeededAuxEntry',
    'VersionNeededAux',
    'VersionNeeded',
    'Section',
    'Symbol',
    'Relocation',
    'Elf',
]

import collections.abc
import dataclasses
from enum import Enum, IntEnum, IntFlag
import itertools
import struct
from typing import BinaryIO, cast, get_type_hints, Iterable, Iterator, NamedTuple, Sequence, TypeVar


#
# Common declarations.
#
def _missing_enum_value(cls, value):
    """An implementation of Enum._missing_ function that is specific to header fields.

    Relies on the class to provide LOOS, HIOS, LOPROC, and HIPROC class fields."""
    if cls.LOOS.value <= value <= cls.HIOS.value:
        name = hex(value)
    elif cls.LOPROC.value <= value <= cls.HIPROC.value:
        name = hex(value)
    else:
        return None
    obj = object.__new__(cls)
    obj._value_ = value
    obj._name_ = name
    return obj


def align_up(value: int, alignment: int) -> int:
    """Align value up to the address alignment."""
    div, mod = divmod(value, alignment)
    if mod == 0:
        return value  # Already aligned.
    return alignment * (div + 1)


class ElfClass(Enum):
    ELF32 = 1
    ELF64 = 2

    address_size: int
    """Amount of bytes needed to represent address for this ELF class."""
    address_string_width: int
    """Amount of characters needed to represent the address in hex format."""
    address_format: str
    """The string format to represent the address (without `0x`)."""
    address_xformat: str
    """The string format to represent the address with `0x`."""

    def __init__(self, value: int) -> None:
        self.address_size = 4 * value
        self.address_string_width = self.address_size * 2
        self.address_format = f'0{self.address_string_width}x'
        self.address_xformat = f'#0{self.address_string_width+2}x'


_T = TypeVar('_T')


@dataclasses.dataclass(frozen=True)
class DataFormat:
    """A class to represent combination of bitness and byte order.

    Provides a facility to read data in the specified format from byte-buffers."""

    bits: ElfClass
    """An ELF class of the data format."""

    byte_order: 'Endianness'
    """A byte order of the ELF file data."""

    @property
    def pointer_format(self) -> str:
        """Return a native-supported format for the pointer on the data format.

        A helper to use for ``struct`` format strings.

        :return: ``L`` for 32-bit data, ``Q`` for 64-bit data."""
        return 'L' if self.bits == ElfClass.ELF32 else 'Q'

    @property
    def byte_order_format(self) -> str:
        """Return a byte-order prefix for the ``struct`` format string.

        :return: ``<`` for the little endian, ``>`` otherwise."""
        return '<' if self.byte_order == Endianness.LITTLE else '>'

    def read_values(
        self,
        buffer: bytes,
        types: Iterable[type],
        format: str,
    ) -> Iterator[tuple]:
        """Read multiple values from the buffer using the ``struct`` module.

        The ``format`` argument is almost the same as the format string for
        ``struct`` module but with a minor difference - the module uses ``P``
        format for native pointers and this format is not supported for
        non-native format string. This function adds support for ``P`` format as
        a *target* architecture pointer and replaces ``P`` with a
        correctly-sized data (4 or 8-byte unsigned). This function also always
        prefixes the format string with a correct byte-order identifier.

        :param buffer: And incomming bytes data.
        :param types: An iterable of types to which to convert the read-out values.
        :param format: A format string to read data from the buffer, similar to
            ``struct`` format strings.

        :return: A iterator of tuples, where each tuple consists of objects that
            were created using the ``types`` sequence, and with arguments read
            from the buffer."""

        real_fmt = self.adjust_format_string(format)
        # `types` can be an iterator and thus can't be iterated repeatedly.
        types_copy = tuple(types)
        for raw_values in struct.iter_unpack(real_fmt, buffer):
            yield tuple(t(a) for t, a in zip(types_copy, raw_values, strict=True))

    def read_dataclass_values(
        self,
        buffer: bytes,
        type: type[_T],
        format: str,
    ) -> Iterator[_T]:
        """Read multiple dataclass instances from the buffer.

        A helper function which specializes the ``read_values`` for the case
        where the values read out from the buffer are fields of the dataclass.
        This function require that fields in the dataclass are in the same
        order as in the buffer."""
        assert dataclasses.is_dataclass(type)
        yield from (type(*a) for a in self.read_values(
            buffer,
            (f.type for f in dataclasses.fields(type)),
            format,
        ))

    def read_value(
        self,
        buffer: bytes,
        types: Iterable[type],
        format: str,
    ) -> tuple:
        """Read one value from the buffer using the ``struct`` module.

        A wrapper around ``read_values`` to read just one value."""
        return next(self.read_values(buffer, types, format))

    def read_dataclass_value(
        self,
        buffer: bytes,
        type: type[_T],
        format: str,
    ) -> _T:
        """Read one dataclass instances from the buffer using the ``struct`` module.

        A wrapper around ``read_dataclass_values`` to read just one value."""
        return next(self.read_dataclass_values(buffer, type, format))

    def read_uint1(self, buffer: bytes) -> int:
        """Parse a 1-byte unsigned integer from the buffer."""
        return struct.unpack(self.adjust_format_string('B'), buffer)[0]

    def read_uint2(self, buffer: bytes) -> int:
        """Parse a 2-byte unsigned integer from the buffer."""
        return struct.unpack(self.adjust_format_string('H'), buffer)[0]

    def read_uint4(self, buffer: bytes) -> int:
        """Parse a 4-byte unsigned integer from the buffer."""
        return struct.unpack(self.adjust_format_string('L'), buffer)[0]

    def read_uint8(self, buffer: bytes) -> int:
        """Parse a 8-byte unsigned integer from the buffer."""
        return struct.unpack(self.adjust_format_string('Q'), buffer)[0]

    def read_sint1(self, buffer: bytes) -> int:
        """Parse a 1-byte signed integer from the buffer."""
        return struct.unpack(self.adjust_format_string('b'), buffer)[0]

    def read_sint2(self, buffer: bytes) -> int:
        """Parse a 2-byte signed integer from the buffer."""
        return struct.unpack(self.adjust_format_string('h'), buffer)[0]

    def read_sint4(self, buffer: bytes) -> int:
        """Parse a 4-byte signed integer from the buffer."""
        return struct.unpack(self.adjust_format_string('l'), buffer)[0]

    def read_sint8(self, buffer: bytes) -> int:
        """Parse a 8-byte signed integer from the buffer."""
        return struct.unpack(self.adjust_format_string('q'), buffer)[0]

    def parse_cstring(self, stream: bytes, offset: int = 0) -> str:
        """Parse a zero-terminated string from bytes.

        This function doesn't really depend on the target data format, it just
        logically makes sense to group it with other functions that read data
        from byte buffers."""
        end = stream.find(b'\x00', offset)
        return stream[offset:end].decode('ascii')

    def adjust_format_string(self, format: str) -> str:
        """Adjust specified format string to this data format.

        Sets endianness and provides exact size to pointers."""
        return self.byte_order_format + format.replace('P', self.pointer_format)

    def calc_size(self, format: str) -> int:
        """Just like ``struct.calcsize` except with support for target pointers."""
        return struct.calcsize(self.adjust_format_string(format))


#
# ELF header.
#
class Endianness(Enum):
    description: str
    "Text description of this endianness type."

    def __new__(cls, value, description=''):
        # if `description` is not given a default value, then something like
        # Endianness(1) produces a warning from mypy, but actually works in
        # CPython. To shut up mypy I've set here a default value, even though
        # it will never be used.
        assert description != ''
        obj = object.__new__(cls)
        obj._value_ = value
        obj.description = description
        return obj

    NONE = (0, "none")
    LITTLE = (1, "2's complement, little endian")
    BIG = (2, "2's complement, big endian")


class ElfOsAbi(Enum):
    description: str
    "Text description of this OS/ABI type."

    def __new__(cls, value, description=''):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.description = description
        return obj

    SYSTEMV = (0, 'UNIX - System V')
    HPUX = (1, 'UNIX - HP-UX')
    NETBSD = (2, 'UNIX - NetBSD')
    GNU = (3, 'UNIX - GNU')
    LINUX = (3, 'UNIX - Linux')
    SOLARIS = (4, 'UNIX - Solaris')
    AIX = (5, 'UNIX - AIX')
    IRIX = (6, 'UNIX - IRIX')
    FREEBSD = (7, 'UNIX - FreeBSD')
    TRU64 = (10, 'UNIX - TRU64')
    MODESTO = (11, 'Novell - Modesto')
    OPENBSD = (12, 'UNIX - OpenBSD')
    OPENVMS = (13, 'VMS - OpenVMS')
    NSK = (14, 'HP - Non-Stop Kernel')
    AROS = (15, 'AROS')
    FENIXOS = (16, 'FenixOS')
    CLOUDABI = (17, 'Nuxi CloudABI')
    OPENVOS = (18, 'Stratus Technologies OpenVOS')


class ElfType(Enum):
    description: str
    "Text description of this ELF file type."

    def __new__(cls, value, description=''):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.description = description
        return obj

    NONE = (0, 'None')
    REL = (1, 'Relocatable file')
    EXEC = (2, 'Executable file')
    DYN = (3, 'Shared object file')
    CORE = (4, 'Core file')
    LOOS = 0xFE00
    HIOS = 0xFEFF
    LOPROC = 0xFF00
    HIPROC = 0xFFFF

    @classmethod
    def _missing_(cls, value):
        return _missing_enum_value(cls, value)


class ElfMachineType(Enum):
    description: str
    "Text description of this machine type."

    def __new__(cls, value, description=''):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.description = description
        return obj

    # This list comes from binutils/include/elf.h file.
    EM_NONE = 0  # No machine
    EM_M32 = 1  # AT&T WE 32100
    EM_SPARC = 2  # SUN SPARC
    EM_386 = (3, 'Intel 80386')  # Intel 80386
    EM_68K = 4  # Motorola m68k family
    EM_88K = 5  # Motorola m88k family
    EM_IAMCU = 6  # Intel MCU
    EM_860 = 7  # Intel 80860
    EM_MIPS = 8  # MIPS R3000 (officially, big-endian only)
    EM_S370 = 9  # IBM System/370
    EM_MIPS_RS3_LE = 10  # MIPS R3000 little-endian (Oct 4 1999 Draft).  Deprecated.
    EM_OLD_SPARCV9 = 11  # Old version of Sparc v9, from before the ABI.  Deprecated.
    EM_res011 = 11  # Reserved
    EM_res012 = 12  # Reserved
    EM_res013 = 13  # Reserved
    EM_res014 = 14  # Reserved
    EM_PARISC = 15  # HPPA
    EM_res016 = 16  # Reserved
    EM_PPC_OLD = 17  # Old version of PowerPC.  Deprecated.
    EM_VPP550 = 17  # Fujitsu VPP500
    EM_SPARC32PLUS = 18  # Sun's "v8plus"
    EM_960 = 19  # Intel 80960
    EM_PPC = 20  # PowerPC
    EM_PPC64 = 21  # 64-bit PowerPC
    EM_S390 = 22  # IBM S/390
    EM_SPU = 23  # Sony/Toshiba/IBM SPU
    EM_res024 = 24  # Reserved
    EM_res025 = 25  # Reserved
    EM_res026 = 26  # Reserved
    EM_res027 = 27  # Reserved
    EM_res028 = 28  # Reserved
    EM_res029 = 29  # Reserved
    EM_res030 = 30  # Reserved
    EM_res031 = 31  # Reserved
    EM_res032 = 32  # Reserved
    EM_res033 = 33  # Reserved
    EM_res034 = 34  # Reserved
    EM_res035 = 35  # Reserved
    EM_V800 = 36  # NEC V800 series
    EM_FR20 = 37  # Fujitsu FR20
    EM_RH32 = 38  # TRW RH32
    EM_MCORE = 39  # Motorola M*Core */ /* May also be taken by Fujitsu MMA
    EM_RCE = 39  # Old name for MCore
    EM_ARM = 40  # ARM
    EM_OLD_ALPHA = 41  # Digital Alpha
    EM_SH = 42  # Renesas (formerly Hitachi) / SuperH SH
    EM_SPARCV9 = 43  # SPARC v9 64-bit
    EM_TRICORE = 44  # Siemens Tricore embedded processor
    EM_ARC = 45  # ARC Cores
    EM_H8_300 = 46  # Renesas (formerly Hitachi) H8/300
    EM_H8_300H = 47  # Renesas (formerly Hitachi) H8/300H
    EM_H8S = 48  # Renesas (formerly Hitachi) H8S
    EM_H8_500 = 49  # Renesas (formerly Hitachi) H8/500
    EM_IA_64 = 50  # Intel IA-64 Processor
    EM_MIPS_X = 51  # Stanford MIPS-X
    EM_COLDFIRE = 52  # Motorola Coldfire
    EM_68HC12 = 53  # Motorola M68HC12
    EM_MMA = 54  # Fujitsu Multimedia Accelerator
    EM_PCP = 55  # Siemens PCP
    EM_NCPU = 56  # Sony nCPU embedded RISC processor
    EM_NDR1 = 57  # Denso NDR1 microprocessor
    EM_STARCORE = 58  # Motorola Star*Core processor
    EM_ME16 = 59  # Toyota ME16 processor
    EM_ST100 = 60  # STMicroelectronics ST100 processor
    EM_TINYJ = 61  # Advanced Logic Corp. TinyJ embedded processor
    EM_X86_64 = (62, 'Advanced Micro Devices X86-64')
    EM_PDSP = 63  # Sony DSP Processor
    EM_PDP10 = 64  # Digital Equipment Corp. PDP-10
    EM_PDP11 = 65  # Digital Equipment Corp. PDP-11
    EM_FX66 = 66  # Siemens FX66 microcontroller
    EM_ST9PLUS = 67  # STMicroelectronics ST9+ 8/16 bit microcontroller
    EM_ST7 = 68  # STMicroelectronics ST7 8-bit microcontroller
    EM_68HC16 = 69  # Motorola MC68HC16 Microcontroller
    EM_68HC11 = 70  # Motorola MC68HC11 Microcontroller
    EM_68HC08 = 71  # Motorola MC68HC08 Microcontroller
    EM_68HC05 = 72  # Motorola MC68HC05 Microcontroller
    EM_SVX = 73  # Silicon Graphics SVx
    EM_ST19 = 74  # STMicroelectronics ST19 8-bit cpu
    EM_VAX = 75  # Digital VAX
    EM_CRIS = 76  # Axis Communications 32-bit embedded processor
    EM_JAVELIN = 77  # Infineon Technologies 32-bit embedded cpu
    EM_FIREPATH = 78  # Element 14 64-bit DSP processor
    EM_ZSP = 79  # LSI Logic's 16-bit DSP processor
    EM_MMIX = 80  # Donald Knuth's educational 64-bit processor
    EM_HUANY = 81  # Harvard's machine-independent format
    EM_PRISM = 82  # SiTera Prism
    EM_AVR = 83  # Atmel AVR 8-bit microcontroller
    EM_FR30 = 84  # Fujitsu FR30
    EM_D10V = 85  # Mitsubishi D10V
    EM_D30V = 86  # Mitsubishi D30V
    EM_V850 = 87  # Renesas V850 (formerly NEC V850)
    EM_M32R = 88  # Renesas M32R (formerly Mitsubishi M32R)
    EM_MN10300 = 89  # Matsushita MN10300
    EM_MN10200 = 90  # Matsushita MN10200
    EM_PJ = 91  # picoJava
    EM_OR1K = 92  # OpenRISC 1000 32-bit embedded processor
    EM_ARC_COMPACT = 93  # ARC International ARCompact processor
    EM_XTENSA = 94  # Tensilica Xtensa Architecture
    EM_SCORE_OLD = 95  # Old Sunplus S+core7 backend magic number. Written in the absence of an ABI.
    EM_VIDEOCORE = 95  # Alphamosaic VideoCore processor
    EM_TMM_GPP = 96  # Thompson Multimedia General Purpose Processor
    EM_NS32K = 97  # National Semiconductor 32000 series
    EM_TPC = 98  # Tenor Network TPC processor
    EM_PJ_OLD = 99  # Old value for picoJava.  Deprecated.
    EM_SNP1K = 99  # Trebia SNP 1000 processor
    EM_ST200 = 100  # STMicroelectronics ST200 microcontroller
    EM_IP2K = 101  # Ubicom IP2022 micro controller
    EM_MAX = 102  # MAX Processor
    EM_CR = 103  # National Semiconductor CompactRISC
    EM_F2MC16 = 104  # Fujitsu F2MC16
    EM_MSP430 = 105  # TI msp430 micro controller
    EM_BLACKFIN = 106  # ADI Blackfin
    EM_SE_C33 = 107  # S1C33 Family of Seiko Epson processors
    EM_SEP = 108  # Sharp embedded microprocessor
    EM_ARCA = 109  # Arca RISC Microprocessor
    EM_UNICORE = 110  # Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
    EM_EXCESS = 111  # eXcess: 16/32/64-bit configurable embedded CPU
    EM_DXP = 112  # Icera Semiconductor Inc. Deep Execution Processor
    EM_ALTERA_NIOS2 = 113  # Altera Nios II soft-core processor
    EM_CRX = 114  # National Semiconductor CRX
    EM_CR16_OLD = 115  # Old, value for National Semiconductor CompactRISC.  Deprecated.
    EM_XGATE = 115  # Motorola XGATE embedded processor
    EM_C166 = 116  # Infineon C16x/XC16x processor
    EM_M16C = 117  # Renesas M16C series microprocessors
    EM_DSPIC30F = 118  # Microchip Technology dsPIC30F Digital Signal Controller
    EM_CE = 119  # Freescale Communication Engine RISC core
    EM_M32C = 120  # Renesas M32C series microprocessors
    EM_res121 = 121  # Reserved
    EM_res122 = 122  # Reserved
    EM_res123 = 123  # Reserved
    EM_res124 = 124  # Reserved
    EM_res125 = 125  # Reserved
    EM_res126 = 126  # Reserved
    EM_res127 = 127  # Reserved
    EM_res128 = 128  # Reserved
    EM_res129 = 129  # Reserved
    EM_res130 = 130  # Reserved
    EM_TSK3000 = 131  # Altium TSK3000 core
    EM_RS08 = 132  # Freescale RS08 embedded processor
    EM_res133 = 133  # Reserved
    EM_ECOG2 = 134  # Cyan Technology eCOG2 microprocessor
    EM_SCORE = 135  # Sunplus Score
    EM_SCORE7 = 135  # Sunplus S+core7 RISC processor
    EM_DSP24 = 136  # New Japan Radio (NJR) 24-bit DSP Processor
    EM_VIDEOCORE3 = 137  # Broadcom VideoCore III processor
    EM_LATTICEMICO32 = 138  # RISC processor for Lattice FPGA architecture
    EM_SE_C17 = 139  # Seiko Epson C17 family
    EM_TI_C6000 = 140  # Texas Instruments TMS320C6000 DSP family
    EM_TI_C2000 = 141  # Texas Instruments TMS320C2000 DSP family
    EM_TI_C5500 = 142  # Texas Instruments TMS320C55x DSP family
    EM_res143 = 143  # Reserved
    EM_TI_PRU = 144  # Texas Instruments Programmable Realtime Unit
    EM_res145 = 145  # Reserved
    EM_res146 = 146  # Reserved
    EM_res147 = 147  # Reserved
    EM_res148 = 148  # Reserved
    EM_res149 = 149  # Reserved
    EM_res150 = 150  # Reserved
    EM_res151 = 151  # Reserved
    EM_res152 = 152  # Reserved
    EM_res153 = 153  # Reserved
    EM_res154 = 154  # Reserved
    EM_res155 = 155  # Reserved
    EM_res156 = 156  # Reserved
    EM_res157 = 157  # Reserved
    EM_res158 = 158  # Reserved
    EM_res159 = 159  # Reserved
    EM_MMDSP_PLUS = 160  # STMicroelectronics 64bit VLIW Data Signal Processor
    EM_CYPRESS_M8C = 161  # Cypress M8C microprocessor
    EM_R32C = 162  # Renesas R32C series microprocessors
    EM_TRIMEDIA = 163  # NXP Semiconductors TriMedia architecture family
    EM_QDSP6 = 164  # QUALCOMM DSP6 Processor
    EM_8051 = 165  # Intel 8051 and variants
    EM_STXP7X = 166  # STMicroelectronics STxP7x family
    EM_NDS32 = 167  # Andes Technology compact code size embedded RISC processor family
    EM_ECOG1 = 168  # Cyan Technology eCOG1X family
    EM_ECOG1X = 168  # Cyan Technology eCOG1X family
    EM_MAXQ30 = 169  # Dallas Semiconductor MAXQ30 Core Micro-controllers
    EM_XIMO16 = 170  # New Japan Radio (NJR) 16-bit DSP Processor
    EM_MANIK = 171  # M2000 Reconfigurable RISC Microprocessor
    EM_CRAYNV2 = 172  # Cray Inc. NV2 vector architecture
    EM_RX = 173  # Renesas RX family
    EM_METAG = 174  # Imagination Technologies Meta processor architecture
    EM_MCST_ELBRUS = 175  # MCST Elbrus general purpose hardware architecture
    EM_ECOG16 = 176  # Cyan Technology eCOG16 family
    EM_CR16 = 177  # National Semiconductor CompactRISC 16-bit processor
    EM_ETPU = 178  # Freescale Extended Time Processing Unit
    EM_SLE9X = 179  # Infineon Technologies SLE9X core
    EM_L1OM = 180  # Intel L1OM
    EM_K1OM = 181  # Intel K1OM
    EM_INTEL182 = 182  # Reserved by Intel
    EM_AARCH64 = 183  # ARM 64-bit architecture
    EM_ARM184 = 184  # Reserved by ARM
    EM_AVR32 = 185  # Atmel Corporation 32-bit microprocessor family
    EM_STM8 = 186  # STMicroeletronics STM8 8-bit microcontroller
    EM_TILE64 = 187  # Tilera TILE64 multicore architecture family
    EM_TILEPRO = 188  # Tilera TILEPro multicore architecture family
    EM_MICROBLAZE = 189  # Xilinx MicroBlaze 32-bit RISC soft processor core
    EM_CUDA = 190  # NVIDIA CUDA architecture
    EM_TILEGX = 191  # Tilera TILE-Gx multicore architecture family
    EM_CLOUDSHIELD = 192  # CloudShield architecture family
    EM_COREA_1ST = 193  # KIPO-KAIST Core-A 1st generation processor family
    EM_COREA_2ND = 194  # KIPO-KAIST Core-A 2nd generation processor family
    EM_ARC_COMPACT2 = (195, 'ARCv2')  # Synopsys ARCompact V2
    EM_OPEN8 = 196  # Open8 8-bit RISC soft processor core
    EM_RL78 = 197  # Renesas RL78 family.
    EM_VIDEOCORE5 = 198  # Broadcom VideoCore V processor
    EM_78K0R = 199  # Renesas 78K0R.
    EM_56800EX = 200  # Freescale 56800EX Digital Signal Controller (DSC)
    EM_BA1 = 201  # Beyond BA1 CPU architecture
    EM_BA2 = 202  # Beyond BA2 CPU architecture
    EM_XCORE = 203  # XMOS xCORE processor family
    EM_MCHP_PIC = 204  # Microchip 8-bit PIC(r) family
    EM_INTELGT = 205  # Intel Graphics Technology
    EM_INTEL206 = 206  # Reserved by Intel
    EM_INTEL207 = 207  # Reserved by Intel
    EM_INTEL208 = 208  # Reserved by Intel
    EM_INTEL209 = 209  # Reserved by Intel
    EM_KM32 = 210  # KM211 KM32 32-bit processor
    EM_KMX32 = 211  # KM211 KMX32 32-bit processor
    EM_KMX16 = 212  # KM211 KMX16 16-bit processor
    EM_KMX8 = 213  # KM211 KMX8 8-bit processor
    EM_KVARC = 214  # KM211 KVARC processor
    EM_CDP = 215  # Paneve CDP architecture family
    EM_COGE = 216  # Cognitive Smart Memory Processor
    EM_COOL = 217  # Bluechip Systems CoolEngine
    EM_NORC = 218  # Nanoradio Optimized RISC
    EM_CSR_KALIMBA = 219  # CSR Kalimba architecture family
    EM_Z80 = 220  # Zilog Z80
    EM_VISIUM = 221  # Controls and Data Services VISIUMcore processor
    EM_FT32 = 222  # FTDI Chip FT32 high performance 32-bit RISC architecture
    EM_MOXIE = 223  # Moxie processor family
    EM_AMDGPU = 224  # AMD GPU architecture
    EM_RISCV = 243  # RISC-V
    EM_LANAI = 244  # Lanai 32-bit processor.
    EM_CEVA = 245  # CEVA Processor Architecture Family
    EM_CEVA_X2 = 246  # CEVA X2 Processor Family
    EM_BPF = 247  # Linux BPF – in-kernel virtual machine.
    EM_GRAPHCORE_IPU = 248  # Graphcore Intelligent Processing Unit
    EM_IMG1 = 249  # Imagination Technologies
    EM_NFP = 250  # Netronome Flow Processor.
    EM_VE = 251  # NEC Vector Engine
    EM_CSKY = 252  # C-SKY processor family.
    EM_ARC_COMPACT3_64 = 253  # Synopsys ARCv2.3 64-bit
    EM_MCS6502 = 254  # MOS Technology MCS 6502 processor
    EM_ARC_COMPACT3 = 255  # Synopsys ARCv2.3 32-bit
    EM_KVX = 256  # Kalray VLIW core of the MPPA processor family
    EM_65816 = 257  # WDC 65816/65C816
    EM_LOONGARCH = 258  # LoongArch
    EM_KF32 = 259  # ChipON KungFu32
    EM_U16_U8CORE = 260  # LAPIS nX-U16/U8
    EM_TACHYUM = 261  # Tachyum
    EM_56800EF = 262  # NXP 56800EF Digital Signal Controller (DSC)


@dataclasses.dataclass(frozen=True)
class ElfHeader:
    magic: str
    elf_class: ElfClass
    endiannes: Endianness
    version: int
    osabi: ElfOsAbi
    abiversion: int
    objectType: ElfType
    machine: ElfMachineType
    version2: int
    entry: int
    program_header_offset: int
    section_header_offset: int
    flags: int
    elf_header_size: int  # Size of this header.
    program_header_size: int
    program_header_entries: int
    section_header_size: int
    section_header_entries: int
    section_header_names_index: int

    @property
    def data_format(self) -> DataFormat:
        """A data format specified in this header."""
        return DataFormat(self.elf_class, self.endiannes)

    @staticmethod
    def get_data_format(header_bytes: bytes) -> DataFormat:
        """Check ELF magic bytes and retrieve ELF class and byte order.

        ELF class is quite important because it affects the size of
        address-sized fields and sometimes the layout of the header, therefore
        it is parsed before the headers themself."""
        assert len(header_bytes) >= 6

        if header_bytes[:4] != bytes.fromhex('7f 45 4c 46'):
            raise ValueError('The input stream is not a valid ELF file.')
        return DataFormat(ElfClass(header_bytes[4]), Endianness(header_bytes[5]))

    @staticmethod
    def parse_elf_header(header_bytes: bytes) -> 'ElfHeader':
        """Parse an ELF header from a given bytes from the file."""
        # ELF class is a special case needed to properly parse address fields.
        df = ElfHeader.get_data_format(header_bytes)

        return df.read_dataclass_value(
            header_bytes[:64 if df.bits == ElfClass.ELF64 else 52],
            ElfHeader,
            'L5B7xHHLPPPL6H',
        )

    @staticmethod
    def read_elf_header(stream: BinaryIO) -> 'ElfHeader':
        """Read ELF header from a binary stream.

        Unlike `parse_elf_header` this function reads data from a stream, and
        thus changes current state of the input stream."""
        stream.seek(0)
        elf_header_bytes = stream.read(64)
        return ElfHeader.parse_elf_header(elf_header_bytes)


#
# Program header.
#
class ProgramHeaderType(Enum):
    NULL = 0  # Program header table entry unused.
    LOAD = 0x00000001  # Loadable segment.
    DYNAMIC = 0x00000002  # Dynamic linking information.
    INTERP = 0x00000003  # Interpreter information.
    NOTE = 0x00000004  # Auxiliary information.
    SHLIB = 0x00000005  # Reserved.
    PHDR = 0x00000006  # Segment containing program header table itself.
    TLS = 0x00000007  # Thread-Local Storage template.

    # Formally those are OS-specific extensions, not part of SystemV ABI, but
    # readelf defines them unconditionally, whether target is GNU or not.
    GNU_EH_FRAME = 0x6474e550
    GNU_STACK = 0x6474e551
    GNU_RELRO = 0x6474e552
    GNU_PROPERTY = 0x6474e553

    LOOS = 0x60000000  # Reserved inclusive range. Operating system specific.
    HIOS = 0x6FFFFFFF
    LOPROC = 0x70000000  # Reserved inclusive range. Processor specific.
    HIPROC = 0x7FFFFFFF

    @classmethod
    def _missing_(cls, value):
        return _missing_enum_value(cls, value)


class ProgramHeaderFlags(IntFlag):
    EXECUTE = 0x1
    WRITE = 0x2
    READ = 0x4

    @classmethod
    def _missing_(cls, value):
        # Can't add those values as class variables, as interpreter gets into
        # some infinite recursion. And if I add them to _ignore_, then they are
        # not available inside of the functions.
        MASKOS = 0x0FF00000
        MASKPROC = 0xF0000000
        if (value & MASKOS == value) or (value & MASKPROC == value):
            obj = int.__new__(cls)
            obj._value_ = value
            obj._name_ = hex(value)
            return obj
        return super()._missing_(value)

    @property
    def summary(self) -> str:
        """Format string in the style of readelf -l option."""
        return ''.join([
            'R' if ProgramHeaderFlags.READ in self else ' ',
            'W' if ProgramHeaderFlags.WRITE in self else ' ',
            'E' if ProgramHeaderFlags.EXECUTE in self else ' ',
        ])


@dataclasses.dataclass(frozen=True)
class ProgramHeader:
    type: ProgramHeaderType
    flags: ProgramHeaderFlags
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    align: int

    @staticmethod
    def read(
        buffer: bytes,
        data_format: DataFormat,
    ) -> Iterator['ProgramHeader']:
        """Read the program header from the specified buffer.

        The buffer must have the size exactly of the header itself."""
        if data_format.bits == ElfClass.ELF64:
            # Fields in the class are in order for Elf64.
            yield from data_format.read_dataclass_values(buffer, ProgramHeader, 'LL6P')
        else:
            # Fields in the class are not in order for Elf32.
            hints = get_type_hints(ProgramHeader)
            fields = ('type', 'offset', 'vaddr', 'paddr', 'filesz', 'memsz', 'flags', 'align')
            arguments = data_format.read_values(
                buffer,
                (hints[f] for f in fields),
                'L5PLP',
            )
            yield from (ProgramHeader(a[0], a[6], a[1], a[2], a[3], a[4], a[5], a[7]) for a in arguments)


#
# Section header.
#
class SectionType(Enum):
    NULL = 0x0  # Section header table entry unused
    PROGBITS = 0x1  # Program data
    SYMTAB = 0x2  # Symbol table
    STRTAB = 0x3  # String table
    RELA = 0x4  # Relocation entries with addends
    HASH = 0x5  # Symbol hash table
    DYNAMIC = 0x6  # Dynamic linking information
    NOTE = 0x7  # Notes
    NOBITS = 0x8  # Program space with no data (bss)
    REL = 0x9  # Relocation entries, no addends
    SHLIB = 0x0A  # Reserved
    DYNSYM = 0x0B  # Dynamic linker symbol table
    INIT_ARRAY = 0x0E  # Array of constructors
    FINI_ARRAY = 0x0F  # Array of destructors
    PREINIT_ARRAY = 0x10  # Array of pre-constructors
    GROUP = 0x11  # Section group
    SYMTAB_SHNDX = 0x12  # Extended section indices
    NUM = 0x13  # Number of defined types.

    # Formally those are OS-specific extensions, not part of SystemV ABI, but
    # readelf defines them unconditionally, whether target is GNU or not.
    GNU_HASH = 0x6ffffff6
    VERDEF = 0x6ffffffd
    VERNEED = 0x6ffffffe
    VERSYM = 0x6fffffff
    GNU_LIBLIST = 0x6ffffff7

    LOOS = 0x60000000  # Start OS-specific.
    HIOS = 0xFFFFFFFF

    @classmethod
    def _missing_(cls, value):
        return _missing_enum_value(cls, value)


class SectionFlags(IntFlag):
    NONE = 0
    WRITE = 0x1  # Writable
    ALLOC = 0x2  # Occupies memory during execution
    EXECINSTR = 0x4  # Executable
    MERGE = 0x10  # Might be merged
    STRINGS = 0x20  # Contains null-terminated strings
    INFO_LINK = 0x40  # 'sh_info' contains SHT index
    LINK_ORDER = 0x80  # Preserve order after combining
    OS_NONCONFORMING = 0x100  # Non-standard OS specific handling required
    GROUP = 0x200  # Section is member of a group
    TLS = 0x400  # Section hold thread-local data
    COMPRESSED = 0x800  # Section containing compressed data
    ORDERED = 0x4000000  # Special ordering requirement (Solaris)
    EXCLUDE = 0x8000000  # Section is excluded unless referenced or allocated (Solaris)

    @classmethod
    def _missing_(cls, value):
        # Can't add those values as class variables, as interpreter gets into
        # some infinite recursion. And if I add them to _ignore_, then they are
        # not available inside of the functions.
        MASKOS = 0x0FF00000
        MASKPROC = 0xF0000000
        if (value & MASKOS == value) or (value & MASKPROC == value):
            obj = int.__new__(cls)
            obj._value_ = value
            obj._name_ = hex(value)
            return obj
        return super()._missing_(value)

    @property
    def summary(self) -> str:
        """Format string in the style of readelf -S option."""
        MASKOS = 0x0FF00000
        MASKPROC = 0xF0000000
        result: list[str] = []
        if SectionFlags.WRITE in self:
            result.append('W')
        if SectionFlags.ALLOC in self:
            result.append('A')
        if SectionFlags.EXECINSTR in self:
            result.append('X')
        if SectionFlags.MERGE in self:
            result.append('M')
        if SectionFlags.STRINGS in self:
            result.append('S')
        if SectionFlags.INFO_LINK in self:
            result.append('I')
        if SectionFlags.LINK_ORDER in self:
            result.append('L')
        if SectionFlags.OS_NONCONFORMING in self:
            result.append('O')
        if SectionFlags.GROUP in self:
            result.append('G')
        if SectionFlags.TLS in self:
            result.append('T')
        if SectionFlags.COMPRESSED in self:
            result.append('C')
        if self.value & MASKOS:
            result.append('o')
        if SectionFlags.EXCLUDE in self:
            result.append('E')
        if self.value & MASKPROC:
            result.append('p')
        return ''.join(result)


@dataclasses.dataclass(frozen=True)
class SectionHeader:
    name_offset: int
    """An offset to a string in the .shstrtab section with the name of this section."""

    type: SectionType
    flags: SectionFlags
    address: int
    offset: int
    size: int
    link: int
    info: int
    address_alignment: int
    entry_size: int

    @staticmethod
    def read(
        buffer: bytes,
        data_format: DataFormat,
    ) -> Iterator['SectionHeader']:
        """Read section headers from the specified buffer."""
        yield from data_format.read_dataclass_values(buffer, SectionHeader, 'LLPPPPLLPP')


#
# String table
#
class StringTable(collections.abc.Iterable[tuple[int, str]]):
    """A representation of a string table section from the ELF file.

    When sections need to reference a variable length string they typically
    store a fixed-size offset in the related string table section. This
    approach is used in various places, for example .shstrtab section contains
    section names and .strtab contains various strings, for example those
    referenced from the .symtab section.

    Reads section from the file once, and stores read data as bytes.
    String table can't be represented as a simple mapping because offsets into
    the table may point into the middle of the string. For example if there are
    strings `name` and `rename` then the table would contain only the `rename`
    and whenever `name` is needed its offset would point into the third
    character of that string.

    Because the table is read once and stored in the memory it may not be
    optimal for cases with large sections that have the size in order of the
    machine's physical memory."""

    _data: bytes
    """The section content."""

    def __init__(
        self,
        stream: BinaryIO,
        string_table_section: SectionHeader,
    ) -> None:
        stream.seek(string_table_section.offset)
        self._data = stream.read(string_table_section.size)
        assert self._data

    def get(self, offset: int) -> str:
        """Get a string from the table starting at the specified offset.

        Regular string sections always start with a '0' code, but .debug_str
        doesn't follow the same rule, hence we can't quick exit for offset == 0."""
        end = self._data.find(b'\x00', offset)
        return self._data[offset:end].decode('ascii')

    def __iter__(self) -> Iterator[tuple[int, str]]:
        start = 1
        while start < len(self._data):
            end = self._data.find(b'\x00', start)
            yield start, self._data[start:end].decode('ascii')
            start = end + 1  # Point to the next string

    def __getitem__(self, offset: int) -> str:
        return self.get(offset)


#
# Symbol table.
#
class SymbolBind(Enum):
    LOCAL = 0
    GLOBAL = 1
    WEAK = 2
    LOPROC = 13
    HIPROC = 15

    @classmethod
    def _missing_(cls, value):
        return _missing_enum_value(cls, value)


class SymbolType(Enum):
    NOTYPE = 0
    OBJECT = 1
    FUNC = 2
    SECTION = 3
    FILE = 4
    LOPROC = 13
    HIPROC = 15

    @classmethod
    def _missing_(cls, value):
        return _missing_enum_value(cls, value)


class SymbolVisibility(Enum):
    DEFAULT = 0
    INTERNAL = 1
    HIDDEN = 2
    PROTECTED = 3


@dataclasses.dataclass(frozen=True)
class SymbolTableEntry:
    name_offset: int
    info: int
    other: int
    section_index: int
    value: int
    size: int
    """The index of the section for which this symbol entry is defined."""

    @staticmethod
    def read(
        buffer: bytes,
        data_format: DataFormat,
    ) -> Iterator['SymbolTableEntry']:
        """Read the symbol table from the specified buffer."""
        if data_format.bits == ElfClass.ELF64:
            # Fields in the class are in order for Elf64.
            yield from data_format.read_dataclass_values(buffer, SymbolTableEntry, 'LBBHPP')
        else:
            # Fields in the class are not in order for Elf32.
            hints = get_type_hints(SymbolTableEntry)
            fields = ('name_offset', 'value', 'size', 'info', 'other', 'section_index')
            arguments = data_format.read_values(
                buffer,
                (hints[f] for f in fields),
                'LPPBBH',
            )
            yield from (SymbolTableEntry(a[0], a[3], a[4], a[5], a[1], a[2]) for a in arguments)

    @property
    def bind(self) -> SymbolBind:
        return SymbolBind(self.info >> 4)

    @property
    def type(self) -> SymbolType:
        return SymbolType(self.info & 0xf)

    @property
    def visibility(self) -> SymbolVisibility:
        return SymbolVisibility(self.other & 0x3)

    @property
    def section_index_name(self) -> str:
        if self.section_index == 0:
            return 'UND'
        elif self.section_index == 0xfff1:
            return 'ABS'
        elif self.section_index == 0xfff2:
            return 'COMMON'
        return str(self.section_index)


#
# Relocations
#
@dataclasses.dataclass(frozen=True)
class RelocationEntry:
    offset: int
    type: int
    symbol_index: int

    def get_info(self, elf_class: ElfClass) -> int:
        if elf_class == ElfClass.ELF64:
            return (self.symbol_index << 32) + self.type
        else:
            return (self.symbol_index << 8) + self.type

    @staticmethod
    def read(
        buffer: bytes,
        data_format: DataFormat,
    ) -> Iterator['RelocationEntry']:
        """Read entries from the provided buffer."""
        if data_format.bits == ElfClass.ELF64:
            raw_values = data_format.read_values(buffer, (int, int), 'PQ')
            yield from (RelocationEntry(a[0], a[1] & 0xFFFFFFFF, a[1] >> 32) for a in raw_values)
        else:
            raw_values = data_format.read_values(buffer, (int, int), 'PL')
            yield from (RelocationEntry(a[0], a[1] & 0xFF, a[1] >> 8) for a in raw_values)


@dataclasses.dataclass(frozen=True)
class RelocationEntryWithAddend(RelocationEntry):
    addend: int

    @staticmethod
    def read(
        buffer: bytes,
        data_format: DataFormat,
    ) -> Iterator['RelocationEntry']:
        """Read entries from the provided buffer."""
        if data_format.bits == ElfClass.ELF64:
            raw_values = data_format.read_values(buffer, (int, int, int), 'PQq')
            yield from (
                RelocationEntryWithAddend(a[0], a[1] & 0xFFFFFFFF, a[1] >> 32, a[2])
                for a in raw_values
            )
        else:
            raw_values = data_format.read_values(buffer, (int, int, int), 'PLl')
            yield from (
                RelocationEntryWithAddend(a[0], a[1] & 0xFF, a[1] >> 8, a[2])
                for a in raw_values
            )


class RelocationTypeI386(IntEnum):
    R_386_NONE = 0
    R_386_32 = 1
    R_386_PC32 = 2
    R_386_GOT32 = 3
    R_386_PLT32 = 4
    R_386_COPY = 5
    R_386_GLOB_DAT = 6
    R_386_JUMP_SLOT = 7
    R_386_RELATIVE = 8
    R_386_GOTOFF = 9
    R_386_GOTPC = 10
    R_386_TLS_TPOFF = 14
    R_386_TLS_IE = 15
    R_386_TLS_GOTIE = 16
    R_386_TLS_LE = 17
    R_386_TLS_GD = 18
    R_386_TLS_LDM = 19
    R_386_16 = 20
    R_386_PC16 = 21
    R_386_8 = 22
    R_386_PC8 = 23
    R_386_TLS_GD_32 = 24
    R_386_TLS_GD_PUSH = 25
    R_386_TLS_GD_CALL = 26
    R_386_TLS_GD_POP = 27
    R_386_TLS_LDM_32 = 28
    R_386_TLS_LDM_PUSH = 29
    R_386_TLS_LDM_CALL = 30
    R_386_TLS_LDM_POP = 31
    R_386_TLS_LDO_32 = 32
    R_386_TLS_IE_32 = 33
    R_386_TLS_LE_32 = 34
    R_386_TLS_DTPMOD32 = 35
    R_386_TLS_DTPOFF32 = 36
    R_386_TLS_TPOFF32 = 37
    R_386_SIZE32 = 38
    R_386_TLS_GOTDESC = 39
    R_386_TLS_DESC_CALL = 40
    R_386_TLS_DESC = 41
    R_386_IRELATIVE = 42


class RelocationTypeAmd64(IntEnum):
    # Comes from https://www.uclibc.org/docs/psABI-x86_64.pdf
    R_X86_64_NONE = 0
    R_X86_64_64 = 1
    R_X86_64_PC32 = 2
    R_X86_64_GOT32 = 3
    R_X86_64_PLT32 = 4
    R_X86_64_COPY = 5
    R_X86_64_GLOB_DAT = 6
    R_X86_64_JUMP_SLOT = 7
    R_X86_64_RELATIVE = 8
    R_X86_64_GOTPCREL = 9
    R_X86_64_32 = 10
    R_X86_64_32S = 11
    R_X86_64_16 = 12
    R_X86_64_PC16 = 13
    R_X86_64_8 = 14
    R_X86_64_PC8 = 15
    R_X86_64_DTPMOD64 = 16
    R_X86_64_DTPOFF64 = 17
    R_X86_64_TPOFF64 = 18
    R_X86_64_TLSGD = 19
    R_X86_64_TLSLD = 20
    R_X86_64_DTPOFF32 = 21
    R_X86_64_GOTTPOFF = 22
    R_X86_64_TPOFF32 = 23
    R_X86_64_PC64 = 24
    R_X86_64_GOTOFF64 = 25
    R_X86_64_GOTPC32 = 26
    R_X86_64_SIZE32 = 32
    R_X86_64_SIZE64 = 33
    R_X86_64_GOTPC32_TLSDESC = 34
    R_X86_64_TLSDESC_CALL = 35
    R_X86_64_TLSDESC = 36
    R_X86_64_IRELATIVE = 37


#
# Dynamic
#
class DynamicEntryFlags(IntFlag):
    ORIGIN = 0x1
    SYMBOLIC = 0x2
    TEXTREL = 0x4
    BIND_NOW = 0x8
    STATIC_TLS = 0x10

    def __str__(self) -> str:
        result: list[str] = []
        vals = DynamicEntryFlags._value2member_map_.values()
        for value in vals:
            if cast(DynamicEntryFlags, value) in self and value.name:
                result.append(value.name)
        return ' '.join(result)


class DynamicEntryFlags1(IntFlag):
    NOW = 0x00000001
    GLOBAL = 0x00000002
    GROUP = 0x00000004
    NODELETE = 0x00000008
    LOADFLTR = 0x00000010
    INITFIRST = 0x00000020
    NOOPEN = 0x00000040
    ORIGIN = 0x00000080
    DIRECT = 0x00000100
    TRANS = 0x00000200
    INTERPOSE = 0x00000400
    NODEFLIB = 0x00000800
    NODUMP = 0x00001000
    CONFALT = 0x00002000
    ENDFILTEE = 0x00004000
    DISPRELDNE = 0x00008000
    DISPRELPND = 0x00010000
    NODIRECT = 0x00020000
    IGNMULDEF = 0x00040000
    NOKSYMS = 0x00080000
    NOHDR = 0x00100000
    EDITED = 0x00200000
    NORELOC = 0x00400000
    SYMINTPOSE = 0x00800000
    GLOBAUDIT = 0x01000000
    SINGLETON = 0x02000000
    STUB = 0x04000000
    PIE = 0x08000000
    KMOD = 0x10000000
    WEAKFILTER = 0x20000000
    NOCOMMON = 0x40000000

    def __str__(self) -> str:
        result: list[str] = []
        vals = DynamicEntryFlags1._value2member_map_.values()
        for value in vals:
            if cast(DynamicEntryFlags1, value) in self and value.name:
                result.append(value.name)
        return ' '.join(result)


class DynamicEntryTag(Enum):
    NULL = 0
    NEEDED = 1
    PLTRELSZ = 2
    PLTGOT = 3
    HASH = 4
    STRTAB = 5
    SYMTAB = 6
    RELA = 7
    RELASZ = 8
    RELAENT = 9
    STRSZ = 10
    SYMENT = 11
    INIT = 12
    FINI = 13
    SONAME = 14
    RPATH = 15
    SYMBOLIC = 16
    REL = 17
    RELSZ = 18
    RELENT = 19
    PLTREL = 20
    DEBUG = 21
    TEXTREL = 22
    JMPREL = 23
    BIND_NOW = 24
    INIT_ARRAY = 25
    FINI_ARRAY = 26
    INIT_ARRAYSZ = 27
    FINI_ARRAYSZ = 28
    RUNPATH = 29
    FLAGS = 30
    ENCODING = 32
    PREINIT_ARRAY = 32
    PREINIT_ARRAYSZ = 33
    SYMTAB_SHNDX = 34
    GNU_HASH = 0x6ffffef5
    VERSYM = 0x6ffffff0
    RELACOUNT = 0x6ffffff9
    RELCOUNT = 0x6ffffffa
    FLAGS_1 = 0x6ffffffb
    VERNEED = 0x6ffffffe
    VERNEEDNUM = 0x6fffffff

    LOOS = 0x6000000D
    HIOS = 0x6ffff000
    LOPROC = 0x70000000
    HIPROC = 0x7fffffff

    @classmethod
    def _missing_(cls, value):
        return _missing_enum_value(cls, value)


@dataclasses.dataclass(frozen=True)
class DynamicEntry:
    tag: DynamicEntryTag
    value: int

    @staticmethod
    def read(
        buffer: bytes,
        data_format: DataFormat,
    ) -> Iterator['DynamicEntry']:
        """Read dynamic entries from the specified buffer."""
        yield from data_format.read_dataclass_values(buffer, DynamicEntry, 'PP')


#
# Verion information.
#
class VersionFlags(IntFlag):
    BASE = 1
    WEAK = 2
    INFO = 4

    def __str__(self) -> str:
        result: list[str] = []
        vals = VersionFlags._value2member_map_.values()
        for value in vals:
            if cast(VersionFlags, value) in self and value.name:
                result.append(value.name)
        return ' | '.join(result) if result else 'none'


@dataclasses.dataclass(frozen=True)
class VersionNeededEntry:
    version: int
    """Version of structure. This value is currently set to 1."""
    cnt: int
    """Number of associated verneed aux array entries."""
    file: int
    """Offset to the file name string in the section header, in bytes."""
    aux: int
    """Offset to a corresponding entry in the vernaux array, in bytes."""
    next: int
    """Offset to the next verneed entry, in bytes."""

    @staticmethod
    def read(
        buffer: bytes,
        data_format: DataFormat,
    ) -> Iterator[tuple[int, 'VersionNeededEntry']]:
        """Read version needed entries from the buffer.

        Returns a iteartor over tuples, where first value of the tuple is the
        entry offset, and second value is the entry itself. Note that this
        differs from most of the other `read` functions which don't return
        offset, but this function has to, due to how it the result is being
        used."""
        format_string = 'HHLLL'
        start = 0
        sz = data_format.calc_size(format_string)
        while True:
            end = start + sz
            entry = data_format.read_dataclass_value(
                buffer[start:end],
                VersionNeededEntry,
                format_string,
            )
            yield start, entry
            if entry.next == 0:
                return
            start += entry.next


@dataclasses.dataclass(frozen=True)
class VersionNeededAuxEntry:
    hash: int
    """Dependency name hash value (ELF hash function)."""
    flags: VersionFlags
    """Dependency information flag bitmask."""
    other: int
    """Object file version identifier used in the .gnu.version symbol version
    array. Bit number 15 controls whether or not the object is hidden; if this
    bit is set, the object cannot be used and the static linker will ignore the
    symbol's presence in the object."""
    name: int
    """Offset to the dependency name string in the section header, in bytes."""
    next: int
    """Offset to the next vernaux entry, in bytes."""

    @staticmethod
    def read(
        buffer: bytes,
        offset: int,
        data_format: DataFormat,
    ) -> Iterator[tuple[int, 'VersionNeededAuxEntry']]:
        """Read version needed aux entries from the buffer.

        :param offset: An offset where to start parsing AUX entries.

        :return: a iteartor over tuples, where first value of the tuple is the
        entry offset, and second value is the entry itself. Note that this
        differs from most of the other `read` functions which don't return
        offset, but this function has to, due to how it the result is being
        used."""
        format_string = 'LHHLL'
        sz = data_format.calc_size(format_string)
        while True:
            end = offset + sz
            vna = data_format.read_dataclass_value(
                buffer[offset:end],
                VersionNeededAuxEntry,
                format_string
            )
            yield offset, vna
            if vna.next == 0:
                return
            offset += vna.next


@dataclasses.dataclass(frozen=True)
class VersionNeededAux:
    raw_entry: VersionNeededAuxEntry
    """Raw data entry."""
    name: str
    flags: VersionFlags
    version: int
    hidden: bool
    hash: int
    offset: int


@dataclasses.dataclass(frozen=True)
class VersionNeeded:
    file_entry: VersionNeededEntry
    """Raw data entry."""
    version: int
    file: str
    aux: Sequence[VersionNeededAux]
    count: int
    offset: int


def _version_table(entries: Iterable[VersionNeeded]) -> Iterator[tuple[int, VersionNeededAux]]:
    """Convert a sequence of verneed entries to a mapping of version number to
    a verneed_aux value."""
    for vn in entries:
        yield from ((vna.version, vna) for vna in vn.aux)


#
# ELF container
#
class Section(NamedTuple):
    number: int
    name: str
    header: SectionHeader


class Symbol(NamedTuple):
    number: int
    name: str
    entry: SymbolTableEntry
    version_info: VersionNeededAux | None = None
    """Optional version information for this symbol.

    Available only if there is a VERSYM section corresponding to the symbol's
    section and defined version is not 0 or 1 (local and global)."""

    @property
    def full_name(self) -> str:
        if self.version_info:
            return f'{self.name}@{self.version_info.name}'
        return self.name


class Relocation(NamedTuple):
    relocation: RelocationEntry | RelocationEntryWithAddend
    symbol: Symbol | None


class Elf:
    @staticmethod
    def _read_program_headers(
        stream: BinaryIO,
        elf_header: ElfHeader,
    ) -> Iterator['ProgramHeader']:
        """Read program headers from the stream and parse them.

        State of the stream's cursor will change during the function execution."""
        pheader_count = elf_header.program_header_entries
        pheader_size = elf_header.program_header_size

        stream.seek(elf_header.program_header_offset)
        data = stream.read(pheader_size * pheader_count)
        yield from ProgramHeader.read(data, elf_header.data_format)

    @staticmethod
    def _read_section_headers(
        stream: BinaryIO,
        elf_header: ElfHeader,
    ) -> Iterator['SectionHeader']:
        """Read section headers from the stream and parse them.

        State of the stream cursor will change during the function execution."""
        section_header_count = elf_header.section_header_entries
        section_header_size = elf_header.section_header_size

        stream.seek(elf_header.section_header_offset)
        data = stream.read(section_header_count * section_header_size)
        yield from SectionHeader.read(data, elf_header.data_format)

    def __init__(self, stream: BinaryIO) -> None:
        self.__stream = stream
        self.file_header = ElfHeader.read_elf_header(stream)
        # In theory we could have done a lazy read for those sections, but in
        # practice I see little reason to complicate the code - the only
        # scenario when program and section headers are not needed is when only
        # the file header is printed.
        self.program_headers = tuple(Elf._read_program_headers(stream, self.file_header))
        self.section_headers = tuple(Elf._read_section_headers(stream, self.file_header))

        # Sections names. I wander how realistic it is to have a file without
        # such section? Anyway, though, this library is not supposed to cover
        # every possible case.
        name_table = StringTable(
            stream,
            self.section_headers[self.file_header.section_header_names_index],
        )
        self.section_names = tuple(name_table[s.name_offset] for s in self.section_headers)

    file_header: ElfHeader
    program_headers: Sequence[ProgramHeader]
    section_headers: Sequence[SectionHeader]
    section_names: Sequence[str]

    @property
    def sections(self) -> Iterable[Section]:
        return (Section(nr, n, h) for nr, n, h in zip(
            range(len(self.section_headers)),
            self.section_names,
            self.section_headers,
        ))

    @property
    def elf_class(self) -> ElfClass:
        return self.file_header.elf_class

    @property
    def data_format(self) -> DataFormat:
        return self.file_header.data_format

    def section_number(self, section_name_or_num: str) -> int:
        """Convert section name or number to a number.

        :param section_name_or_num: Can be either a section name or a number.
        :returns: The number of the specified section."""
        if section_name_or_num.isnumeric():
            return int(section_name_or_num)
        for num, s in enumerate(self.section_names):
            if s == section_name_or_num:
                return num
        raise ValueError(f'Unknown section name `{section_name_or_num}`')

    def strings(self, section_number: int) -> StringTable:
        return StringTable(self.__stream, self.section_headers[section_number])

    def symbols(self, section_number: int) -> Iterable[Symbol]:
        section = self.section_headers[section_number]
        name_section = self.section_headers[section.link]
        name_table = StringTable(self.__stream, name_section)
        syms = SymbolTableEntry.read(self.section_content(section_number), self.data_format)
        # Is there a VERSYM section that links to this section?
        versym_sh = next((
            s.number for s in self.sections
            if s.header.type == SectionType.VERSYM and s.header.link == section_number
        ), None)
        versions = self.symbol_versions(versym_sh) if versym_sh else itertools.repeat((0, None))

        for num, symbol, version_info in zip(itertools.count(), syms, versions):
            yield Symbol(num, name_table[symbol.name_offset], symbol, version_info[1])

    def relocations(self, section_number: int) -> Iterable[Relocation]:
        section = self.section_headers[section_number]
        assert section.type in (SectionType.REL, SectionType.RELA)
        # Has to provide explicit types to avoid errors from mypy.
        rtype: type[RelocationEntry] | type[RelocationEntryWithAddend] = (
            RelocationEntry if section.type == SectionType.REL else RelocationEntryWithAddend
        )
        symbols = list(self.symbols(section.link)) if section.link else None

        def get_symbol(index: int) -> Symbol | None:
            if symbols and index:
                return symbols[index]
            return None

        relocations: Iterable[RelocationEntry] = rtype.read(
            self.section_content(section_number),
            self.data_format,
        )
        yield from (Relocation(reloc, get_symbol(reloc.symbol_index)) for reloc in relocations)

    def relocation_type(self, rel: RelocationEntry) -> IntEnum:
        """Return a machine-specific relocation type value."""
        rel_types = {
            ElfMachineType.EM_386: RelocationTypeI386,
        }
        rela_types = {
            ElfMachineType.EM_X86_64: RelocationTypeAmd64,
        }
        if isinstance(rel, RelocationEntryWithAddend):
            return rela_types[self.file_header.machine](rel.type)
        return rel_types[self.file_header.machine](rel.type)

    @property
    def dynamic_info(self) -> Iterator[DynamicEntry]:
        prev: DynamicEntry | None = None
        # Data can contain multiple NULLs in the end.
        for section in self.sections_of_type(SectionType.DYNAMIC):
            for e in DynamicEntry.read(self.section_content(section.number), self.data_format):
                if e.tag == DynamicEntryTag.NULL and prev and e.tag == prev.tag:
                    break
                yield e
                prev = e

    @property
    def version_needed(self) -> Iterator[VersionNeeded]:
        # The section shall contain an array of Elfxx_Verneed structures,
        # optionally followed by an array of Elfxx_Vernaux structures.
        # Although formally there is no reason why those would be arrays:
        # presence of `next` field allows this to be effectively a linked list.
        section = next(self.sections_of_type(SectionType.VERNEED))
        data = self.section_content(section.number)
        names = self.strings(section.header.link)

        for offset, vn in VersionNeededEntry.read(data, self.data_format):
            aux_start = offset + vn.aux
            vna_list = tuple(
                VersionNeededAux(
                    vna,
                    names[vna.name],
                    vna.flags,
                    vna.other & 0x7fff,
                    bool(vna.other & 0x8000),
                    vna.hash,
                    aux_offset,
                )
                for aux_offset, vna in VersionNeededAuxEntry.read(data, aux_start, self.data_format)
            )
            yield VersionNeeded(
                vn,
                vn.version,
                names[vn.file],
                vna_list,
                vn.cnt,
                offset,
            )

    def symbol_versions(
        self,
        section_number: int,
    ) -> Iterator[tuple[int, VersionNeededAux | None]]:
        """Return version information for a symbol.

        Returns an iterator over tuple. First item in the tuple is the version
        information number (values stored in the versym section). Second item
        is the related VersionNeededAux entry for this version number. The
        second item may be none, since version values 0 and 1 has no such entry."""
        version_info_map = dict(_version_table(self.version_needed))
        section_header = self.section_headers[section_number]
        data = self.section_content(section_number)
        count = section_header.size // section_header.entry_size
        for index in range(count):
            start_byte = index * 2 + 1
            end_byte = index * 2 - 1 if index > 0 else None
            value = int(bytes.hex(data[start_byte:end_byte:-1]), 16)
            yield value, version_info_map.get(value, None)

    def read(self, offset: int, size: int) -> bytes:
        """Return the content of the file at specified offset."""
        self.__stream.seek(offset)
        return self.__stream.read(size)

    def section_content(self, section_number: int) -> bytes:
        """Return content of the specified section as bytes."""
        section = self.section_headers[section_number]
        return self.read(section.offset, section.size)

    def sections_of_type(self, shtype: SectionType) -> Iterator[Section]:
        for s in self.sections:
            if s.header.type == shtype:
                yield s
        return
