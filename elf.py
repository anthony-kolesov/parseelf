# Copyright (c) 2022 Anton Kolesov
# SPDX-License-Identifier: MIT

"""Classes specific to parsing of ELF files.

For documentation see http://www.sco.com/developers/gabi/latest/contents.html."""

__all__ = [
    'Endianness',
    'ElfOsAbi',
    'ElfType',
    'ElfMachineType',
    'ElfHeader',
    'ProgramHeaderType',
    'read_program_headers',
    'SectionType',
    'SectionFlags',
    'SectionHeader',
    'read_section_headers',
    'StringTable',
    'SymbolTableEntry',
    'Section',
    'Symbol',
    'Elf',
    'read_table_section',
]

import collections.abc
import dataclasses
from enum import Enum, IntEnum, IntFlag
from typing import BinaryIO, cast, get_type_hints, Iterable, Iterator, NamedTuple, Sequence, TypeVar

import header
from header import ElfClass, Field


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


#
# ELF header.
#
class Endianness(Enum):
    description: str
    "Text description of this endianness type."

    def __new__(cls, value, description):
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
    _pad1: bytes
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

    @classmethod
    def get_layout(cls, elf_class: ElfClass) -> Iterable[Field]:
        hints = get_type_hints(cls)
        return (
            Field.with_hint('magic', hints, 4),
            Field.with_hint('elf_class', hints, 1),
            Field.with_hint('endiannes', hints, 1),
            Field.with_hint('version', hints, 1),
            Field.with_hint('osabi', hints, 1),
            Field.with_hint('abiversion', hints, 1),
            Field.with_hint('_pad1', hints, 7),
            Field.with_hint('objectType', hints, 2),
            Field.with_hint('machine', hints, 2),
            Field.with_hint('version2', hints, 4),
            Field.with_hint('entry', hints, elf_class.address_size),
            Field.with_hint('program_header_offset', hints, elf_class.address_size),
            Field.with_hint('section_header_offset', hints, elf_class.address_size),
            Field.with_hint('flags', hints, 4),
            Field.with_hint('elf_header_size', hints, 2),
            Field.with_hint('program_header_size', hints, 2),
            Field.with_hint('program_header_entries', hints, 2),
            Field.with_hint('section_header_size', hints, 2),
            Field.with_hint('section_header_entries', hints, 2),
            Field.with_hint('section_header_names_index', hints, 2),
        )

    @staticmethod
    def get_elf_class(header_bytes: bytes) -> ElfClass:
        """Check ELF magic bytes and retrieve ELF class.

        ELF class is quite important because it affects the size of
        address-sized fields and sometimes the layout of the header, therefore
        it is parsed before the headers themself."""
        assert len(header_bytes) >= 5

        if header_bytes[:4] != bytes.fromhex('7f 45 4c 46'):
            raise ValueError('The input stream is not a valid ELF file.')
        return ElfClass(header_bytes[4])

    @staticmethod
    def parse_elf_header(header_bytes: bytes) -> 'ElfHeader':
        """Parse an ELF header from a given bytes from the file."""
        # ELF class is a special case needed to properly parse address fields.
        elf_class = ElfHeader.get_elf_class(header_bytes)
        return header.parse_struct(header_bytes, ElfHeader, elf_class)

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

    @classmethod
    def get_layout(cls, elf_class: ElfClass) -> Iterable[Field]:
        hints = get_type_hints(cls)
        type = Field.with_hint('type', hints, 4)
        flags = Field.with_hint('flags', hints, 4)
        offset = Field.with_hint('offset', hints, elf_class.address_size)
        vaddr = Field.with_hint('vaddr', hints, elf_class.address_size)
        paddr = Field.with_hint('paddr', hints, elf_class.address_size)
        filesz = Field.with_hint('filesz', hints, elf_class.address_size)
        memsz = Field.with_hint('memsz', hints, elf_class.address_size)
        align = Field.with_hint('align', hints, elf_class.address_size)
        if elf_class == ElfClass.ELF64:
            return (
                type,
                flags,
                offset,
                vaddr,
                paddr,
                filesz,
                memsz,
                align,
            )
        else:
            return (
                type,
                offset,
                vaddr,
                paddr,
                filesz,
                memsz,
                flags,
                align,
            )


def read_program_headers(
    stream: BinaryIO,
    elf_header: ElfHeader,
) -> Iterator[ProgramHeader]:
    """Read program headers from the stream and parse them.

    State of the stream cursor can change during the function execution."""
    pheader_count = elf_header.program_header_entries
    pheader_size = elf_header.program_header_size

    stream.seek(elf_header.program_header_offset)
    data = stream.read(pheader_size * pheader_count)
    for cnt in range(pheader_count):
        start = pheader_size * cnt
        end = start + pheader_size
        yield header.parse_struct(data[start:end], ProgramHeader, elf_header.elf_class)


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

    @classmethod
    def get_layout(cls, elf_class: ElfClass) -> Iterable[Field]:
        hints = get_type_hints(cls)
        return (
            Field.with_hint('name_offset', hints, 4),
            Field.with_hint('type', hints, 4),
            Field.with_hint('flags', hints, elf_class.address_size),
            Field.with_hint('address', hints, elf_class.address_size),
            Field.with_hint('offset', hints, elf_class.address_size),
            Field.with_hint('size', hints, elf_class.address_size),
            Field.with_hint('link', hints, 4),
            Field.with_hint('info', hints, 4),
            Field.with_hint('address_alignment', hints, elf_class.address_size),
            Field.with_hint('entry_size', hints, elf_class.address_size),
        )


def read_section_headers(
    stream: BinaryIO,
    elf_header: ElfHeader,
) -> Iterator[SectionHeader]:
    """Read section headers from the stream and parse them.

    State of the stream cursor can change during the function execution."""
    section_header_count = elf_header.section_header_entries
    section_header_size = elf_header.section_header_size

    stream.seek(elf_header.section_header_offset)
    data = stream.read(section_header_count * section_header_size)
    for cnt in range(section_header_count):
        start = section_header_size * cnt
        end = start + section_header_size
        yield header.parse_struct(data[start:end], SectionHeader, elf_header.elf_class)


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
        assert self._data and self._data[0] == 0

    def get(self, offset: int) -> str:
        """Get a string from the table starting at the specified offset."""
        if offset == 0:
            return ''

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
    value: int
    size: int
    info: int
    other: int
    section_index: int
    """The index of the section for which this symbol entry is defined."""

    @classmethod
    def get_layout(cls, elf_class: ElfClass) -> Iterable[Field]:
        hints = get_type_hints(cls)
        name_offset = Field.with_hint('name_offset', hints, 4)
        value = Field.with_hint('value', hints, elf_class.address_size)
        size = Field.with_hint('size', hints, elf_class.address_size)
        info = Field.with_hint('info', hints, 1)
        other = Field.with_hint('other', hints, 1)
        section_index = Field.with_hint('section_index', hints, 2)
        if elf_class == ElfClass.ELF64:
            return (
                name_offset,
                info,
                other,
                section_index,
                value,
                size,
            )
        else:
            return (
                name_offset,
                value,
                size,
                info,
                other,
                section_index,
            )

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

    @classmethod
    def get_layout(cls, elf_class: ElfClass) -> Iterable[Field]:
        hints = get_type_hints(cls)
        # This approach surely will not work for big endian targets, because
        # offset is the least significant byte of `info`, so it's location
        # changes depending on the endianness.
        offset = Field.with_hint('offset', hints, elf_class.address_size)
        if elf_class == ElfClass.ELF64:
            return (
                offset,
                Field.with_hint('type', hints, 4),
                Field.with_hint('symbol_index', hints, 4),
            )
        else:
            return (
                offset,
                Field.with_hint('type', hints, 1),
                Field.with_hint('symbol_index', hints, 3),
            )


@dataclasses.dataclass(frozen=True)
class RelocationEntryWithAddend(RelocationEntry):
    addend: int

    @classmethod
    def get_layout(cls, elf_class: ElfClass) -> Iterable[Field]:
        hints = get_type_hints(cls)
        return (
            *super().get_layout(elf_class),
            Field.with_hint('addend', hints, elf_class.address_size),
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

    @classmethod
    def get_layout(cls, elf_class: ElfClass) -> Iterable[Field]:
        hints = get_type_hints(cls)
        return (
            Field.with_hint('tag', hints, elf_class.address_size),
            Field.with_hint('value', hints, elf_class.address_size),
        )


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


class Relocation(NamedTuple):
    relocation: RelocationEntry | RelocationEntryWithAddend
    symbol: Symbol | None


class Elf:
    def __init__(self, stream: BinaryIO) -> None:
        self.__stream = stream
        self.file_header = ElfHeader.read_elf_header(stream)
        # In theory we could have done a lazy read for those sections, but in
        # practice I see little reason to complicate the code - the only
        # scenario when program and section headers are not needed is when only
        # the file header is printed.
        self.program_headers = tuple(read_program_headers(stream, self.file_header))
        self.section_headers = tuple(read_section_headers(stream, self.file_header))

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
        syms = read_table_section(
            self.__stream,
            section,
            SymbolTableEntry,
            self.elf_class,
        )
        for num, symbol in enumerate(syms):
            yield Symbol(num, name_table[symbol.name_offset], symbol)

    def relocations(self, section_number: int) -> Iterable[Relocation]:
        section = self.section_headers[section_number]
        assert section.type in (SectionType.REL, SectionType.RELA)
        rtype = RelocationEntry if section.type == SectionType.REL else RelocationEntryWithAddend
        symbols = list(self.symbols(section.link)) if section.link else None

        def get_symbol(index: int) -> Symbol | None:
            if symbols and index:
                return symbols[index]
            return None

        relocations: Iterable[RelocationEntry] = read_table_section(
            self.__stream,
            section,
            rtype,
            self.elf_class,
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
            for e in read_table_section(self.__stream, section.header, DynamicEntry, self.elf_class):
                if e.tag == DynamicEntryTag.NULL and prev and e.tag == prev.tag:
                    break
                yield e
                prev = e

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


_T_struct = TypeVar('_T_struct', bound=header.Struct)


def read_table_section(
    stream: BinaryIO,
    section: SectionHeader,
    entity_type: type[_T_struct],
    elf_class: ElfClass,
) -> Iterator[_T_struct]:
    """Read the section of some strcutured entities of fixed size.

    This function only works for sections with non-zero entity size."""
    # Read the section.
    stream.seek(section.offset)
    data = stream.read(section.size)

    # Validate entity size
    assert section.entry_size != 0
    assert section.entry_size == sum(f.size for f in entity_type.get_layout(elf_class))
    assert section.size % section.entry_size == 0

    start = 0
    while start < len(data):
        end = start + section.entry_size
        yield header.parse_struct(data[start:end], entity_type, elf_class)
        start = end
