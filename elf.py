"""Classes specific to parsing of ELF files."""

__all__ = [
    # Classes.
    'Endianness',
    'ElfOsAbi',
    'ElfType',
    'ElfMachineType',
    'ElfHeader',
    'ProgramHeaderType',
    'ProgramHeader32',
    'ProgramHeader64',
    'get_program_header_type'
]

import dataclasses
from enum import Enum
from typing import BinaryIO, Type

import header
from header import ElfClass


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
# ELF header types
#
class Endianness(Enum):
    LITTLE = 1
    BIG = 2


class ElfOsAbi(Enum):
    SYSTEMV = 0
    HPUX = 1
    NETBSD = 2
    GNU = 3
    LINUX = 3
    SOLARIS = 4
    AIX = 5
    IRIX = 6
    FREEBSD = 7
    TRU64 = 10
    MODESTO = 11
    OPENBSD = 12
    OPENVMS = 13
    NSK = 14
    AROS = 15
    FENIXOS = 16
    CLOUDABI = 17
    OPENVOS = 18
    C6000_ELFABI = 64
    C6000_LINUX = 65
    ARM_FDPIC = 65
    ARM = 97
    STANDALONE = 255


class ElfType(Enum):
    NONE = 0
    REL = 1
    EXEC = 2
    DYN = 3
    CORE = 4
    LOOS = 0xFE00
    HIOS = 0xFEFF
    LOPROC = 0xFF00
    HIPROC = 0xFFFF

    @classmethod
    def _missing_(cls, value):
        return _missing_enum_value(cls, value)


class ElfMachineType(Enum):
    # This list comes from binutils/include/elf.h file.
    EM_NONE = 0  # No machine
    EM_M32 = 1  # AT&T WE 32100
    EM_SPARC = 2  # SUN SPARC
    EM_386 = 3  # Intel 80386
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
    EM_X86_64 = 62  # Advanced Micro Devices X86-64 processor
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
    EM_ARC_COMPACT2 = 195  # Synopsys ARCompact V2
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
    magic: str = dataclasses.field(metadata=header.meta(size=4))  # offset = 0
    elf_class: ElfClass  # offset = 4
    endiannes: Endianness  # offset = 5
    version: int  # offset = 6
    osabi: ElfOsAbi  # offset = 7
    abiversion: int  # offset = 8
    _pad1: bytes = dataclasses.field(metadata=header.meta(size=7, hidden=True))  # offset = 9
    objectType: ElfType = dataclasses.field(metadata=header.meta(size=2))  # offset = 0x10
    machine: ElfMachineType = dataclasses.field(metadata=header.meta(size=2))  # offset = 0x12
    version2: int = dataclasses.field(metadata=header.meta(size=4))  # offset = 0x14
    entry: int = dataclasses.field(metadata=header.meta(address=True))
    program_header_offset: int = dataclasses.field(metadata=header.meta(address=True))
    section_header_offset: int = dataclasses.field(metadata=header.meta(address=True))
    flags: int = dataclasses.field(metadata=header.meta(size=4))
    elf_header_size: int = dataclasses.field(metadata=header.meta(size=2))  # Size of this header.
    program_header_size: int = dataclasses.field(metadata=header.meta(size=2))
    program_header_entries: int = dataclasses.field(metadata=header.meta(size=2))
    section_header_size: int = dataclasses.field(metadata=header.meta(size=2))
    section_header_entries: int = dataclasses.field(metadata=header.meta(size=2))
    section_header_names_index: int = dataclasses.field(metadata=header.meta(size=2))

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
        return header.parse_header(header_bytes, ElfHeader, elf_class)

    @staticmethod
    def read_elf_header(stream: BinaryIO) -> 'ElfHeader':
        """Read ELF header from a binary stream.

        Unlike `parse_elf_header` this function reads data from a stream, and
        thus changes current state of the input stream."""
        stream.seek(0)
        elf_header_bytes = stream.read(64)
        return ElfHeader.parse_elf_header(elf_header_bytes)


#
# Program header types.
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
    LOOS = 0x60000000  # Reserved inclusive range. Operating system specific.
    HIOS = 0x6FFFFFFF
    LOPROC = 0x70000000  # Reserved inclusive range. Processor specific.
    HIPROC = 0x7FFFFFFF

    @classmethod
    def _missing_(cls, value):
        return _missing_enum_value(cls, value)


# Program headers for 32 and 64 bit ELFs have different order of fields.
@dataclasses.dataclass(frozen=True)
class ProgramHeader32:
    type: ProgramHeaderType = dataclasses.field(metadata=header.meta(size=4))
    offset: int = dataclasses.field(metadata=header.meta(address=True))
    vaddr: int = dataclasses.field(metadata=header.meta(address=True))
    paddr: int = dataclasses.field(metadata=header.meta(address=True))
    filesz: int = dataclasses.field(metadata=header.meta(address=True))
    memsz: int = dataclasses.field(metadata=header.meta(address=True))
    flags: int = dataclasses.field(metadata=header.meta(size=4))
    align: int = dataclasses.field(metadata=header.meta(address=True))


@dataclasses.dataclass(frozen=True)
class ProgramHeader64:
    type: ProgramHeaderType = dataclasses.field(metadata=header.meta(size=4))
    flags: int = dataclasses.field(metadata=header.meta(size=4))
    offset: int = dataclasses.field(metadata=header.meta(address=True))
    vaddr: int = dataclasses.field(metadata=header.meta(address=True))
    paddr: int = dataclasses.field(metadata=header.meta(address=True))
    filesz: int = dataclasses.field(metadata=header.meta(address=True))
    memsz: int = dataclasses.field(metadata=header.meta(address=True))
    align: int = dataclasses.field(metadata=header.meta(address=True))


def get_program_header_type(elf_class: ElfClass) -> Type[ProgramHeader32] | Type[ProgramHeader64]:
    return ProgramHeader64 if elf_class == ElfClass.ELF64 else ProgramHeader32
