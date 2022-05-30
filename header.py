# Copyright (c) 2022 Anton Kolesov
# SPDX-License-Identifier: MIT

"""Helper module to deal with data classes representing ELF headers."""

__all__ = [
    # Classes.
    'ElfClass',
    # Functions.
    'parse_int_le',
    'align_up',
    'parse_cstring',
]

from enum import Enum


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


def parse_int_le(stream: bytes) -> int:
    """Parse little-endian integer from a byte stream."""
    # This is an easy but not optimal way - convert bytes to a hex string
    # and then parse integer from the string.
    # Note that bytes come little endian, hence have to be reversed.
    # TODO: It seems to me that for big endian targets the data will be
    # big endian as well? If so the function would have to accept
    # endianness as an argument. For now I only care about little endian
    # targets.
    return int(stream[::-1].hex(), 16)


def align_up(value: int, alignment: int) -> int:
    """Align value up to the address alignment."""
    div, mod = divmod(value, alignment)
    if mod == 0:
        return value  # Already aligned.
    return alignment * (div + 1)


def parse_cstring(stream: bytes, offset: int = 0) -> str:
    """Parse zero-terminated string from bytes."""
    end = stream.find(b'\x00', offset)
    return stream[offset:end].decode('ascii')
