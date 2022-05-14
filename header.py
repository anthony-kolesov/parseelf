# Copyright (c) 2022 Anton Kolesov
# SPDX-License-Identifier: MIT

"""Helper module to deal with data classes representing ELF headers."""

__all__ = [
    # Classes.
    'ElfClass',
    'Field',
    'Struct',
    # Functions.
    'parse_struct',
]

import dataclasses
from enum import Enum
from typing import Any, Iterable, Protocol, Type, TypeVar


class ElfClass(Enum):
    ELF32 = 1
    ELF64 = 2

    address_size: int
    """Amount of bytes needed to represent address for this ELF class."""
    address_string_width: int
    "Amount of characters needed to represent the address in hex format."""
    address_format: str
    "The string format to represent the address (without `0x`)."""

    def __init__(self, value: int) -> None:
        self.address_size = 4 * value
        self.address_string_width = self.address_size * 2
        self.address_format = f'0{self.address_string_width}x'


@dataclasses.dataclass(frozen=True)
class Field:
    """A field of a structured class."""
    name: str
    type: Type
    size: int

    @staticmethod
    def with_hint(name: str, type_hints: dict[str, Any], size: int) -> 'Field':
        """Construct a new Field isntance using the provided type hint mapping.

        The only purpose of this function is to reduce name repetition and replace code like:
            Field('value', type_hints['value'], 4)
        with:
            Field.with_hint('value', type_hints, 4)"""
        return Field(name, type_hints[name], size)


class Struct(Protocol):
    @classmethod
    def get_layout(cls, elf_class: ElfClass) -> Iterable[Field]:
        ...


_T_struct = TypeVar('_T_struct', bound=Struct)


def _parse_value(field_type: Type, stream: bytes) -> Any:
    """Parse a field value from a byte stream."""
    # If target type is string or bytes just convert to a hex representation.
    # Note that this is done for `bytes` as well, so they are stored as string
    # representations as well.
    if issubclass(field_type, (str, bytes)):
        return bytes.hex(stream)
    else:
        # Integer type, convert bytes to int.
        # This is an easy but not optimal way - convert bytes to a hex string
        # and then parse integer from the string.
        # Note that bytes come little endian, hence have to be reversed.
        # TODO: It seems to me that for big endian targets the data will be
        # big endian as well? If so the function would have to accept
        # endianness as an argument. For now I only care about little endian
        # targets.
        return field_type(int(bytes.hex(stream[::-1]), 16))


def parse_struct(
    header_bytes: bytes,
    header_type: type[_T_struct],
    elf_class: ElfClass,
) -> _T_struct:
    """Parse fields for an object of a structured class and return a new instance of the class."""
    layout: Iterable[Field] = header_type.get_layout(elf_class)
    kwargs: dict[str, Any] = {}
    start = 0
    for field in layout:
        end = start + field.size
        kwargs[field.name] = _parse_value(field.type, header_bytes[start:end])
        start = end
    return header_type(**kwargs)
