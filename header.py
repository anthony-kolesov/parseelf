"""Helper module to deal with data classes representing ELF headers."""

__all__ = [
    # Constants.
    'ADDRESS',
    'HIDDEN',
    'SIZE',
    # Classes.
    'ElfClass',
    # Functions.
    'field_size',
    'meta',
    'parse_value',
]

from dataclasses import Field, fields
from enum import Enum
from typing import Any, Type, TypeVar

ADDRESS = 'address'
HIDDEN = 'hidden'
SIZE = 'size'


_T = TypeVar('_T')


class ElfClass(Enum):
    ELF32 = 1
    ELF64 = 2


def field_size(field: Field, elf_class: ElfClass) -> int:
    """Evaluate size of the field."""
    if field.metadata.get(ADDRESS, False):
        return (4 if elf_class == ElfClass.ELF32 else 8)
    return field.metadata.get(SIZE, 1)


def meta(*, size=1, address=False, hidden=False) -> dict[str, Any]:
    """Return a field metadata with specified parameters.

    This function is just an annotated factory for dictionaries.
    Note that if `address` is set to true, then value of `size` is
    meaningless."""
    return {
        HIDDEN: hidden,
        ADDRESS: address,
        SIZE: size,
    }


def parse_header(
    header_bytes: bytes,
    header_type: Type[_T],
    elf_class: ElfClass,
) -> _T:
    kwargs: dict[str, Any] = {}
    start = 0
    for field in fields(header_type):
        end = start + field_size(field, elf_class)
        kwargs[field.name] = parse_value(field, header_bytes[start:end])
        start = end

    return header_type(**kwargs)


def parse_value(field: Field, stream: bytes) -> Any:
    """Parse a field value from a byte stream."""
    # If target type is string or bytes just convert to a hex representation.
    # Note that this is done for `bytes` as well, so they are stored as string
    # representations as well.
    if issubclass(field.type, (str, bytes)):
        return bytes.hex(stream)
    else:
        # Integer type, convert bytes to int.
        # This is an easy but not optimal way - convert bytes to a hext string
        # and then parse integer from the string.
        # Note that bytes come little endian, hence have to be reversed.
        # TODO: It seems to me that for big endiand targets the data will be
        # big endian as well? If so the function would have to accept
        # endianness as an argument. For now I only care about little endian
        # targets.
        return field.type(int(bytes.hex(stream[::-1]), 16))
