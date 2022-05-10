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
]

from dataclasses import Field
from enum import Enum
from typing import Any

ADDRESS = 'address'
HIDDEN = 'hidden'
SIZE = 'size'


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
