"""Helper module to deal with data classes representing ELF headers."""

__all__ = [
    # Constants.
    'ADDRESS',
    'HIDDEN',
    'SIZE',
    # Functions.
    'meta',
]

from typing import Any

ADDRESS = 'address'
HIDDEN = 'hidden'
SIZE = 'size'


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
