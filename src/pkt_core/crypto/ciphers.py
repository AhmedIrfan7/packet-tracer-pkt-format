"""Block-cipher backends.

The container needs exactly one primitive from the cipher: *encrypt a 16-byte
block*. Everything above this module (CMAC, CTR, EAX) is expressed purely in
terms of that oracle, so the backend is swappable.

Two backends are provided:

* :class:`LibgcryptCipher` — the default. Fast and battle-tested; it is the same
  primitive the reference codec ``pt9.py`` uses.
* Pure-Python implementations for portability (Twofish / Serpent / CAST-256).
  When present they are cross-checked against libgcrypt in the test suite.

Where a cipher is unavailable the factory raises :class:`UnsupportedCipherError`
rather than silently substituting another algorithm.
"""

from __future__ import annotations

import ctypes
from typing import Callable, Final, Protocol, runtime_checkable

from pkt_core.errors import UnsupportedCipherError

__all__ = [
    "BLOCK_SIZE",
    "BlockCipher",
    "LibgcryptCipher",
    "get_cipher",
    "available_ciphers",
    "cipher_available",
    "CIPHER_KEY_SIZES",
]

BLOCK_SIZE: Final[int] = 16

#: libgcrypt algorithm identifiers (``gcry_cipher_algos``).
_GCRY_IDS: Final[dict[str, int]] = {
    "twofish": 10,
    "serpent128": 12,
    "serpent192": 13,
    "serpent256": 14,
    "aes": 7,
}

_GCRY_ECB: Final[int] = 1

#: Permitted key sizes in bytes for each named cipher.
CIPHER_KEY_SIZES: Final[dict[str, tuple[int, ...]]] = {
    "twofish": (16, 24, 32),
    "serpent128": (16,),
    "serpent192": (24,),
    "serpent256": (32,),
    "cast256": (16, 24, 32),
    "aes": (16, 24, 32),
}


@runtime_checkable
class BlockCipher(Protocol):
    """Minimal interface required by :mod:`pkt_core.crypto.primitives`."""

    block_size: int

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt one block and return the ciphertext block."""
        ...


# --------------------------------------------------------------------------
# libgcrypt backend
# --------------------------------------------------------------------------
class _Libgcrypt:
    """Thin, module-scoped ctypes binding to ``libgcrypt``.

    Loaded once. ``libgcrypt`` is used in ECB mode only, so no IV is involved at
    this layer — EAX's own nonce handling lives in :mod:`pkt_core.crypto.primitives`.
    """

    def __init__(self) -> None:
        self._lib = self._load()
        lib = self._lib
        lib.gcry_check_version.restype = ctypes.c_char_p
        lib.gcry_check_version(None)
        lib.gcry_cipher_open.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint,
        ]
        lib.gcry_cipher_open.restype = ctypes.c_int
        lib.gcry_cipher_setkey.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.gcry_cipher_setkey.restype = ctypes.c_int
        lib.gcry_cipher_encrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.gcry_cipher_encrypt.restype = ctypes.c_int

    @staticmethod
    def _load() -> ctypes.CDLL:
        for name in ("libgcrypt.so.20", "libgcrypt.so"):
            try:
                return ctypes.CDLL(name)
            except OSError:
                continue
        raise UnsupportedCipherError(
            "libgcrypt not found (install libgcrypt20); no pure-Python backend "
            "is registered yet"
        )

    def open(self, algo_id: int) -> ctypes.c_void_p:
        handle = ctypes.c_void_p()
        if self._lib.gcry_cipher_open(ctypes.byref(handle), algo_id, _GCRY_ECB, 0) != 0:
            raise UnsupportedCipherError(f"gcry_cipher_open failed for id {algo_id}")
        return handle

    def setkey(self, handle: ctypes.c_void_p, key: bytes) -> None:
        if self._lib.gcry_cipher_setkey(handle, key, len(key)) != 0:
            raise UnsupportedCipherError(f"gcry_cipher_setkey rejected {len(key)}-byte key")

    def encrypt(self, handle: ctypes.c_void_p, block: bytes) -> bytes:
        out = ctypes.create_string_buffer(BLOCK_SIZE)
        if self._lib.gcry_cipher_encrypt(handle, out, BLOCK_SIZE, block, BLOCK_SIZE) != 0:
            raise UnsupportedCipherError("gcry_cipher_encrypt failed")
        return out.raw


_LIB: _Libgcrypt | None = None


def _libgcrypt() -> _Libgcrypt:
    global _LIB
    if _LIB is None:
        _LIB = _Libgcrypt()
    return _LIB


class LibgcryptCipher:
    """A block cipher backed by ``libgcrypt`` in ECB mode."""

    block_size: int = BLOCK_SIZE

    def __init__(self, name: str, key: bytes) -> None:
        if name not in _GCRY_IDS:
            raise UnsupportedCipherError(f"{name!r} is not available in libgcrypt")
        if len(key) not in CIPHER_KEY_SIZES.get(name, ()):
            raise ValueError(f"{name} does not accept a {len(key)}-byte key")
        self._name = name
        self._handle = _libgcrypt().open(_GCRY_IDS[name])
        _libgcrypt().setkey(self._handle, key)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"block must be {BLOCK_SIZE} bytes, got {len(block)}")
        return _libgcrypt().encrypt(self._handle, block)


# --------------------------------------------------------------------------
# Pure-Python backend (optional, for portability)
# --------------------------------------------------------------------------
def _pure_python_cipher(name: str, key: bytes) -> BlockCipher | None:
    """Return a pure-Python cipher if one has been registered, else ``None``.

    Kept as a late import so this module works with or without the pure-Python
    implementations present.
    """
    import importlib

    try:
        pure = importlib.import_module("pkt_core.crypto.ciphers_pure")
    except ImportError:
        return None
    factory: Callable[[bytes], BlockCipher] | None = getattr(pure, name, None)
    if factory is None:
        return None
    return factory(key)


def get_cipher(name: str, key: bytes) -> BlockCipher:
    """Construct the named block cipher.

    Preference order: pure-Python (portable, self-contained) then libgcrypt.

    Args:
        name: ``"twofish"``, ``"serpent128"``, ``"serpent256"``, ``"cast256"``…
        key: 16/24/32-byte key.

    Raises:
        UnsupportedCipherError: if no backend can provide the cipher.
        ValueError: if the key length is wrong for that cipher.
    """
    if name not in CIPHER_KEY_SIZES:
        raise UnsupportedCipherError(f"unknown cipher {name!r}")
    if len(key) not in CIPHER_KEY_SIZES[name]:
        raise ValueError(f"{name} does not accept a {len(key)}-byte key")

    impl = _pure_python_cipher(name, key)
    if impl is not None:
        return impl

    if name in _GCRY_IDS:
        return LibgcryptCipher(name, key)

    raise UnsupportedCipherError(
        f"cipher {name!r} needs a backend: libgcrypt has no {name!r} and no "
        "pure-Python implementation is registered"
    )


def cipher_available(name: str) -> bool:
    """Whether this build can actually provide the named cipher."""
    try:
        probe = b"\x00" * CIPHER_KEY_SIZES[name][0]
    except (KeyError, IndexError):
        return False
    try:
        get_cipher(name, probe)
    except (UnsupportedCipherError, ValueError):
        return False
    return True


def available_ciphers() -> list[str]:
    """Names of every cipher this build can provide."""
    return [n for n in CIPHER_KEY_SIZES if cipher_available(n)]
