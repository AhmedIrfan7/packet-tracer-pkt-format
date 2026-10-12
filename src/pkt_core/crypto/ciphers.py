"""Block-cipher backends: selection, acceleration and fallback.

The container needs exactly one primitive from the cipher: *encrypt a 16-byte
block*. Everything above this module (CMAC, CTR, EAX) is expressed purely in
terms of that oracle, so the backend is swappable.

Two backends are provided:

* **libgcrypt** — used first, because it is roughly 100x faster and a container
  run is CTR + CMAC over the whole payload. A 600 KB file is ~38k blocks.
* **Pure Python** (:mod:`pkt_core.crypto.ciphers_pure`) — the portable fallback,
  and the *only* source of CAST-256, which libgcrypt does not implement at all.

Preference order is therefore libgcrypt when it covers the algorithm, pure
Python otherwise. The two are cross-checked against each other and against
published known-answer tests in ``tests/test_ciphers.py``, so the fast path is
not the unverified one.

.. note::

   ``libgcrypt`` 1.12 **renumbered** its static cipher identifiers:
   ``SERPENT128/192/256`` are now ``304/305/306``, not ``12/13/14``, and
   ``TWOFISH128`` is ``303``. Hard-coding the historical values silently breaks
   those algorithms. This module therefore resolves names through
   ``gcry_cipher_map_name`` and never assumes a numeric id.
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
    "encrypt_block",
    "available_ciphers",
    "cipher_available",
    "CIPHER_KEY_SIZES",
    # re-exported from the pure-Python backend
    "CIPHERS",
    "KEY_SIZES",
    "CipherRegistry",
    "Twofish",
    "Serpent",
    "CAST256",
]

BLOCK_SIZE: Final[int] = 16

#: Permitted key sizes in bytes for each named cipher.
CIPHER_KEY_SIZES: Final[dict[str, tuple[int, ...]]] = {
    "twofish": (16, 24, 32),
    "serpent128": (16,),
    "serpent192": (24,),
    "serpent256": (32,),
    "cast256": (16, 24, 32),
    "aes": (16, 24, 32),
}

_GCRY_ECB: Final[int] = 1

#: Names ``libgcrypt`` may know, for the accelerated path.
_GCRY_NAMES: Final[tuple[str, ...]] = (
    "twofish",
    "serpent128",
    "serpent192",
    "serpent256",
    "aes",
)


@runtime_checkable
class BlockCipher(Protocol):
    """Minimal interface required by :mod:`pkt_core.crypto.primitives`.

    Both backends implement this, so callers never need to know which one they
    were handed.
    """

    block_size: int
    key_size: int

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt one block and return the ciphertext block."""
        ...


# --------------------------------------------------------------------------
# libgcrypt backend
# --------------------------------------------------------------------------
class _Libgcrypt:
    """Module-scoped ctypes binding to ``libgcrypt``.

    Used in ECB mode only, so no IV is involved here — EAX's nonce handling
    lives in :mod:`pkt_core.crypto.primitives`.
    """

    def __init__(self) -> None:
        self._lib = self._load()
        lib = self._lib
        lib.gcry_check_version.restype = ctypes.c_char_p
        lib.gcry_check_version(None)
        lib.gcry_cipher_map_name.restype = ctypes.c_int
        lib.gcry_cipher_map_name.argtypes = [ctypes.c_char_p]
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
        raise UnsupportedCipherError("libgcrypt not found (install libgcrypt20)")

    def algo_id(self, name: str) -> int:
        """Resolve a cipher name to this build's identifier (never hard-coded)."""
        return int(self._lib.gcry_cipher_map_name(name.encode("ascii")))

    def has(self, name: str) -> bool:
        return self.algo_id(name) != 0

    def open(self, name: str) -> ctypes.c_void_p:
        algo = self.algo_id(name)
        if algo == 0:
            raise UnsupportedCipherError(f"libgcrypt has no cipher named {name!r}")
        handle = ctypes.c_void_p()
        if self._lib.gcry_cipher_open(ctypes.byref(handle), algo, _GCRY_ECB, 0) != 0:
            raise UnsupportedCipherError(f"gcry_cipher_open failed for {name!r}")
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


def _libgcrypt() -> _Libgcrypt | None:
    global _LIB
    if _LIB is None:
        try:
            _LIB = _Libgcrypt()
        except UnsupportedCipherError:
            return None
    return _LIB


class LibgcryptCipher:
    """A block cipher backed by ``libgcrypt`` in ECB mode."""

    block_size: int = BLOCK_SIZE
    #: Length of the key this instance was constructed with.
    key_size: int

    def __init__(self, name: str, key: bytes) -> None:
        lib = _libgcrypt()
        if lib is None or not lib.has(name):
            raise UnsupportedCipherError(f"{name!r} is not available in libgcrypt")
        if len(key) not in CIPHER_KEY_SIZES.get(name, ()):
            raise ValueError(f"{name} does not accept a {len(key)}-byte key")
        self._name = name
        self.key_size = len(key)
        self._handle = lib.open(name)
        lib.setkey(self._handle, key)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"block must be {BLOCK_SIZE} bytes, got {len(block)}")
        lib = _libgcrypt()
        if lib is None:  # pragma: no cover - already constructed
            raise UnsupportedCipherError("libgcrypt disappeared")
        return lib.encrypt(self._handle, block)


# --------------------------------------------------------------------------
# Pure-Python backend
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# Re-export the pure-Python implementation surface
# --------------------------------------------------------------------------
from pkt_core.crypto.ciphers_pure import (  # noqa: E402,F401
    CAST256,
    CIPHERS,
    KEY_SIZES,
    CipherRegistry,
    Serpent,
    Twofish,
)


def _pure_cipher(name: str, key: bytes) -> BlockCipher | None:
    """Return a pure-Python cipher, or ``None`` if this name is unsupported."""
    try:
        from pkt_core.crypto import ciphers_pure as pure
    except ImportError:  # pragma: no cover - optional module
        return None
    registry: dict[str, Callable[[bytes], BlockCipher]] | None = getattr(
        pure, "CIPHERS", None
    )
    if not registry or name not in registry:
        return None
    return registry[name](key)


def get_cipher(name: str, key: bytes) -> BlockCipher:
    """Construct the named block cipher.

    Preference order: ``libgcrypt`` where it covers the algorithm (fast), then
    pure Python (portable, and the only source of CAST-256).

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

    # Native first: this is on the hot path for every container operation and
    # the two backends are proven byte-identical in tests/test_ciphers.py.
    if name in _GCRY_NAMES:
        try:
            return LibgcryptCipher(name, key)
        except UnsupportedCipherError:
            pass  # fall through to the pure implementation

    impl = _pure_cipher(name, key)
    if impl is not None:
        return impl

    raise UnsupportedCipherError(
        f"cipher {name!r} needs a backend: libgcrypt has no {name!r} and no "
        "pure-Python implementation is registered"
    )


def encrypt_block(name: str, key: bytes, block: bytes) -> bytes:
    """One-shot convenience: encrypt a single block."""
    return get_cipher(name, key).encrypt_block(block)


def cipher_available(name: str) -> bool:
    """Whether this build can actually provide the named cipher."""
    sizes = CIPHER_KEY_SIZES.get(name)
    if not sizes:
        return False
    try:
        get_cipher(name, b"\x00" * sizes[0])
    except (UnsupportedCipherError, ValueError):
        return False
    return True


def available_ciphers() -> list[str]:
    """Names of every cipher this build can provide."""
    return [n for n in CIPHER_KEY_SIZES if cipher_available(n)]
