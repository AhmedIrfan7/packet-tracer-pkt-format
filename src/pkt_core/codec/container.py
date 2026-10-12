"""The Packet Tracer container: detection, decode and encode.

A ``.pkt``/``.pka`` file is, from the outside in::

    file bytes
      |  layer A : reverse + positional XOR
      v
      AEAD ciphertext || 16-byte tag      (Crypto++ EAX, fixed key + fixed IV)
      |  layer B : XOR (len - i)          Util::deobfuscateBytes
      v
      Qt qCompress : 4-byte BE length + zlib
      v
      UTF-8 XML

**There is no magic header.** The first bytes of a container are effectively
random in every generation of the format, so identification is *verifier-based*:
try a candidate (cipher, key, IV) and accept it only when the EAX tag verifies.
That is a cryptographic oracle with a 2^-128 false-positive rate, so detection is
both necessary and conclusive.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from pkt_core.codec.qcompress import qcompress, quncompress
from pkt_core.crypto.keys import FORMATS, FormatName, FormatSpec, get_format
from pkt_core.crypto.primitives import eax_open, eax_seal
from pkt_core.crypto.stream import layer_a, layer_a_inverse, layer_b
from pkt_core.errors import (
    FormatError,
    IntegrityError,
    PacketTracerError,
    TruncatedFileError,
)

__all__ = [
    "Container",
    "decode_bytes",
    "decode",
    "encode_bytes",
    "encode",
    "detect_format",
    "root_tag",
    "DEFAULT_FORMAT",
]

DEFAULT_FORMAT: FormatName = "pkt"


@dataclass(frozen=True, slots=True)
class Container:
    """A decoded container: the bytes we started from, and what they held.

    Attributes:
        xml: The decompressed UTF-8 XML document.
        format_name: Which flavour produced it (``"pkt"``, ``"pta"``, …).
        spec: The key schedule that was used.
        raw: The original file bytes, when known (``None`` for synthesised ones).
    """

    xml: bytes
    format_name: FormatName
    spec: FormatSpec
    raw: bytes | None = None

    @property
    def root_tag(self) -> str:
        """Root element name — ``PACKETTRACER5`` vs ``PACKETTRACER5_ACTIVITY``."""
        return root_tag(self.xml)

    @property
    def is_activity(self) -> bool:
        """True for scored ``.pka`` activities rather than plain ``.pkt`` labs."""
        return self.root_tag.upper().endswith("_ACTIVITY")


def root_tag(xml: bytes) -> str:
    """Extract the root element name from an XML byte string without parsing it.

    Parsing is unnecessary for this one fact and would be wasteful on the
    multi-megabyte documents real labs contain.
    """
    head = xml[:400].decode("utf-8", "replace")
    start = head.find("<")
    end = head.find(">", start)
    if start < 0 or end <= start:
        return "?"
    return head[start + 1 : end].split()[0]


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------
def detect_format(
    raw: bytes,
    candidates: Sequence[FormatName] | None = None,
) -> FormatName:
    """Identify the container flavour by AEAD tag verification.

    Args:
        raw: The complete file bytes.
        candidates: Formats to try, in order. Defaults to every registered format.

    Returns:
        The name of the first flavour whose tag verifies.

    Raises:
        TruncatedFileError: if the buffer is too short to hold a tag.
        FormatError: if no candidate authenticates. For a genuinely *legacy*
            container this is expected — see ``docs/LEGACY_FORMAT.md``.
    """
    if len(raw) < 16:
        raise TruncatedFileError(
            f"file is {len(raw)} bytes; a container needs at least 16 for the EAX tag"
        )
    names: Iterable[FormatName] = candidates if candidates is not None else FORMATS.keys()
    tried: list[str] = []
    for name in names:
        spec = get_format(name)
        try:
            result = eax_open(spec.cipher, spec.key, spec.iv, layer_a(raw))
        except PacketTracerError:
            tried.append(name)
            continue
        if result.valid:
            return name
        tried.append(name)
    raise FormatError(
        f"no known format authenticated this file (tried: {', '.join(tried)}). "
        "If this is a pre-PT-6 container it uses the legacy transform — see "
        "docs/LEGACY_FORMAT.md"
    )


# --------------------------------------------------------------------------
# Decode
# --------------------------------------------------------------------------
def decode_bytes(
    raw: bytes,
    fmt: FormatName | None = None,
    *,
    verify_tag: bool = True,
) -> Container:
    """Open a container and return its XML payload.

    Args:
        raw: The complete file bytes.
        fmt: Force a specific flavour. When ``None`` the flavour is detected via
            the AEAD tag.
        verify_tag: When ``True`` (default) a failed tag raises. When ``False``
            the decrypted bytes are returned anyway — useful for forensics on
            damaged files, and only reachable explicitly.

    Returns:
        A :class:`Container` with the inflated XML.

    Raises:
        TruncatedFileError: input too short.
        IntegrityError: tag mismatch and ``verify_tag`` is True.
        FormatError: detection failed, or the payload is not a container.
        CompressionError: the qCompress layer would not inflate.
    """
    if len(raw) < 16:
        raise TruncatedFileError(
            f"file is {len(raw)} bytes; a container needs at least 16 bytes"
        )
    name = fmt if fmt is not None else detect_format(raw)
    spec = get_format(name)

    result = eax_open(spec.cipher, spec.key, spec.iv, layer_a(raw))
    if verify_tag and not result.valid:
        raise IntegrityError(
            f"EAX tag mismatch for format {name!r} — the file is corrupt or is "
            "not this flavour"
        )
    xml = quncompress(layer_b(result.plaintext))
    return Container(xml=xml, format_name=name, spec=spec, raw=raw)


def decode(
    path: str | Path,
    fmt: FormatName | None = None,
    *,
    verify_tag: bool = True,
) -> Container:
    """Read ``path`` from disk and :func:`decode_bytes` it."""
    data = Path(path).read_bytes()
    return decode_bytes(data, fmt, verify_tag=verify_tag)


# --------------------------------------------------------------------------
# Encode
# --------------------------------------------------------------------------
def encode_bytes(
    xml: bytes,
    fmt: FormatName = DEFAULT_FORMAT,
    *,
    level: int = -1,
) -> bytes:
    """Build a container from XML bytes.

    Args:
        xml: The UTF-8 XML document.
        fmt: Which flavour to seal it as.
        level: zlib compression level (``-1`` is Qt's default).

    Returns:
        Complete file bytes.

    Note:
        With a fixed key/IV the AEAD is deterministic, so identical XML always
        produces identical file bytes. zlib's exact compressed stream may vary
        across zlib builds; container-level round-trip is therefore verified by
        inflating and re-comparing, not by demanding identical zlib bytes.
    """
    spec = get_format(fmt)
    payload = layer_b(qcompress(xml, level))
    sealed = eax_seal(spec.cipher, spec.key, spec.iv, payload)
    return layer_a_inverse(sealed)


def encode(
    path: str | Path,
    xml: bytes,
    fmt: FormatName = DEFAULT_FORMAT,
    *,
    level: int = -1,
) -> None:
    """Build a container from XML bytes and write it to ``path``."""
    Path(path).write_bytes(encode_bytes(xml, fmt, level=level))
