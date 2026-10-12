"""Byte-level node model for lossless Packet Tracer XML.

Every node carries the exact source bytes it was parsed from. Serialization of
an unmodified document is concatenation of those spans, which is what makes
byte-exact round-trip achievable despite the corpus's control bytes, NUL
terminators and non-standard character references.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Sequence

from pkt_core.errors import FormatError

__all__ = [
    "XmlNode",
    "XmlText",
    "XmlElement",
    "XmlDocument",
    "ATTR_NAME",
    "ATTR_VALUE",
    "parse_xml_bytes",
    "parse_xml",
]

#: Attribute tuple shape: ``(raw_name_bytes, raw_value_bytes, raw_source_span)``.
ATTR_NAME = 0
ATTR_VALUE = 1


@dataclass(slots=True)
class XmlText:
    """Raw character data between tags.

    Attribute:
        data: The exact source bytes, quirks and all. Never normalised.
    """

    data: bytes

    #: Set when this node's content has been edited, forcing re-emission.
    _dirty: bool = field(default=False, repr=False)

    @property
    def dirty(self) -> bool:
        return self._dirty

    def to_bytes(self) -> bytes:
        return self.data

    @property
    def text(self) -> str:
        """Lossy UTF-8 view, for humans and for tests. Not used on write."""
        return self.data.decode("utf-8", "replace")


@dataclass(slots=True)
class XmlElement:
    """An element: start tag, children, end tag — with its original bytes.

    Attributes:
        name: The element name as raw bytes (XML names are ASCII in practice).
        attrs: Ordered ``(raw_name, raw_value, raw_source)`` triples. Values are
            stored **with** their surrounding quotes, exactly as they appeared,
            so unmodified attributes round-trip byte-for-byte.
        children: Ordered child nodes (:class:`XmlElement` or :class:`XmlText`).
        raw: The complete source span from ``<`` to ``>`` of the end tag, or the
            full self-closing span. ``None`` once the node is synthesised.
    """

    name: bytes
    attrs: list[tuple[bytes, bytes, bytes]] = field(default_factory=list)
    children: list["XmlNode"] = field(default_factory=list)
    raw: bytes | None = None
    _dirty: bool = field(default=False, repr=False)

    @property
    def dirty(self) -> bool:
        return self._dirty or any(c.dirty for c in self.children)

    # -- convenience (lossy, read-only) -----------------------------------
    @property
    def tag(self) -> str:
        return self.name.decode("utf-8", "replace")

    def get(self, name: str) -> str | None:
        """Attribute value decoded to text, without its quoting."""
        want = name.encode("utf-8")
        for raw_name, raw_value, _src in self.attrs:
            if raw_name == want:
                v = raw_value
                if len(v) >= 2 and v[0:1] in (b'"', b"'") and v[-1:] == v[0:1]:
                    v = v[1:-1]
                return v.decode("utf-8", "replace")
        return None

    def set(self, name: str, value: str) -> None:
        """Set an attribute, marking this element dirty so it re-serialises."""
        want = name.encode("utf-8")
        new_val = value.encode("utf-8")
        for i, (raw_name, raw_value, _src) in enumerate(self.attrs):
            if raw_name == want:
                quote = raw_value[0:1] if raw_value[:1] in (b'"', b"'") else b'"'
                self.attrs[i] = (raw_name, quote + new_val + quote, b"")
                self._dirty = True
                return
        self.attrs.append((want, b'"' + new_val + b'"', b""))
        self._dirty = True

    def find(self, name: str) -> "XmlElement | None":
        """First direct child element with this name."""
        want = name.encode("utf-8")
        for child in self.children:
            if isinstance(child, XmlElement) and child.name == want:
                return child
        return None

    def find_all(self, name: str) -> list["XmlElement"]:
        """Every direct child element with this name."""
        want = name.encode("utf-8")
        return [c for c in self.children if isinstance(c, XmlElement) and c.name == want]

    def iter_elements(self) -> Iterator["XmlElement"]:
        """Depth-first walk over all descendant elements (excluding self)."""
        for child in self.children:
            if isinstance(child, XmlElement):
                yield child
                yield from child.iter_elements()

    @property
    def text(self) -> str:
        """Concatenated descendant text (lossy UTF-8)."""
        parts: list[str] = []
        for child in self.children:
            if isinstance(child, XmlText):
                parts.append(child.text)
            else:
                parts.append(child.text)
        return "".join(parts)

    def append_text(self, data: bytes) -> None:
        self.children.append(XmlText(data=data))
        self._dirty = True

    def append(self, child: "XmlNode") -> None:
        self.children.append(child)
        self._dirty = True

    # -- serialization ----------------------------------------------------
    def to_bytes(self) -> bytes:
        """Emit this element.

        If nothing changed, the original source bytes are returned verbatim —
        this is the path that makes byte-exact round-trip free. Otherwise the
        element is re-serialised from its (possibly edited) model.
        """
        if self.raw is not None and not self.dirty:
            return self.raw

        out = bytearray(b"<")
        out += self.name
        for raw_name, raw_value, src in self.attrs:
            out += b" " + raw_name + b"="
            if src:
                out += src
            elif raw_value[:1] in (b'"', b"'"):
                out += raw_value
            else:
                out += b'"' + raw_value + b'"'

        if not self.children and self.raw is not None and self.raw.rstrip().endswith(b"/>"):
            out += b"/>"
            return bytes(out)

        out += b">"
        for child in self.children:
            out += child.to_bytes()
        out += b"</" + self.name + b">"
        return bytes(out)


#: Either flavour of node.
XmlNode = XmlText | XmlElement


@dataclass(slots=True)
class XmlDocument:
    """A whole document: bytes before the root, the root, bytes after it.

    Attribute:
        prologue: Everything before the root element (XML declaration, if any).
        root: The root element.
        epilogue: Everything after the root element — including the trailing NUL
            that PT 4.1 documents carry.
    """

    prologue: bytes
    root: XmlElement
    epilogue: bytes

    @property
    def dirty(self) -> bool:
        return self.root.dirty

    def to_bytes(self) -> bytes:
        return self.prologue + self.root.to_bytes() + self.epilogue

    @property
    def root_tag(self) -> str:
        return self.root.tag


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------
def _find_tag_end(data: bytes, start: int) -> int:
    """Index of the ``>`` closing the tag begun at ``data[start] == '<'``.

    Handles quoted attribute values, which may legally contain ``>``.
    """
    i = start + 1
    quote: int | None = None
    n = len(data)
    while i < n:
        b = data[i]
        if quote is not None:
            if b == quote:
                quote = None
        elif b in (0x22, 0x27):  # " or '
            quote = b
        elif b == 0x3E:  # >
            return i
        i += 1
    raise FormatError(f"unterminated tag starting at offset {start}")


def _parse_attrs(raw: bytes) -> list[tuple[bytes, bytes, bytes]]:
    """Split the inside of a start tag into ``(name, value_with_quotes, span)``.

    The raw name text after the element name is preserved verbatim in ``span``
    per attribute so that quoting style, spacing and ordering survive.
    """
    # strip leading name and trailing '>' or '/>'
    body = raw[1:]
    if body.endswith(b">"):
        body = body[:-1]
    if body.endswith(b"/"):
        body = body[:-1]

    # skip the element name
    i = 0
    n = len(body)
    while i < n and not body[i : i + 1].isspace() and body[i] not in (0x3D,):
        i += 1
    body = body[i:]

    attrs: list[tuple[bytes, bytes, bytes]] = []
    i = 0
    n = len(body)
    while i < n:
        while i < n and body[i : i + 1].isspace():
            i += 1
        if i >= n:
            break
        name_start = i
        while i < n and body[i] not in (0x3D, 0x3E) and not body[i : i + 1].isspace():
            i += 1
        name = body[name_start:i]
        while i < n and body[i : i + 1].isspace():
            i += 1
        if i < n and body[i] == 0x3D:
            i += 1
            while i < n and body[i : i + 1].isspace():
                i += 1
            if i < n and body[i] in (0x22, 0x27):
                q = body[i]
                j = i + 1
                while j < n and body[j] != q:
                    j += 1
                value = body[i : j + 1]
                i = j + 1
            else:
                j = i
                while j < n and not body[j : j + 1].isspace():
                    j += 1
                value = body[i:j]
                i = j
        else:
            value = b""
        if name:
            attrs.append((name, value, b""))
    return attrs


def _parse_element(data: bytes, pos: int) -> tuple[XmlElement, int]:
    """Parse one element starting at ``data[pos] == '<'``.

    Returns the element and the offset just past it.
    """
    if data[pos : pos + 2] == b"<?" or data[pos : pos + 2] == b"<!":
        raise FormatError(f"unexpected declaration at offset {pos}")
    end = _find_tag_end(data, pos)
    raw_start_tag = data[pos : end + 1]

    # element name
    i = pos + 1
    n = len(data)
    while i < n and not data[i : i + 1].isspace() and data[i] not in (0x3E, 0x2F):
        i += 1
    name = data[pos + 1 : i]

    self_closing = raw_start_tag.rstrip(b">").endswith(b"/")
    attrs = _parse_attrs(raw_start_tag)

    elem = XmlElement(name=name, attrs=attrs, children=[], raw=None)
    cursor = end + 1

    if self_closing:
        elem.raw = raw_start_tag
        return elem, cursor

    # children until the matching end tag
    text_start = cursor
    while True:
        lt = data.find(b"<", cursor)
        if lt < 0:
            raise FormatError(f"element <{name.decode('utf-8', 'replace')}> never closed")
        if lt > text_start:
            elem.children.append(XmlText(data=data[text_start:lt]))

        if data[lt : lt + 2] == b"</":
            tag_end = _find_tag_end(data, lt)
            if data[lt + 2 : tag_end].strip() != name:
                raise FormatError(
                    f"mismatched end tag at offset {lt}: "
                    f"expected </{name.decode('utf-8', 'replace')}>"
                )
            elem.raw = data[pos : tag_end + 1]
            return elem, tag_end + 1

        if data[lt : lt + 2] in (b"<?", b"<!"):
            tag_end = _find_tag_end(data, lt)
            elem.children.append(XmlText(data=data[lt : tag_end + 1]))
            cursor = tag_end + 1
            text_start = cursor
            continue

        child, cursor = _parse_element(data, lt)
        elem.children.append(child)
        text_start = cursor


def parse_xml_bytes(data: bytes) -> XmlDocument:
    """Parse a Packet Tracer document, preserving every source byte.

    Args:
        data: The complete document, quirks included.

    Returns:
        An :class:`XmlDocument` whose :meth:`~XmlDocument.to_bytes` reproduces
        ``data`` exactly when nothing has been modified.

    Raises:
        FormatError: if no root element can be located or the structure is
            unusably broken (mismatched end tags, unterminated tag).
    """
    lt = data.find(b"<")
    if lt < 0:
        raise FormatError("no element found in document")
    root, after = _parse_element(data, lt)
    return XmlDocument(prologue=data[:lt], root=root, epilogue=data[after:])


def parse_xml(data: str) -> XmlDocument:
    """Parse a document given as text (encoded to UTF-8 first)."""
    return parse_xml_bytes(data.encode("utf-8"))
