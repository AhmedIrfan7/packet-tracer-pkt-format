"""Lab-level models: document root, network, options, clusters, IOS config."""

from __future__ import annotations

from typing import ClassVar, Iterator

from pydantic import PrivateAttr

from pkt_core.models.base import PktNode
from pkt_core.models.network import Device, Link
from pkt_core.xml.nodes import XmlDocument, XmlElement

__all__ = ["RunningConfig", "Cluster", "LabOptions", "Network", "Lab"]


class RunningConfig(PktNode):
    """Cisco IOS running configuration, stored as one ``<LINE>`` per line.

    Each line is exposed as :class:`bytes`, deliberately. Packet Tracer embeds
    raw control characters in config text - the IOS ``banner motd ^C...^C``
    delimiters are stored as literal ``\\x03`` - and decoding to ``str`` would
    either fail or silently normalise exactly the bytes we guarantee to keep.
    """

    _claimed: ClassVar[frozenset[str]] = frozenset({"LINE"})

    @property
    def lines(self) -> list[bytes]:
        """Config lines as raw bytes, in document order."""
        out: list[bytes] = []
        for line in self._children("LINE"):
            parts = [c.data for c in line.children if hasattr(c, "data")]
            out.append(b"".join(parts))
        return out

    @property
    def text(self) -> str:
        """Lossy UTF-8 rendering. Read-only; never used when writing."""
        return b"\n".join(self.lines).decode("utf-8", "replace")

    def iter_lines(self) -> Iterator[bytes]:
        return iter(self.lines)


class Cluster(PktNode):
    """A canvas grouping (clustering) in the topology view."""

    _claimed: ClassVar[frozenset[str]] = frozenset(
        {"NAME", "CLUSTERID", "CLUSTER_BG_IMAGE", "CLUSTER_EMBEDDED_BG_IMAGE",
         "CLUSTER_ICON_IMAGE", "TILED_BG"}
    )

    @property
    def name(self) -> str:
        return self._text("NAME")

    @property
    def cluster_id(self) -> str:
        """e.g. ``1-1`` for the root cluster."""
        return self._text("CLUSTERID")

    @property
    def tiled_background(self) -> bool:
        return self._bool("TILED_BG")


class LabOptions(PktNode):
    """User-interface and display options for the workspace."""

    _claimed: ClassVar[frozenset[str]] = frozenset(
        {
            "LANGUAGE", "ANIMATION", "LOGICALALIGN", "PHYSICALALIGN", "SOUND",
            "TELEPHONESOUND", "DOCK", "LOGGING", "PASS", "CONFIGPATH",
            "MODELSHOWN", "LINKLIGHTSSHOWN", "PORTSHOWN", "BACKGROUNDS",
            "HIDEPHYSICAL", "HIDEATTRIBUTES", "HIDECONFIG",
            "HIDECONFIGOFROUTERANDSWITCH", "HIDECLIOFROUTERANDSWITCH",
            "HIDESERVICES",
        }
    )

    @property
    def language(self) -> str:
        return self._text("LANGUAGE")

    @property
    def animation(self) -> bool:
        return self._bool("ANIMATION")

    @property
    def sound(self) -> bool:
        return self._bool("SOUND")

    @property
    def show_link_lights(self) -> bool:
        return self._bool("LINKLIGHTSSHOWN")

    @property
    def show_ports(self) -> bool:
        return self._bool("PORTSHOWN")

    @property
    def config_path(self) -> str:
        return self._text("CONFIGPATH")

    @property
    def password(self) -> str:
        """Activity-wizard password, if set (``<PASS>``)."""
        return self._text("PASS")


class Network(PktNode):
    """The ``<NETWORK>`` block: every device and every link."""

    _claimed: ClassVar[frozenset[str]] = frozenset({"DEVICES", "LINKS"})

    @property
    def devices(self) -> list[Device]:
        node = self._el.find("DEVICES")
        return [Device.from_element(d) for d in node.find_all("DEVICE")] if node is not None else []

    @property
    def links(self) -> list[Link]:
        node = self._el.find("LINKS")
        return [Link.from_element(l) for l in node.find_all("LINK")] if node is not None else []

    @property
    def device_count(self) -> int:
        return len(self.devices)

    @property
    def link_count(self) -> int:
        return len(self.links)

    def device_named(self, name: str) -> Device | None:
        for dev in self.devices:
            if dev.name == name:
                return dev
        return None


class Lab(PktNode):
    """A Packet Tracer document.

    This is the entry point: it wraps the parsed document and exposes the
    entities worth typing, while leaving everything else in ``extra_fields``
    and preserving the original bytes.
    """

    _claimed: ClassVar[frozenset[str]] = frozenset(
        {
            "VERSION", "NETWORK", "OPTIONS", "CLUSTERS", "SCRIPT_MODULE",
            "PIXMAPBANK", "MOVIEBANK", "SCENARIOSET", "PHYSICALWORKSPACE",
        }
    )

    _doc: XmlDocument = PrivateAttr()

    def __init__(self, doc: XmlDocument) -> None:
        super().__init__()
        self._el = doc.root
        self._doc = doc

    @classmethod
    def from_bytes(cls, data: bytes) -> "Lab":
        from pkt_core.xml import parse_xml_bytes

        return cls(parse_xml_bytes(data))

    @property
    def document(self) -> XmlDocument:
        return self._doc

    @property
    def version(self) -> str:
        """Packet Tracer build that wrote the file, e.g. ``7.3.1.0362``.

        This is what pins the container family: below ``5.3.3`` the file uses
        the legacy container.
        """
        return self._text("VERSION")

    @property
    def is_activity(self) -> bool:
        """True for scored ``.pka`` activities (root ``*_ACTIVITY``)."""
        return self._doc.root_tag.upper().endswith("_ACTIVITY")

    @property
    def network(self) -> Network | None:
        node = self._el.find("NETWORK")
        return Network.from_element(node) if node is not None else None

    @property
    def options(self) -> LabOptions | None:
        node = self._el.find("OPTIONS")
        return LabOptions.from_element(node) if node is not None else None

    @property
    def clusters(self) -> list[Cluster]:
        node = self._el.find("CLUSTERS")
        if node is None:
            return []
        out: list[Cluster] = []
        for tag in ("ROOTCLUSTER", "CLUSTER"):
            out.extend(Cluster.from_element(c) for c in node.find_all(tag))
        return out

    # -- convenience over Network -----------------------------------------
    @property
    def devices(self) -> list[Device]:
        net = self.network
        return net.devices if net is not None else []

    @property
    def links(self) -> list[Link]:
        net = self.network
        return net.links if net is not None else []

    def device_named(self, name: str) -> Device | None:
        net = self.network
        return net.device_named(name) if net is not None else None

    # -- serialization ----------------------------------------------------
    def to_xml(self) -> bytes:
        """Serialise the whole document; unmodified documents are byte-exact."""
        return self._doc.to_bytes()

    def summary(self) -> dict[str, object]:
        """Compact, JSON-friendly overview - handy for ``pkt info`` and diffs."""
        net = self.network
        return {
            "root_tag": self._doc.root_tag,
            "version": self.version,
            "is_activity": self.is_activity,
            "devices": net.device_count if net else 0,
            "links": net.link_count if net else 0,
            "clusters": len(self.clusters),
        }
