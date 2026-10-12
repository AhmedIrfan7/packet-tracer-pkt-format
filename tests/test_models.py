"""Tests for the typed object model.

The model is a *view* over the lossless XML tree, so the load-bearing property
is: reading through it must not change a single byte.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from pkt_core import decode_bytes
from pkt_core.models import (
    Cable,
    Cluster,
    Device,
    Lab,
    LabOptions,
    Link,
    Module,
    Network,
    Port,
    RunningConfig,
    Workspace,
    unknown_children,
)
from pkt_core.xml import parse_xml_bytes

REPO = Path(__file__).resolve().parent.parent
INDEX = REPO.parent / "corpus" / "CORPUS_INDEX.tsv"
CORPUS = REPO.parent / "corpus" / "internet"

SAMPLE = """<PACKETTRACER5>
 <VERSION>7.3.1.0362</VERSION>
 <NETWORK>
  <DEVICES>
   <DEVICE>
    <ENGINE>
     <TYPE model="2960-24TT" customModel="">Switch</TYPE>
     <NAME translate="true">Switch0</NAME>
     <POWER>true</POWER>
     <DESCRIPTION>core</DESCRIPTION>
     <MODULE>
      <TYPE>eNonRemovableModule</TYPE>
      <MODEL/>
      <SLOT>
       <TYPE>eNonRemovableModule</TYPE>
       <MODULE>
        <TYPE>eNonRemovableModule</TYPE>
        <MODEL/>
        <PORT>
         <TYPE>eCopperFastEthernet</TYPE>
         <BANDWIDTH>100000</BANDWIDTH>
         <FULLDUPLEX>true</FULLDUPLEX>
         <MACADDRESS>00E0.A3D0.EC01</MACADDRESS>
         <BIA>00E0.A3D0.EC01</BIA>
         <CLOCKRATE>2000000</CLOCKRATE>
         <MYSTERY_TAG>keep me</MYSTERY_TAG>
        </PORT>
       </MODULE>
      </SLOT>
     </MODULE>
    </ENGINE>
    <WORKSPACE>
     <LOGICAL>
      <X>369</X>
      <Y>202</Y>
      <DEVCLUSTERID>1-1</DEVCLUSTERID>
     </LOGICAL>
    </WORKSPACE>
   </DEVICE>
  </DEVICES>
  <LINKS>
   <LINK>
    <TYPE>eCopper</TYPE>
    <CABLE>
     <LENGTH>35.3636</LENGTH>
     <FUNCTIONAL>true</FUNCTIONAL>
     <FROM>save-ref-id:111</FROM>
     <PORT>FastEthernet0/1</PORT>
     <TO>save-ref-id:222</TO>
     <PORT>FastEthernet0</PORT>
     <GEO_VIEW_COLOR>#000000</GEO_VIEW_COLOR>
     <TYPE>eStraightThrough</TYPE>
    </CABLE>
   </LINK>
  </LINKS>
 </NETWORK>
 <OPTIONS>
  <LANGUAGE>default.ptl</LANGUAGE>
  <ANIMATION>true</ANIMATION>
  <LINKLIGHTSSHOWN>true</LINKLIGHTSSHOWN>
  <PASS>hunter2</PASS>
 </OPTIONS>
 <CLUSTERS>
  <ROOTCLUSTER>
   <NAME translate="true">Root</NAME>
   <CLUSTERID>1-1</CLUSTERID>
   <TILED_BG>false</TILED_BG>
  </ROOTCLUSTER>
 </CLUSTERS>
 <RUNNINGCONFIG>
  <LINE>hostname Switch</LINE>
  <LINE>banner motd \x03wtf\x03</LINE>
 </RUNNINGCONFIG>
</PACKETTRACER5>
"""


@pytest.fixture(scope="module")
def lab() -> Lab:
    return Lab.from_bytes(SAMPLE.encode("utf-8"))


# --------------------------------------------------------------------------
# Fidelity
# --------------------------------------------------------------------------
def test_model_access_does_not_alter_bytes(lab: Lab) -> None:
    _ = lab.summary()
    _ = lab.devices
    _ = lab.links
    _ = lab.options
    _ = lab.clusters
    assert lab.to_xml() == SAMPLE.encode("utf-8")


def test_roundtrip_is_byte_exact() -> None:
    raw = SAMPLE.encode("utf-8")
    assert Lab.from_bytes(raw).to_xml() == raw


# --------------------------------------------------------------------------
# Devices
# --------------------------------------------------------------------------
def test_device_identity(lab: Lab) -> None:
    dev = lab.devices[0]
    assert dev.name == "Switch0"
    assert dev.kind == "Switch"
    assert dev.model == "2960-24TT"
    assert dev.custom_model == ""
    assert dev.powered is True
    assert dev.description == "core"


def test_device_canvas_placement(lab: Lab) -> None:
    dev = lab.devices[0]
    assert dev.position == (369.0, 202.0)
    assert dev.cluster_id == "1-1"


def test_ports_are_flattened_through_modules_and_slots(lab: Lab) -> None:
    ports = lab.devices[0].ports
    assert len(ports) == 1
    p = ports[0]
    assert p.type == "eCopperFastEthernet"
    assert p.mac_address == "00E0.A3D0.EC01"
    assert p.burned_in_address == "00E0.A3D0.EC01"
    assert p.bandwidth == 100000
    assert p.full_duplex is True
    assert p.clock_rate == 2000000


def test_unknown_port_children_land_in_extra_fields(lab: Lab) -> None:
    p = lab.devices[0].ports[0]
    assert "MYSTERY_TAG" in p.extra_fields
    assert p.extra_fields["MYSTERY_TAG"][0].text == "keep me"


def test_device_named_lookup(lab: Lab) -> None:
    assert lab.device_named("Switch0") is not None
    assert lab.device_named("Nope") is None


# --------------------------------------------------------------------------
# Links
# --------------------------------------------------------------------------
def test_link_endpoints_and_ports(lab: Lab) -> None:
    link = lab.links[0]
    assert link.type == "eCopper"
    assert link.cable_type == "eStraightThrough"
    assert link.port_names == ["FastEthernet0/1", "FastEthernet0"]
    assert link.endpoints == ("save-ref-id:111", "save-ref-id:222")
    assert link.cable is not None
    assert link.cable.length == 35.3636
    assert link.cable.functional is True
    assert link.cable.geo_view_color == "#000000"


def test_cable_less_link_does_not_crash() -> None:
    xml = b"<PACKETTRACER5><NETWORK><LINKS><LINK><TYPE>eRadio</TYPE></LINK></LINKS></NETWORK></PACKETTRACER5>"
    lab = Lab.from_bytes(xml)
    link = lab.links[0]
    assert link.cable is None
    assert link.cable_type == ""
    assert link.port_names == []


# --------------------------------------------------------------------------
# Options, clusters, config
# --------------------------------------------------------------------------
def test_options(lab: Lab) -> None:
    assert lab.options is not None
    assert lab.options.language == "default.ptl"
    assert lab.options.animation is True
    assert lab.options.show_link_lights is True
    assert lab.options.password == "hunter2"


def test_clusters(lab: Lab) -> None:
    assert len(lab.clusters) == 1
    assert lab.clusters[0].name == "Root"
    assert lab.clusters[0].cluster_id == "1-1"


def test_running_config_keeps_control_bytes() -> None:
    """IOS banner delimiters are literal 0x03 and must not be normalised."""
    lab = Lab.from_bytes(SAMPLE.encode("utf-8"))
    node = lab.element.find("RUNNINGCONFIG")
    assert node is not None
    cfg = RunningConfig.from_element(node)
    assert cfg.lines[0] == b"hostname Switch"
    assert b"\x03wtf\x03" in cfg.lines[1], "control bytes must survive as bytes"


# --------------------------------------------------------------------------
# extra_fields contract
# --------------------------------------------------------------------------
def test_unknown_children_helper_groups_by_name() -> None:
    doc = parse_xml_bytes(b"<R><A/><A/><B/></R>")
    extra = unknown_children(doc.root, {"B"})
    assert set(extra) == {"A"}
    assert len(extra["A"]) == 2


def test_lab_extra_fields_lists_unmodelled_root_children() -> None:
    raw = b"<PACKETTRACER5><VERSION>9</VERSION><WEIRD_THING/></PACKETTRACER5>"
    lab = Lab.from_bytes(raw)
    assert "WEIRD_THING" in lab.extra_fields
    assert lab.to_xml() == raw


# --------------------------------------------------------------------------
# Real corpus
# --------------------------------------------------------------------------
def _corpus_labs() -> list[tuple[str, bytes]]:
    if not INDEX.exists() or not CORPUS.exists():
        return []
    out: list[tuple[str, bytes]] = []
    with INDEX.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh, delimiter="\t"))
    for row in rows[:120]:
        name = row["filename"]
        if name.lower().endswith(".zip"):
            continue
        path = CORPUS / name
        if not path.exists():
            continue
        try:
            out.append((name, decode_bytes(path.read_bytes()).xml))
        except Exception:  # noqa: BLE001
            continue
    return out


@pytest.mark.corpus
def test_corpus_model_access_is_lossless() -> None:
    docs = _corpus_labs()
    if not docs:
        pytest.skip("corpus not fetched (see corpus/README.md)")
    bad: list[str] = []
    for name, xml in docs:
        lab = Lab.from_bytes(xml)
        _ = lab.summary()
        for dev in lab.devices:
            _ = dev.name, dev.kind, dev.model, dev.position, dev.ports
        for link in lab.links:
            _ = link.type, link.cable_type, link.port_names
        _ = lab.options, lab.clusters
        if lab.to_xml() != xml:
            bad.append(name)
    assert not bad, f"{len(bad)} documents changed bytes:\n" + "\n".join(bad[:10])


@pytest.mark.corpus
def test_corpus_devices_and_links_are_found() -> None:
    docs = _corpus_labs()
    if not docs:
        pytest.skip("corpus not fetched (see corpus/README.md)")
    saw_device = saw_link = 0
    for _name, xml in docs:
        lab = Lab.from_bytes(xml)
        saw_device += len(lab.devices)
        saw_link += len(lab.links)
    assert saw_device > 0, "no devices found anywhere in the corpus sample"
    assert saw_link > 0, "no links found anywhere in the corpus sample"
