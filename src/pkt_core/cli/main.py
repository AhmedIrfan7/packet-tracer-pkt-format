"""``pkt`` — command-line interface for Packet Tracer container files.

A deliberately thin consumer of :mod:`pkt_core`. Nothing here contains format
logic; if a behaviour needs to know about cipher or framing details it belongs in
the library, not in this module.

    pkt info   lab.pkt
    pkt unpack lab.pkt -o out/
    pkt pack   out/lab.xml -o lab.pkt
    pkt diff   a.pkt b.pkt
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path
from typing import Sequence

from pkt_core import (
    DEFAULT_FORMAT,
    FORMATS,
    Container,
    PacketTracerError,
    decode,
    decode_bytes,
    encode,
    encode_bytes,
    root_tag,
)
from pkt_core.codec.container import detect_format

__all__ = ["main", "cmd_info", "cmd_unpack", "cmd_pack", "cmd_diff"]

_PROG = "pkt"


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------
def _load(path: Path) -> Container:
    return decode(path)


def _xml_text(xml: bytes) -> list[str]:
    return xml.decode("utf-8", "replace").splitlines(keepends=True)


# --------------------------------------------------------------------------
# pkt info
# --------------------------------------------------------------------------
def cmd_info(args: argparse.Namespace) -> int:
    """Decrypt just enough to describe the file."""
    path: Path = args.file
    raw = path.read_bytes()
    container = decode_bytes(raw, verify_tag=not args.no_verify)

    print(f"file        : {path}")
    print(f"size        : {len(raw):,} bytes")
    print(f"format      : {container.format_name}")
    print(f"cipher      : {container.spec.cipher}")
    print(f"key byte    : 0x{container.spec.key_byte:02x}  (repeated x16)")
    print(f"iv byte     : 0x{container.spec.iv_byte:02x}  (repeated x16)")
    print(f"root tag    : {container.root_tag}")
    print(f"kind        : {'scored activity (.pka)' if container.is_activity else 'network lab (.pkt)'}")
    print(f"xml bytes   : {len(container.xml):,}")
    if args.json:
        print(json.dumps({
            "path": str(path),
            "size": len(raw),
            "format": container.format_name,
            "cipher": container.spec.cipher,
            "key_byte": f"0x{container.spec.key_byte:02x}",
            "iv_byte": f"0x{container.spec.iv_byte:02x}",
            "root_tag": container.root_tag,
            "is_activity": container.is_activity,
            "xml_bytes": len(container.xml),
        }, indent=2))
    return 0


# --------------------------------------------------------------------------
# pkt unpack
# --------------------------------------------------------------------------
def cmd_unpack(args: argparse.Namespace) -> int:
    """Write the inner XML out, alongside a small metadata sidecar."""
    path: Path = args.file
    container = _load(path)

    out_dir: Path = args.output
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = path.stem if not path.name.lower().endswith(".pkt.pka") else path.name[:-8]

    xml_path = out_dir / f"{stem}.xml"
    xml_path.write_bytes(container.xml)

    meta = {
        "source_file": path.name,
        "source_size": path.stat().st_size,
        "format": container.format_name,
        "cipher": container.spec.cipher,
        "key_byte": f"0x{container.spec.key_byte:02x}",
        "iv_byte": f"0x{container.spec.iv_byte:02x}",
        "root_tag": container.root_tag,
        "is_activity": container.is_activity,
        "xml_bytes": len(container.xml),
    }
    meta_path = out_dir / f"{stem}.container.json"
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    print(f"xml   -> {xml_path}  ({len(container.xml):,} bytes)")
    print(f"meta  -> {meta_path}")
    print(f"kind  : {'scored activity' if container.is_activity else 'network lab'}")
    return 0


# --------------------------------------------------------------------------
# pkt pack
# --------------------------------------------------------------------------
def cmd_pack(args: argparse.Namespace) -> int:
    """Re-serialise XML back into a container."""
    src: Path = args.file
    xml = src.read_bytes()

    detected = root_tag(xml)
    if args.output.exists() and not args.force:
        print(f"error: {args.output} exists (use --force to overwrite)", file=sys.stderr)
        return 1

    encode(args.output, xml, args.format, level=args.level)
    out_size = args.output.stat().st_size
    print(f"xml   : {len(xml):,} bytes  (root <{detected}>)")
    print(f"format: {args.format}")
    print(f"wrote -> {args.output}  ({out_size:,} bytes)")

    if args.verify:
        again = decode(args.output)
        if again.xml != xml:
            print("error: round-trip verification FAILED", file=sys.stderr)
            return 1
        print("round-trip: OK (decoded bytes match the input XML exactly)")
    return 0


# --------------------------------------------------------------------------
# pkt diff
# --------------------------------------------------------------------------
def cmd_diff(args: argparse.Namespace) -> int:
    """Compare two containers.

    Compares at two levels: the container identity (format, cipher, root tag,
    XML size) and the XML text itself. Exit status is 0 when identical, 1 when
    they differ — so this is script-friendly.
    """
    a = _load(args.file_a)
    b = _load(args.file_b)

    same = True
    print(f"{'field':<12} {'A':<28} {'B':<28}")
    print("-" * 70)
    rows = [
        ("format", a.format_name, b.format_name),
        ("cipher", a.spec.cipher, b.spec.cipher),
        ("root tag", a.root_tag, b.root_tag),
        ("kind", "activity" if a.is_activity else "lab",
                 "activity" if b.is_activity else "lab"),
        ("xml bytes", f"{len(a.xml):,}", f"{len(b.xml):,}"),
    ]
    for name, va, vb in rows:
        mark = " " if va == vb else "*"
        if va != vb:
            same = False
        print(f"{mark}{name:<11} {va:<28} {vb:<28}")

    if a.xml == b.xml:
        print("\nXML payloads are byte-identical.")
        return 0

    same = False
    if args.unified:
        diff = difflib.unified_diff(
            _xml_text(a.xml),
            _xml_text(b.xml),
            fromfile=str(args.file_a),
            tofile=str(args.file_b),
            n=args.context,
        )
        sys.stdout.writelines(diff)
    else:
        print("\nXML payloads differ. Re-run with --unified for a text diff.")
    return 0 if same else 1


# --------------------------------------------------------------------------
# CLI wiring
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog=_PROG,
        description="Read, write and compare Cisco Packet Tracer .pkt/.pka containers.",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("info", help="describe a container")
    p.add_argument("file", type=Path)
    p.add_argument("--no-verify", action="store_true", help="skip AEAD tag check")
    p.add_argument("--json", action="store_true", help="also print machine-readable output")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("unpack", help="extract the inner XML and metadata")
    p.add_argument("file", type=Path)
    p.add_argument("-o", "--output", type=Path, required=True, help="output directory")
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("pack", help="build a container from XML")
    p.add_argument("file", type=Path, help="input XML file")
    p.add_argument("-o", "--output", type=Path, required=True)
    p.add_argument("--format", default=DEFAULT_FORMAT, choices=sorted(FORMATS))
    p.add_argument("--level", type=int, default=-1, help="zlib level (-1 default)")
    p.add_argument("--force", action="store_true", help="overwrite the output")
    p.add_argument("--verify", action="store_true", help="decode again and compare")
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("diff", help="compare two containers")
    p.add_argument("file_a", type=Path)
    p.add_argument("file_b", type=Path)
    p.add_argument("-u", "--unified", action="store_true", help="emit a unified XML diff")
    p.add_argument("-C", "--context", type=int, default=3)
    p.set_defaults(func=cmd_diff)

    return ap


def main(argv: Sequence[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    try:
        return int(args.func(args))
    except PacketTracerError as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
