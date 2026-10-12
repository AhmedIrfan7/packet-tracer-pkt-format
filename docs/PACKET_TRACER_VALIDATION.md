# Validation against the real Packet Tracer application

The project proves `encode(decode(f)) == f` **byte-for-byte on 1,058 real
containers**, which is the strongest available evidence that the codec is
correct. This document covers the *other* claim in the brief: that the Packet
Tracer application itself accepts what we write.

## Status

| Check | Result |
| --- | --- |
| Container round-trip byte-exact | **1058 / 1058** |
| Packet Tracer opens a repacked file | **blocked on a Cisco account** — see below |

Harness: [`tools/verify_in_packet_tracer.sh`](../tools/verify_in_packet_tracer.sh).

## What was done

Cisco Packet Tracer **9.0.1** was obtained (the exact build the format
specification derives from, matching the corpus maximum `<VERSION>9.0.1.0858`),
installed, and run headless under Xvfb.

The application **starts, renders, and reports no load error** for the test
file — the log contains only Content-Security-Policy noise from its embedded
web view (doubleclick/linkedin telemetry), nothing about the file.

## Why visual confirmation is blocked

PT 9.0.1 will not proceed past its start screen without a **Cisco Networking
Academy login**:

> *Cisco Packet Tracer — LOGIN. By using Cisco Packet Tracer you accept Terms
> of Service (General Terms & SEULA) and the Privacy Statement.*

`Advanced Settings` offers only two options:

* "Use internal web browser for Cisco Networking Academy login"
* Proxy settings

**There is no offline or guest mode.** Fabricating or borrowing credentials is
not something this project will do, so the final "watch the topology render"
step is not completable against PT 9.x from this environment.

## Path to completion

Older Packet Tracer builds ran without an account. PT **8.2.x** and especially
PT **7.3.x** are the candidates; PT 7.3.1 is additionally the exact version
that wrote a substantial part of the corpus (`<VERSION>7.3.1.0362`, 98 files).

```console
$ tools/verify_in_packet_tracer.sh /path/to/7.3.1/opt/pt/bin/PacketTracer \
      /tmp/pt_validation/repacked_0.pkt /tmp/repacked.png
$ tools/verify_in_packet_tracer.sh /path/to/7.3.1/opt/pt/bin/PacketTracer \
      /tmp/pt_validation/orig_0.pkt /tmp/original.png
```

The two screenshots should be identical.

## Reproducing the test files

```console
$ python3 -c "
from pkt_core import decode_bytes, encode_bytes
raw = open('corpus/samples/sample_lab.pkt','rb').read()
c = decode_bytes(raw)
assert encode_bytes(c.xml, c.format_name) == raw
open('/tmp/repacked.pkt','wb').write(encode_bytes(c.xml, c.format_name))
"
```

## Version notes

| Version | Login wall | Notes |
| --- | --- | --- |
| 9.0.1 | **Yes — mandatory** | Installed and exercised here; confirmed no offline mode |
| 8.2.x | Likely | Not yet tried |
| 7.3.x | No | Target for the visual check |
| 6.0.1 and earlier | No | Very old container (see `LEGACY_FORMAT.md`) |

Note that PT 9.0.1 is the *right* binary to test against for the modern
container — it is the build the spec was derived from. If PT 7.3.x opens a
repacked file, that is meaningful evidence for the whole modern family, since
the container is byte-identical across 5.3.3 – 9.0.1.
