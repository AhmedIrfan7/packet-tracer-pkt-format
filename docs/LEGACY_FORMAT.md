# The legacy Packet Tracer container (PT 5.x) — Family L

**Status: SOLVED and verified byte-exact on 193 real files.**

This is the population that defeated the modern codec with `EAX tag mismatch`.
It is not a harder variant of the modern container — it is a strictly simpler one.

---

## 1. The result

```
legacy (PT 5.x)                    modern (PT 6.0 - 9)
-----------------                  ---------------------------------
raw bytes F                        raw bytes F
  |                                  | layer A : reverse + positional XOR
  |                                  v
  | layer B : XOR (n - i)            AEAD: Crypto++ EAX over Twofish
  |                                  |   (key 0x89*16, IV 0x10*16, 16-byte tag)
  v                                  v
qCompress : BE length + zlib       layer B : XOR (m - i)
  |                                  v
  v                                qCompress : BE length + zlib
UTF-8 XML                            v
                                   UTF-8 XML
```

**There is no AEAD layer and no byte reversal in the legacy family.** The entire
transform is `Util::deobfuscateBytes` applied over a Qt `qCompress` payload.

```python
# decode
payload = layer_b(file_bytes)          # P[i] ^= (n - i) & 0xFF
xml     = zlib.decompress(payload[4:])
assert len(xml) == be_u32(payload[:4])

# encode  (layer_b is an involution)
payload = be_u32(len(xml)) + zlib.compress(xml)
file    = layer_b(payload)
```

## 2. Verification

| Check | Result |
| --- | --- |
| Decode to well-formed XML | **193 / 193** |
| `encode(decode(f)) == f` byte-for-byte | **193 / 193** |
| Declared qCompress length == inflated length | 193 / 193 |
| Root element | `PACKETTRACER5` and `PACKETTRACER5_ACTIVITY` — same document model as modern |
| `<VERSION>` values seen | `5.1` (PT 5.x generation) |

The one item in the failure set that does not decode is
`bbent-cis202__AllPkaFiles.zip`, which is a ZIP archive and not a container at
all.

Both document kinds appear in this family, exactly as in the modern one — the
`.pkt` / `.pka` distinction is a root-element distinction, not a container one.

## 3. Why this is easy to miss

The two families look identical from the outside: **neither has a magic header**,
and both begin with high-entropy bytes. The difference is only visible *after*
attempting a transform:

| Probe | Legacy | Modern |
| --- | --- | --- |
| `layer_b` then check for `78 9c` at offset 4 | **matches** | no |
| `layer_a` + EAX tag verify | no | **matches** |
| Reversal present? | no | yes |

A naive implementation that assumes the modern stack will report "corrupt file"
for perfectly good PT 5.x files, because it is looking for an authentication tag
that was never written.

## 4. Hypothesis ladder — what was actually tried

The investigation was run cheapest-first, with an oracle at each rung. Recording
the negatives matters as much as the result.

| Rung | Hypothesis | Outcome |
| --- | --- | --- |
| L1 | Same AEAD, different `(cipher, keyByte, ivByte)` from the shipped `Util::` table (Serpent `0xab/0x23`, `0xab/0xcd`, CAST256 `0x12/0xfe`, `0xf1/0x1f`, Twofish `0xba/0xbe`) | **FAIL** — no parameter authenticated |
| L2 | Same AEAD, any repeated-byte key × any repeated-byte IV (65,536 combos per cipher) | **FAIL** — the space is exhausted without a single tag match, which is strong evidence there is no AEAD at all |
| **L3** | **No AEAD and no reversal — `layer_b` then qCompress** | **SUCCESS — 193/193, byte-exact round-trip** |
| L4 | Alternative positional XOR / reversal variants | not reached (L3 closed it) |
| L5 | Legacy block cipher (Blowfish/DES/RC4/TEA) | not reached |
| L6 | Different inner document model | **FALSE** — same `PACKETTRACER5` / `PACKETTRACER5_ACTIVITY` roots |

The decisive negative was L2: an exhaustive search of the plausible key space
producing *zero* tag matches is not "we haven't found the key yet", it is "there
is no tag to find". That redirected the search to the unencrypted hypothesis.

## 5. Population and provenance

193 files, from two independent lineages:

| Population | Files | Provenance |
| --- | --- | --- |
| `bbent-cis202-PTA2011__*` | 60 | Official Cisco NetAcad PTA curriculum (IT-Essentials / CCNA-1 ch. 1–11). `AllPkaFiles.zip` last-modified 2011-08-16. |
| `abderaoufsec__CCNA-PacketTracerlabs__*` | 129 | Older-generation members of a *mixed* repo (224 other files in the same repo use the modern container) |
| `Rakibul73__…__{1,2,4,8}.pka` | 4 | — |

`abderaoufsec` is the most useful of these for research: the same topic material
exists in **both** containers within one repository, holding content constant and
varying only the container.

## 6. Implementation

`pkt_core` models this as the `"legacy"` flavour
(`pkt_core.crypto.keys.FORMATS["legacy"]`, `FormatSpec.is_legacy`).

Detection order in `pkt_core.codec.container.detect_format`:

1. Try each modern flavour; accept the first whose **EAX tag verifies**
   (false-positive rate 2⁻¹²⁸).
2. Otherwise, if `layer_b(raw)` yields a plausible big-endian length followed by
   a zlib magic (`78 01` / `78 5e` / `78 9c` / `78 da`), classify as `"legacy"`.

The legacy check is structural, not cryptographic — there is no tag to consult —
so it is gated on both the length plausibility and the zlib magic, and then
confirmed exactly when the inflated size matches the declared length. That is
what `quncompress` enforces.

## 7. Open items

* The precise **PT version boundary** is narrowed to "before the modern container"
  but not pinned to a build number. The 2011 NetAcad set is PT 5.x (`<VERSION>5.1`);
  the earliest confirmed modern member is PT 6.0 (2014). A PT 5.3.x sample would
  close the gap.
* Whether `Util::` in PT 5.x named this path differently (there is no
  `decryptPTSave` to call in the modern sense) has not been established from a
  PT 5.x binary; the transform is established from the files themselves.
* The `.pta` / `.pkc` (Serpent) and `sm` / `userapp` (CAST-256) flavours are
  specified but not exercised by the `.pkt`/`.pka` corpus.

## 8. Reproducing the proof

```console
$ python3 corpus/fetch_corpus.py --out corpus/files      # or use the local corpus
$ python3 -m pytest tests/test_legacy.py -q               # includes byte-exact round-trip
```

`tests/test_legacy.py::test_real_legacy_roundtrip_is_byte_exact` is the
authoritative assertion: it requires `encode(decode(f)) == f` for **every**
fetched legacy file.
