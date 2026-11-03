# RE-001: node #115 .init_array registration and initializer FDE extents

- Component: foundation / process initialization (RE-001 #115 function map).
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: which initializer pointers does node #115 register in `.init_array`,
  and what authenticated FDE extent and raw unwind record does each one have?
- Scope: one table. Static bytes only. No target execution, no emulation, no
  reconstruction or gate claim. No dependency byte window is claimed here.

## What the bytes show

| Item | Value |
| --- | --- |
| `.eh_frame` | VA `0xca6ed8`, size 7,803,772 |
| `.init_array` | VA `0x63f36c8`, file `0x63f16c8`, size 1,344 (168 slots) |
| slots bound by `R_X86_64_RELATIVE` | 168 / 168 |
| targets inside a covering FDE | 167 |
| targets with no covering FDE | 1 (`slot 0x63f36d0 -> 0x14193e0`) |
| `.eh_frame` tables | 135,313 FDE, 3 CIE |
| entry-map digest | `c69a12ec70260c4d9b01789de2b6eb52c0659ee4a7e371483e85637ad97f2f35` |

Every `.init_array` slot is bound by an `R_X86_64_RELATIVE` entry in
`.rela.dyn`, so the stored eight-byte slot value is zero and the initializer
address is the relocation addend. The entry-map digest is SHA-256 over one
`%x %x %x %x\n` line per slot in ascending slot order: slot, resolved target,
covering FDE start, covering FDE end (or `%x %x none\n` when no FDE covers the
target).

Initializer extents are the half-open range of the covering `.eh_frame` FDE,
not the next unwind-index start. Three examples:

| Slot | Target | FDE extent | Bytes | FDE record loc | CIE loc |
| --- | --- | --- | ---: | --- | --- |
| `0x63f36c8` | `0x5ca55c0` | `0x5ca55c0..0x5ca55d2` | 18 | `0x33baac` | `0x0` |
| `0x63f36d8` | `0x5d20090` | `0x5d20090..0x5d200c3` | 51 | `0x3435c4` | `0x0` |
| `0x63f36f0` | `0x5d83f80` | `0x5d83f80..0x5d8479b` | 2075 | `0x73513c` | `0x730230` |

The raw FDE and CIE record bytes for the recorded detail entries are in
`evidence.json` (`record_bytes`, `cie_bytes`) and the matching native readelf
frame lines, unmodified, are in `frames.txt`. Each recorded FDE's frame-link
field equals `record_loc + 4 - cie_loc` for all 167 bounded extents.

The distinct CIE at `0x730230` is a second unwind personality
(`zPLR`, personality-encoded LSDA) used by the larger C++-style initializers;
the small initializers use the CIE at `0x0`.

## Inferences (kept separate from the bytes)

- Names of the initializers are not recovered. No symbol, comment or upstream
  source is used to label a target.
- `slot 0x63f36d0 -> 0x14193e0` has no covering FDE. Whether that target is a
  real code entry, a thunk, or data is **unresolved**.
- Which of these initializers are first-party node code versus C++ runtime
  static initialization is **not established here**; therefore no dependency
  window and no first-party byte count is claimed.

## Limits

- Static parsing of the pinned capture only. The captured binary was never
  executed, emulated or traced; no behaviour, ordering or effect of the
  initializers is claimed.
- Only 9 of the 168 entries are recorded as detail entries. The full table is
  pinned by the entry-map digest and by the counts above, not by 168 separate
  records.
- No `.text` byte comparison, no source attribution, no #94 correspondence and
  no reconstruction gate is advanced by this packet.

## Reproduce

The checker re-derives every recorded value from the pinned bytes and rejects
corrupted claims. `MANIFEST.sha256` is written from the saved files.

```sh
python3 tools/foundation_init_array.py
```
