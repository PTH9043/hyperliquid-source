# RE-001: node #115 FDE body `0x141b610..0x141b633`

- Component: foundation (RE-001, #115 function map).
- Target: Linux x86-64 node #115, 105,896,032 bytes; SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Window: half-open VA range `0x141b610..0x141b633`, 35 bytes.
- Question: what does this complete FDE body compute - which value is
  compared, which call it makes, and what are its two results?

This is a new bounded packet. It records one FDE body only. It makes no
whole-component, reconstruction or equivalence claim and does not execute
the target.

## Recorded target identity

The verifier recomputes the SHA-256 of `artifacts/node/115/hl-node` before
any assertion. The digest printed by the recorded run is
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Recorded FDE record

From the retained `readelf --debug-dump=frames` output (unwind-table entry
offset `0xfc`, record length `0x14`, CIE `00000000`):

```
000000fc 0000000000000014 00000100 FDE cie=00000000 pc=000000000141b610..000000000141b633
```

The end address is taken from this FDE record, not from the next unwind
entry.

## Observed body

`objdump -d --start-address=0x141b610 --stop-address=0x141b633`:

```
 141b610: 31 c0             xor    %eax,%eax
 141b612: 48 3b 06          cmp    (%rsi),%rax
 141b615: 71 1b             jno    141b632
 141b617: 50                push   %rax
 141b618: 48 8b 46 08       mov    0x8(%rsi),%rax
 141b61c: 48 8b 77 08       mov    0x8(%rdi),%rsi
 141b620: 48 8b 57 10       mov    0x10(%rdi),%rdx
 141b624: 48 89 c7          mov    %rax,%rdi
 141b627: e8 94 f2 ff ff    call   141a8c0
 141b62c: b0 04             mov    $0x4,%al
 141b62e: 48 83 c4 08       add    $0x8,%rsp
 141b632: c3                ret
```

Twelve native instructions over 35 bytes. The body has two exits: the guard
at `0x141b615` jumps to the single `ret` and returns the zero already in
`%eax`; the fall-through path pushes one word, reloads three fields, calls
`0x141a8c0`, returns `0x04` in `%al` and discards the pushed word with
`add $0x8,%rsp`.

## Dependency identity

The target carries no first-party symbol for this address. `objdump` builds the
label from the nearest exported `.dynsym` symbol,
`_ZNKSt5ctypeIcE8do_widenEc@@Base`, a libstdc++ `std::ctype<char>` member; the
window itself has no symbol entry. Following CONTRIBUTING.md this is recorded
as a **dependency window**: it counts only in target totals and the dependency
table, never as reconstructed first-party component bytes. The dependency
identity is `libstdc++` and the recorded evidence is the `objdump` label next
to the window in `frames.txt`.

## Inference (kept apart from the observation)

`cmp (%rsi),%rax` with `%rax` cleared to zero computes `0 - qword[rsi]`.
`jno` therefore takes the early return unless that qword is
`0x8000000000000000`, the only operand whose subtraction from zero sets the
overflow flag. Under that reading the guard returns `0` for every value
except the signed minimum. This is a flag inference from the recorded
encodings; the packet does not emulate or run the target.

## Status

The checker, its committed test, `evidence.json` and the raw excerpts are
added in the following edits. Until those files exist the verifier fails on
the missing files, which is expected progress.

## Limits

Only the recorded bytes of this one FDE body. The call target `0x141a8c0`,
the caller set, the meaning of the compared word and the return-value
enumeration are not established here. No execution, no network, no
reconstruction credit.
