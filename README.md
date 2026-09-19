# mechadec — Sony SPC970 decompiler, processor module and ROM loader

The SPC970 is Sony's 16-bit MCU core. It is the CPU inside the PlayStation 2
**MechaCon** (CXR706080 / CXP102064 and relatives), the chip that drives the
optical block, the RTC and EEPROM, the SCMD/NCMD host protocol and MagicGate.

This repository carries three things that share one ISA model:

```
loaders/mechacon.py   recognise a 256 KiB dump, map the banks, name what is known
procs/spc970.py       IDA 9.x processor module  (disassembly, xrefs, stack frames)
mechadec/             the decompiler:
        loader -> decoder -> lifter -> cfg -> opt -> structure -> cgen
```

The processor module does not restate the encoding — it drives `mechadec`'s
decoder, so the disassembler and the decompiler cannot disagree about what a
byte sequence means.

The ISA model is a Python re-implementation of DiscoStarslayer's Ghidra SLEIGH
specification, [ghidra-spc970](https://github.com/DiscoStarslayer/ghidra-spc970).
The pipeline follows the sibling tools [`spudec`](https://github.com/zecoxao/spudec),
[`rl78dec`](https://github.com/zecoxao/rl78dec), [`f00ddec`](https://github.com/zecoxao/f00ddec)
and [`startrekdec`](https://github.com/zecoxao/startrekdec).

## Why the decoder looks the way it does

SPC970 is a **prefix machine**, not a fixed opcode map. The first byte usually
selects an *addressing mode* and pushes the decoder into one of eight tables; a
later byte selects the *operation*, which then binds that pending operand. Two
prefixes can stack, which is how the genuine memory-to-memory forms are
encoded. So a byte means nothing on its own — only relative to the decoder
state that reached it.

```
phase 0   first byte              table 1
phase 1   after a tbl2 prefix     table 2   general addressing
phase 2   after a tbl3 prefix     table 3   immediate
phase 3   after 0x10..0x17        table 4   register direct, mul/div/shift
phase 4   after 0xF3              table 5   long branch, jmp/jsr, push/popc
phase 5   after a second prefix   table 6   two-operand memory to memory
phase 6   after tbl2 op 0xE2      table 7   32-bit and bit operations
phase 7   after tbl3 op 0xE2/0xE7 table 8   32-bit immediate
```

The consequence worth knowing: **the operand width belongs to the operation,
not to the prefix.** The same `0xC4` register-direct prefix yields a byte, a
word or a long operand depending only on the operation byte that follows. A
prefix therefore decodes to an addressing mode with no width, and the
operation stamps the width on.

Instructions are 1–9 bytes and unaligned, so a decoder that starts one byte off
produces plausible-looking nonsense rather than an obvious error. That is why
entry-point discovery is deliberately conservative (below).

## What the decoder was checked against

The MechaCon startup routine has an exact byte signature recorded independently
in the Ghidra loader (it is how that loader recognises a ROM and finds its
primary bank), so it is a reference encoding that nobody writing this decoder
chose. It decodes as:

```
FC0000  E6 00              LINK   xFP,#0
FC0002  D8 E8 7A 09        MOV.W  #0,[0x097A]
FC0006  36 CC              MOV.W  @(6,FP),RW4
FC0008  06 0A              BNE    →FC0014   ─┐
FC000A  D8 E8 78 09        MOV.W  #0,[0x0978]│
FC000E  EA 00 01 E8 7A 09  MOV.W  #0x100,…   │
FC0014  E8 78 09 CC        MOV.W  [0x0978],RW4 ←┘
FC0018  07 04              BEQ    →FC001E   ─┐
FC001A  EC 02 E6 FF        PJSR   0xFFE602   │
FC001E  E2 80 …           ←────────────────────┘
```

Both branch targets land exactly on instruction boundaries the decoder derives
independently, which a wrong instruction length would break. `tests/` asserts
this.

On a real CXP102064 ROM, recursive descent from the discovered entries decodes
~40 000 instructions and reaches an encoding the decoder cannot represent
**once**, out of 17 375 reachable targets from the table-derived entries. That
one site sits past a `TJSR`, whose vector table the SLEIGH reference documents
as unrecovered ("no confirmed executed sample"), so descent past it is
speculative by nature. The tests bound the rate rather than claiming zero,
because zero is not something a recursive-descent decoder can promise.

## One place this disagrees with the SLEIGH reference

Table 4's two-operand shifts. SLEIGH models `SHLL RW4,RW5` as
`RW5 = RW4 << 1` — a shift by one, into the op-byte register. On this ROM that
leaves a dead constant load in front of 131 of the 150 shift sites:

```
FC023B  MOVXU  [0x966],RW4
FC0240  MOV    #3,RW5        ; dead under the SLEIGH reading
FC0242  SHLL   RW4,RW5
FC0246  MOV    #0x744,RW0
FC0249  ADD    RW4,RW0       ; RW4 is what is used afterwards, not RW5
```

The op-byte register is the **shift count** and the prefix register is the
value *and* the destination: `RW4 <<= RW5`, giving `ptr = 0x744 + (index << 3)`
— ordinary indexing into an 8-byte-per-entry table. Evidence: the count
register is loaded with a small constant immediately before 131/150 sites (the
prefix register, once), and it is the prefix register that is read afterwards.
mechadec lifts it that way; `tests/test_pipeline.py` pins it.

## Entry-point discovery

Because a wrong start address yields convincing garbage, discovery is layered
and conservative:

1. the primary bank base, the far vectors at `0xFFFF90`/`0xFFFF9C`, and the
   reset vector when it resolves;
2. the MechaCon dispatch tables — SCMD main, SCMD 03 subcommands, the two NCMD
   tables, PMAP, MagicGate — plus the signature-anchored SFR helpers;
3. every 24-bit ROM pointer stored anywhere in the image **whose target begins
   with a real function prologue** (`LINK` or `STM`);
4. the call targets recursive descent finds from all of the above, iterated to
   a fixed point.

Step 3 accepts only a prologue on purpose. Accepting any decodable target
raises raw byte coverage from 65% to 90% and is worse: the extra "code" is data,
and it shows up as a flood of `BRA` (9 810 versus 1 879). Under-decoding is the
right failure here.

On a CXP102064 ROM this finds 1 102 entry points and names 281 handlers.

## Use

Headless, no IDA needed:

```sh
python -m mechadec mechacon.bin -o mechacon.c
python -m mechadec mechacon.bin --list            # tables and named handlers
python -m mechadec mechacon.bin --asm 0xFC0000    # raw disassembly
python -m mechadec mechacon.bin --func 0xFC1986   # one function
```

In IDA, put `mechadec/` and `mechadec_plugin.py` in `plugins/`, `spc970.py` in
`procs/` and `mechacon.py` in `loaders/`:

```
Ctrl-Shift-S   decompile the function under the cursor
Ctrl-F5        decompile everything
Ctrl-Shift-M   apply the recovered MechaCon names to the database
```

The plugin carries its own decoder, so it works whether the database was made
with the `spc970` processor module or the ROM was loaded as a plain blob at
`0xFC0000`.

## Sample output

```c
void SCMD_81_MG_SessionInit(void)
{
    link(xFP, 4);   /* frame setup */
    push_regs(regs(RW2, RW3));
    mem8[xFP - 2] = 0x80;
    RW4 = ram_0978;
    if (ram_0978 != 0) {
        if (ram_1727 != 1) goto loc_FC19D1;
        ram_0978 = 1;
        mem8[xFP - 4] = ram_1728;
        RB2 = 0x3F & mem8[xFP - 4];
        RB3 = mem8[xFP - 4];
        RB3 = RB3 >> 6;
        ...
```

## Tests

```sh
python -m unittest mechadec.tests.test_decoder mechadec.tests.test_pipeline
```

They run without IDA and without a ROM. Point `MECHADEC_TEST_ROM` at a MechaCon
dump to additionally enable the whole-image checks.

## Scope, honestly

* `TJSR`'s call table is not recovered; it is emitted as a `table_call`
  intrinsic. Nothing in the available corpus pins it down.
* Coverage is ~65% of non-zero ROM bytes. The remainder is mostly genuine data
  — string tables, DSP configuration blocks, the dispatch tables themselves.
* The decimal-adjust pair, the context/trap group and `LDM`/`STM` are emitted
  as pseudo-calls rather than guessed at.
* Comparisons derived from the X flag are unsigned and those from M^V are
  signed; the generated C uses the same operators for both, so read the flag
  note in the banner.

## Licence

MIT.
