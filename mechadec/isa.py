"""
Sony SPC970 instruction-set description.

The SPC970 is Sony's 16-bit MCU core; it is the CPU inside the PlayStation 2
"MechaCon" (CXR706080 / CXP102064 and relatives), which drives the optical
block, the RTC/EEPROM, the SCMD/NCMD host protocol and MagicGate.  This module
is the single source of truth for register names, flag effects and the memory
map.  The encoding model in :mod:`mechadec.decoder` follows DiscoStarslayer's
Ghidra SLEIGH specification (``ghidra-spc970``), and the lifter follows its
p-code semantics.

Encoding model
--------------
SPC970 is a *prefix* machine, not a fixed opcode map.  The first byte usually
selects an addressing mode and pushes the decoder into one of eight tables; a
later byte selects the actual operation, which then binds that pending operand.
Two prefixes can stack, giving genuine memory-to-memory forms (table 6).

    phase 0   first byte              table 1
    phase 1   after a tbl2 prefix     table 2   (general addressing)
    phase 2   after a tbl3 prefix     table 3   (immediate)
    phase 3   after 0x10..0x17        table 4   (register direct, mul/div/shift)
    phase 4   after 0xF3              table 5   (long branch, jmp/jsr, push/popc)
    phase 5   after a second prefix   table 6   (two-operand mem-to-mem)
    phase 6   after tbl2 op 0xE2      table 7   (32-bit / bit ops)
    phase 7   after tbl3 op 0xE2/0xE7 table 8   (32-bit immediate)

Address space
-------------
    ram   24-bit, byte addressed.  Data accesses below 0x10000 are internal
          RAM; DP/EP supply the bank for register-indirect forms.
    io    8-bit special-function registers, reached by the BSET/BCLR/BBC/BBS
          short forms in table 1.

On MechaCon the 256 KiB mask ROM is mapped at 0xFC0000..0xFFFFFF as four
64 KiB banks and internal RAM lives at 0x000000..0x00FFFF.
"""

# ---------------------------------------------------------------------------
# registers
# ---------------------------------------------------------------------------

# Byte registers, encoding order 0..7.
RB = tuple("RB%d" % i for i in range(8))
# Word registers, encoding order 0..7 (6 and 7 alias the frame/stack pointer).
RW = ("RW0", "RW1", "RW2", "RW3", "RW4", "RW5", "FP", "SP")
# Long (32-bit) registers, encoding order 0..7.
RL = tuple("RL%d" % i for i in range(8))
# The 24-bit pointer view of a word register, used by every indirect form.
RP = ("RW0", "RW1", "RW2", "RW3", "RW4", "RW5", "xFP", "xSP")

# Control registers, encoding order 0..7 (index 5 is the full PSW, 4 its low
# byte).  Index 5 is only reachable through the cwReg constructors.
CTRL = ("UTP", "DP", "EP", "STP", "CCR", "PSW", "IM", "BCR")

WORD_REGS = frozenset(RW + ("wFP", "wSP", "PSW", "PC", "SSP", "USP"))
LONG_REGS = frozenset(RL + ("xFP", "xSP"))
PTR_REGS = frozenset(("xFP", "xSP"))

WIDTH_BYTES = {"b": 1, "w": 2, "l": 4}
WIDTH_SUFFIX = {"b": ".B", "w": ".W", "l": ".L"}


def reg_for(index, width):
    """The register named by a 3-bit field at the given operand width."""
    if width == "b":
        return RB[index]
    if width == "l":
        return RL[index]
    return RW[index]


# ---------------------------------------------------------------------------
# flags  --  PSW: IM[15:13] BCR[12:8] S I - - M V X Z
# ---------------------------------------------------------------------------
# X is the carry/extension flag, M the negative (MSB) flag.  Branches read
# Z, X, V and M; unsigned relations come from X, signed ones from M^V.
CC = ("RA", "RN", "HI", "LS", "XC", "XS", "NE", "EQ",
      "VC", "VS", "MC", "MS", "GE", "LT", "GT", "LE")

# Condition code -> the IR condition token used by structure.cond_expr.
CC_COND = {
    0x0: None,        # BRA, unconditional
    0x1: "never",     # BRN, never taken
    0x2: "hi", 0x3: "ls",
    0x4: "nx", 0x5: "x",
    0x6: "nz", 0x7: "z",
    0x8: "nv", 0x9: "v",
    0xA: "nm", 0xB: "m",
    0xC: "ge", 0xD: "lt",
    0xE: "gt", 0xF: "le",
}

# Mnemonics whose result defines Z/M (and, for the arithmetic group, X/V).
SETS_FLAGS = frozenset((
    "MOV", "XOR", "OR", "AND", "ADD", "ADDX", "SUB", "SUBX", "CMP",
    "NOT", "NEG", "INC", "DEC", "MULU", "MUL", "DIVU", "DIV",
    "SHAL", "SHAR", "SHLL", "SHLR", "ROTL", "ROTR", "SHXL", "SHXR",
    "DADDX", "DSUBX", "MOVA", "MOVX", "MOVXU",
))
# The subset that yields a real two-operand relation for branch recovery.
COMPARES = frozenset(("CMP",))
SUBTRACTS = frozenset(("SUB", "SUBX"))

# Bit instructions that only touch X (the carry flag).
BIT_TO_X = frozenset(("BXOR", "BOR", "BAND", "BLD"))
BIT_RMW = frozenset(("BSET", "BCLR", "BNOT", "BST"))

# ---------------------------------------------------------------------------
# control flow
# ---------------------------------------------------------------------------
BRANCH = frozenset(("BRA", "BRN", "BHI", "BLS", "BXC", "BXS", "BNE", "BEQ",
                    "BVC", "BVS", "BMC", "BMS", "BGE", "BLT", "BGT", "BLE"))
BIT_BRANCH = frozenset(("BBC", "BBS"))
LOOP_BRANCH = frozenset(("DBNZ",))
CALL = frozenset(("JSR", "PJSR", "TJSR"))
RET = frozenset(("RTS", "PRTS", "REIT"))
JUMP = frozenset(("JMP", "PJMP"))
HALT = frozenset(("SLEEP", "STOP", "TRAPE"))

# Instructions that terminate a basic block outright.
STOP = RET | JUMP | HALT | frozenset(("BRA",))

# Shift/rotate mnemonic -> IR operator ('?' means an intrinsic is emitted).
SHIFTS = {
    "SHAL": "<<", "SHLL": "<<", "SHAR": "?", "SHLR": ">>",
    "ROTL": "?", "ROTR": "?", "SHXL": "?", "SHXR": "?",
}

# ---------------------------------------------------------------------------
# memory map
# ---------------------------------------------------------------------------
RAM_BASE = 0x000000
RAM_SIZE = 0x010000
ROM_BASE = 0xFC0000
ROM_END = 0xFFFFFF
ROM_SIZE = 0x040000
BANK_SIZE = 0x010000
ADDR_MASK = 0xFFFFFF


def is_rom(addr):
    return ROM_BASE <= (addr & ADDR_MASK) <= ROM_END


def is_ram(addr):
    return (addr & ADDR_MASK) < RAM_SIZE
