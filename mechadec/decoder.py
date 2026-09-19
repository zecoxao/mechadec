"""
Sony SPC970 instruction decoder.

A byte-stream, little-endian, variable-length decoder for the eight-table
prefix machine described in :mod:`mechadec.isa`.  It is a Python
re-implementation of the constructor set in DiscoStarslayer's ``ghidra-spc970``
SLEIGH specification, arranged as an explicit phase machine rather than as
context-register constraints.

The key idea is that a prefix byte fixes an *addressing mode* but not an
operand width: the same 0xB4 prefix yields a byte, word or long access
depending on which operation byte follows it.  A prefix therefore decodes to an
:class:`Arg` (mode only), and the operation binds it with
:meth:`Arg.operand`, which stamps the width on.

Operand ``mode`` values produced here:

    reg      register (``reg``)
    ctrl     control register (``reg``)
    imm      immediate (``value``, ``width``)
    abs      absolute data address (``addr``, ``width``, ``space``)
    disp     @(disp, base)          (``base_reg``, ``disp``, ``width``)
    ind      @(base)                (``base_reg``, ``width``)
    predec   @(-base)               (``base_reg``, ``width``)
    postinc  @(base+)               (``base_reg``, ``width``)
    pop      @(SP+)                 (``width``)
    addrof   effective address of another operand (``base``)
    bit      one bit of another operand (``base``, ``bit``)
    code     branch/call target (``addr``)
    reglist  LDM/STM register set (``regs``)
"""

from . import isa

# ---------------------------------------------------------------------------
# operands
# ---------------------------------------------------------------------------


class Operand:
    __slots__ = ("mode", "reg", "value", "addr", "base_reg", "disp",
                 "bit", "base", "width", "space", "regs")

    def __init__(self, mode, reg=None, value=0, addr=0, base_reg=None,
                 disp=0, bit=0, base=None, width="b", space="ram", regs=()):
        self.mode = mode
        self.reg = reg
        self.value = value
        self.addr = addr
        self.base_reg = base_reg
        self.disp = disp
        self.bit = bit
        self.base = base
        self.width = width
        self.space = space
        self.regs = regs

    def __repr__(self):
        return "<Op %s %s>" % (self.mode, self.reg or hex(self.addr))


class Arg:
    """An addressing mode contributed by a prefix byte.  ``kind`` is one of
    ``fp``/``abs11``/``rdisp``/``rind``/``rdir``/``abs16``/``abs24``/``pop``/
    ``predec``/``postinc``/``imm``; the operand width is supplied later by the
    operation byte."""

    __slots__ = ("kind", "index", "disp", "addr", "value")

    def __init__(self, kind, index=0, disp=0, addr=0, value=0):
        self.kind = kind
        self.index = index
        self.disp = disp
        self.addr = addr
        self.value = value

    def operand(self, width):
        k = self.kind
        if k == "fp":
            return Operand("disp", base_reg="xFP", disp=self.disp, width=width)
        if k == "abs11":
            return Operand("abs", addr=self.addr, width=width)
        if k == "rdisp":
            return Operand("disp", base_reg=isa.RP[self.index], disp=self.disp, width=width)
        if k == "rind":
            return Operand("ind", base_reg=isa.RP[self.index], width=width)
        if k == "rdir":
            return Operand("reg", reg=isa.reg_for(self.index, width), width=width)
        if k in ("abs16", "abs24"):
            return Operand("abs", addr=self.addr, width=width)
        if k == "pop":
            return Operand("pop", width=width)
        if k == "predec":
            return Operand("predec", base_reg=isa.RP[self.index], width=width)
        if k == "postinc":
            return Operand("postinc", base_reg=isa.RP[self.index], width=width)
        if k == "imm":
            return Operand("imm", value=self.value, width=width)
        return Operand("imm", value=0, width=width)

    def address_operand(self):
        """The *address* an addressing mode denotes, for PUSHA."""
        op = self.operand("w")
        if op.mode in ("reg", "imm"):
            return op
        return Operand("addrof", base=op, width="w")


class Insn:
    __slots__ = ("ea", "size", "mnem", "ops", "width", "raw", "phase", "note")

    def __init__(self, ea):
        self.ea = ea
        self.size = 0
        self.mnem = None
        self.ops = []
        self.width = None
        self.raw = b""
        self.phase = 0
        self.note = ""

    def op(self, i):
        return self.ops[i] if i < len(self.ops) else None

    def __repr__(self):
        return "<Insn %06X %s>" % (self.ea, self.mnem)


# ---------------------------------------------------------------------------
# decoder state
# ---------------------------------------------------------------------------

_ALU1 = ("XOR", "OR", "AND", "SUBX", "ADDX", "SUB", "ADD", "CMP")
_BITOPS = ("BXOR", "BOR", "BAND", "BNOT", "BSET", "BCLR", "BLD", "BST")
_SHIFTS = ("SHAL", "SHAR", "SHLL", "SHLR", "ROTL", "ROTR", "SHXL", "SHXR")


class _Dec:
    def __init__(self, image, base, ea):
        self.image = image
        self.base = base
        self.start = ea - base
        self.pos = self.start
        self.ea = ea
        self.ins = Insn(ea)
        self.arg = None          # operand pending from the first prefix
        self.arg2 = None         # operand pending from the second prefix
        self.pwidth = "b"        # tbl2Width: byte or word family

    # -- byte stream --------------------------------------------------------

    def u8(self):
        b = self.image[self.pos]
        self.pos += 1
        return b

    def s8(self):
        v = self.u8()
        return v - 0x100 if v & 0x80 else v

    def u16(self):
        return self.u8() | (self.u8() << 8)

    def s16(self):
        v = self.u16()
        return v - 0x10000 if v & 0x8000 else v

    def u24(self):
        return self.u8() | (self.u8() << 8) | (self.u8() << 16)

    @property
    def next_ea(self):
        return self.base + self.pos

    # -- emit ---------------------------------------------------------------

    def done(self, mnem, *ops, **kw):
        ins = self.ins
        ins.mnem = mnem
        ins.ops = [o for o in ops if o is not None]
        ins.width = kw.get("width")
        ins.note = kw.get("note", "")
        ins.size = self.pos - self.start
        ins.raw = bytes(self.image[self.start:self.pos])
        return ins

    def bad(self):
        self.ins.mnem = None
        self.ins.size = 0
        return self.ins

    # -- helpers ------------------------------------------------------------

    def rel8(self):
        d = self.s8()
        return Operand("code", addr=(self.next_ea + d) & isa.ADDR_MASK)

    def rel16(self):
        d = self.s16()
        return Operand("code", addr=(self.next_ea + d) & isa.ADDR_MASK)

    def a(self, width):
        """Materialise the pending first operand at *width*."""
        return self.arg.operand(width) if self.arg is not None else None

    def b(self, width):
        return self.arg2.operand(width) if self.arg2 is not None else None


def _reg(index, width):
    return Operand("reg", reg=isa.reg_for(index, width), width=width)


def _ctrl(index):
    return Operand("ctrl", reg=isa.CTRL[index], width="w")


def _imm(value, width="b"):
    return Operand("imm", value=value, width=width)


def _bit(base, index):
    return Operand("bit", base=base, bit=index, width=base.width)


# ---------------------------------------------------------------------------
# phase 0  --  table 1
# ---------------------------------------------------------------------------


def _phase0(d):
    b = d.u8()
    hi, h3, lo = b >> 4, (b >> 3) & 1, b & 7
    nib = b & 0xF

    if hi == 0x0:                                   # B<cc> rel8
        return d.done("B" + isa.CC[nib], d.rel8())

    if hi == 0x1:
        if h3 == 0:                                 # table 4 prefix
            d.arg = Arg("rdir", index=lo)
            return _phase3(d)
        return d.done("TJSR", _imm(lo))             # implementation-defined table

    if hi in (0x2, 0x3):                            # @(simm4, FP)
        d.arg = Arg("fp", disp=nib - 16 if nib & 8 else nib)
        d.pwidth = "b" if hi == 0x2 else "w"
        return _phase1(d)

    if hi == 0x4:                                   # BSET/BCLR io8.bit
        port = Operand("abs", addr=d.u8(), width="b", space="io")
        return d.done("BCLR" if h3 else "BSET", _bit(port, lo))

    if hi == 0x5:                                   # BBC/BBS io8.bit, rel8
        port = Operand("abs", addr=d.u8(), width="b", space="io")
        return d.done("BBS" if h3 else "BBC", _bit(port, lo), d.rel8())

    if hi in (0x6, 0x7):                            # MOV/CMP #imm, reg
        mnem = "MOV" if hi == 0x6 else "CMP"
        if h3 == 0:
            return d.done(mnem, _imm(d.u8(), "b"), _reg(lo, "b"), width="b")
        return d.done(mnem, _imm(d.u16(), "w"), _reg(lo, "w"), width="w")

    if hi == 0x8:                                   # abs11 prefix
        d.pwidth = "w" if h3 else "b"
        d.arg = Arg("abs11", addr=(lo << 8) | d.u8())
        return _phase1(d)

    if hi == 0x9:                                   # @(simm16, reg) prefix
        d.pwidth = "w" if h3 else "b"
        d.arg = Arg("rdisp", index=lo, disp=d.s16())
        return _phase1(d)

    if hi == 0xA:                                   # @(simm8, reg) prefix
        d.pwidth = "w" if h3 else "b"
        d.arg = Arg("rdisp", index=lo, disp=d.s8())
        return _phase1(d)

    if hi == 0xB:                                   # @(reg) prefix
        d.pwidth = "w" if h3 else "b"
        d.arg = Arg("rind", index=lo)
        return _phase1(d)

    if hi == 0xC:                                   # register-direct prefix
        d.pwidth = "w" if h3 else "b"
        d.arg = Arg("rdir", index=lo)
        return _phase1(d)

    if hi == 0xD:                                   # small immediate prefix
        d.pwidth = "w" if h3 else "b"
        d.arg = Arg("imm", value=lo)
        return _phase2(d)

    return _phase0_tail(d, b)


def _phase0_tail(d, b):
    if b == 0xE0:
        d.pwidth = "b"
        d.arg = Arg("abs16", addr=d.u16())
        return _phase1(d)
    if b == 0xE1:
        d.pwidth = "b"
        d.arg = Arg("abs24", addr=d.u24())
        return _phase1(d)
    if b == 0xE2:
        d.pwidth = "b"
        d.arg = Arg("imm", value=d.u8())
        return _phase2(d)
    if b == 0xE4:                                   # JSR within the code page
        t = d.u16()
        return d.done("JSR", Operand("code", addr=(d.next_ea & 0xFF0000) | t))
    if b == 0xE5:
        t = d.u16()
        return d.done("JMP", Operand("code", addr=(d.next_ea & 0xFF0000) | t))
    if b == 0xE6:
        return d.done("LINK", Operand("reg", reg="xFP", width="l"), _imm(d.u8(), "b"))
    if b == 0xE7:
        d.pwidth = "b"
        d.arg = Arg("pop")
        return _phase1(d)
    if b == 0xE8:
        d.pwidth = "w"
        d.arg = Arg("abs16", addr=d.u16())
        return _phase1(d)
    if b == 0xE9:
        d.pwidth = "w"
        d.arg = Arg("abs24", addr=d.u24())
        return _phase1(d)
    if b == 0xEA:
        d.pwidth = "w"
        d.arg = Arg("imm", value=d.u16())
        return _phase2(d)
    if b == 0xEC:
        return d.done("PJSR", Operand("code", addr=d.u24()))
    if b == 0xED:
        return d.done("PJMP", Operand("code", addr=d.u24()))
    if b == 0xEE:
        return d.done("LINK", Operand("reg", reg="xFP", width="l"), _imm(d.u16(), "w"))
    if b == 0xEF:
        d.pwidth = "w"
        d.arg = Arg("pop")
        return _phase1(d)
    if b == 0xF1:
        return d.done("TRAPE")
    if b == 0xF2:
        v = d.u8()
        if v == 0xC8:                               # consumes an inline descriptor
            return d.done("TRAPA", _imm(v), _imm(d.u8()))
        return d.done("TRAPA", _imm(v))
    if b == 0xF3:
        return _phase4(d)
    if b == 0xF5:
        return d.done("REIT")
    if b == 0xF6:
        return d.done("UNLK", Operand("reg", reg="xFP", width="l"))
    if b == 0xF7:                                   # LDM: mask bit 7 is RW0
        mask = d.u8()
        regs = tuple(isa.RW[i] for i in range(8) if mask & (1 << (7 - i)))
        return d.done("LDM", Operand("reglist", regs=regs, width="w"))
    if b == 0xF8:                                   # STM: mask bit 0 is RW0
        mask = d.u8()
        regs = tuple(isa.RW[i] for i in range(8) if mask & (1 << i))
        return d.done("STM", Operand("reglist", regs=regs, width="w"))
    if b == 0xFA:
        return d.done("RTS")
    if b == 0xFB:
        return d.done("PRTS")
    if b == 0xFC:
        return d.done("EI")
    if b == 0xFD:
        return d.done("DI")
    if b == 0xFE:
        d.pwidth = "w"
        d.arg = Arg("imm", value=d.u8())
        return _phase2(d)
    if b == 0xFF:
        return d.done("NOP")
    return d.bad()


# ---------------------------------------------------------------------------
# phase 1  --  table 2, general addressing
# ---------------------------------------------------------------------------


def _phase1(d):
    d.ins.phase = 1
    b = d.u8()
    hi, h3, lo = b >> 4, (b >> 3) & 1, b & 7
    w = d.pwidth

    if hi <= 0x7:
        if h3 == 0:                                 # alu  arg -> reg
            return d.done(_ALU1[hi], d.a(w), _reg(lo, w), width=w)
        return d.done(_BITOPS[hi], _bit(d.a(w), lo), width=w)

    if hi == 0x8:
        if h3 == 0:
            d.arg2 = Arg("abs11", addr=(lo << 8) | d.u8())
            return _phase5(d)
        dst = Operand("abs", addr=(lo << 8) | d.u8(), width=w)
        return d.done("MOV", d.a(w), dst, width=w)

    if hi == 0x9:
        if h3 == 0:
            d.arg2 = Arg("rdisp", index=lo, disp=d.s16())
            return _phase5(d)
        dst = Arg("rdisp", index=lo, disp=d.s16()).operand(w)
        return d.done("MOV", d.a(w), dst, width=w)

    if hi == 0xA:
        if h3 == 0:
            d.arg2 = Arg("rdisp", index=lo, disp=d.s8())
            return _phase5(d)
        dst = Arg("rdisp", index=lo, disp=d.s8()).operand(w)
        return d.done("MOV", d.a(w), dst, width=w)

    if hi == 0xB:
        if h3 == 0:
            d.arg2 = Arg("rind", index=lo)
            return _phase5(d)
        return d.done("MOV", d.a(w), Arg("rind", index=lo).operand(w), width=w)

    if hi == 0xC:
        if h3 == 0:
            d.arg2 = Arg("rdir", index=lo)
            return _phase5(d)
        return d.done("MOV", d.a(w), _reg(lo, w), width=w)

    if hi == 0xD:                                   # BBC/BBS arg.bit, rel8
        return d.done("BBS" if h3 else "BBC", _bit(d.a(w), lo), d.rel8(), width=w)

    if b == 0xE0:
        d.arg2 = Arg("abs16", addr=d.u16())
        return _phase5(d)
    if b == 0xE1:
        d.arg2 = Arg("abs24", addr=d.u24())
        return _phase5(d)
    if b == 0xE2:
        return _phase6(d)
    if b == 0xE4:
        return d.done("NOT", d.a(w), width=w)
    if b == 0xE5:
        return d.done("SWAP", d.a(w), width=w)
    if b == 0xE6:
        return d.done("NEG", d.a(w), width=w)
    if b == 0xE7:
        return d.done("PUSHA", d.arg.address_operand(), width=w)
    if b == 0xE8:
        return d.done("MOV", d.a(w), Operand("abs", addr=d.u16(), width=w), width=w)
    if b == 0xE9:
        return d.done("MOV", d.a(w), Operand("abs", addr=d.u24(), width=w), width=w)
    if b == 0xEC:
        return d.done("INC", d.a(w), width=w)
    if b == 0xED:
        return d.done("DEC", d.a(w), width=w)
    if b == 0xEF:
        return d.done("PUSH", d.a(w), width=w)
    if 0xF0 <= b <= 0xF7:
        return d.done(_SHIFTS[b - 0xF0], d.a(w), width=w)
    return d.bad()


# ---------------------------------------------------------------------------
# phase 2  --  table 3, immediate source
# ---------------------------------------------------------------------------


def _phase2(d):
    d.ins.phase = 2
    b = d.u8()
    hi, h3, lo = b >> 4, (b >> 3) & 1, b & 7
    w = d.pwidth

    if hi <= 0x7:
        if h3 == 0:
            return d.done(_ALU1[hi], d.a(w), _reg(lo, w), width=w)
        dst = Operand("abs", addr=(lo << 8) | d.u8(), width=w)
        return d.done(_ALU1[hi], d.a(w), dst, width=w)

    if hi == 0x8:
        if h3 == 0:
            d.arg2 = Arg("abs11", addr=(lo << 8) | d.u8())
            return _phase5(d)
        dst = Operand("abs", addr=(lo << 8) | d.u8(), width=w)
        return d.done("MOV", d.a(w), dst, width=w)

    if hi == 0x9:
        if h3 == 0:
            d.arg2 = Arg("rdisp", index=lo, disp=d.s16())
            return _phase5(d)
        return d.done("MOV", d.a(w), Arg("rdisp", index=lo, disp=d.s16()).operand(w), width=w)

    if hi == 0xA:
        if h3 == 0:
            d.arg2 = Arg("rdisp", index=lo, disp=d.s8())
            return _phase5(d)
        return d.done("MOV", d.a(w), Arg("rdisp", index=lo, disp=d.s8()).operand(w), width=w)

    if hi == 0xB:
        if h3 == 0:
            d.arg2 = Arg("rind", index=lo)
            return _phase5(d)
        return d.done("MOV", d.a(w), Arg("rind", index=lo).operand(w), width=w)

    if hi == 0xC:
        if h3 == 0:
            d.arg2 = Arg("rdir", index=lo)
            return _phase5(d)
        return d.done("MOV", d.a(w), _reg(lo, w), width=w)

    if hi == 0xD:                                   # MOV #imm, @(simm4, FP)
        nib = b & 0xF
        disp = nib - 16 if nib & 8 else nib
        dst = Operand("disp", base_reg="xFP", disp=disp, width=w)
        return d.done("MOV", d.a(w), dst, width=w)

    if b == 0xE0:
        d.arg2 = Arg("abs16", addr=d.u16())
        return _phase5(d)
    if b == 0xE1:
        d.arg2 = Arg("abs24", addr=d.u24())
        return _phase5(d)
    if b == 0xE2:
        return _phase7(d, mode=0)
    if b == 0xE4:
        return d.done("ANDC", d.a(w), _ctrl(4), width=w)
    if b == 0xE5:
        return d.done("ANDC", d.a(w), _ctrl(5), width=w)
    if b == 0xE7:
        high = d.u16()
        return _phase7(d, mode=1, high=high)
    if b == 0xE8:
        return d.done("MOV", d.a(w), Operand("abs", addr=d.u16(), width=w), width=w)
    if b == 0xE9:
        return d.done("MOV", d.a(w), Operand("abs", addr=d.u24(), width=w), width=w)
    if b == 0xEC:
        return d.done("ORC", d.a(w), _ctrl(4), width=w)
    if b == 0xED:
        return d.done("ORC", d.a(w), _ctrl(5), width=w)
    if b == 0xEF:
        return d.done("PUSH", d.a(w), width=w)
    if hi == 0xF and h3 == 0:
        return d.done("MOVC", d.a(w), _ctrl(lo), width=w)
    return d.bad()


# ---------------------------------------------------------------------------
# phase 3  --  table 4, register direct
# ---------------------------------------------------------------------------


def _phase3(d):
    d.ins.phase = 3
    b = d.u8()
    hi, h3, lo = b >> 4, (b >> 3) & 1, b & 7

    if hi <= 0x7:                                   # shift src -> dst
        w = "w" if h3 else "b"
        return d.done(_SHIFTS[hi], d.a(w), _reg(lo, w), width=w)

    if hi == 0xA:
        return d.done("DIVU" if h3 else "MULU", d.a("w"), _reg(lo, "l"), width="w")
    if hi == 0xB:
        return d.done("DIV" if h3 else "MUL", d.a("w"), _reg(lo, "l"), width="w")
    if hi == 0xC:
        return d.done("DIVU" if h3 else "MULU", d.a("b"), _reg(lo, "w"), width="b")
    if hi == 0xD:
        return d.done("DIV" if h3 else "MUL", d.a("b"), _reg(lo, "w"), width="b")

    if 0xE0 <= b <= 0xE7:
        return d.done(_SHIFTS[b - 0xE0], d.a("l"), width="l")
    if b == 0xE8:
        return d.done("MOV", d.a("w"), Operand("ctrl", reg="USP", width="w"), width="w")
    if b == 0xE9:
        return d.done("MOV", Operand("ctrl", reg="USP", width="w"), d.a("w"), width="w")
    if b == 0xEC:
        return d.done("XORC", _imm(lo), _ctrl(d.arg.index), width="b")
    if b == 0xED:
        return d.done("LDCTX")
    if b == 0xEE:
        return d.done("NEG", d.a("l"), width="l")
    if hi == 0xF:
        if h3 == 0:
            return d.done("MOVC", d.a("w"), _ctrl(lo), width="w")
        return d.done("MOVC", _ctrl(lo), d.a("w"), width="w")
    return d.bad()


# ---------------------------------------------------------------------------
# phase 4  --  table 5, reached through 0xF3
# ---------------------------------------------------------------------------


def _phase4(d):
    d.ins.phase = 4
    b = d.u8()
    hi, h3, lo = b >> 4, (b >> 3) & 1, b & 7

    if hi == 0x0:                                   # long conditional branch
        return d.done("B" + isa.CC[b & 0xF], d.rel16())
    if hi == 0x3:
        w = "w" if h3 else "b"
        return d.done("DBNZ", _reg(lo, w), d.rel8(), width=w)
    if hi == 0x9:                                   # pre-decrement prefix
        d.pwidth = "w" if h3 else "b"
        d.arg = Arg("predec", index=lo)
        return _phase1(d)
    if hi == 0xA:                                   # post-increment prefix
        d.pwidth = "w" if h3 else "b"
        d.arg = Arg("postinc", index=lo)
        return _phase1(d)
    if hi == 0xC:
        tgt = Operand("ind", base_reg=isa.RP[lo], width="l")
        return d.done("JSR" if h3 else "JMP", tgt)
    if hi == 0xD:
        return d.done("PUSHC" if h3 else "POPC", _ctrl(lo))
    if b == 0xE2:
        return d.done("SLEEP")
    if b == 0xE3:
        return d.done("STOP")
    return d.bad()


# ---------------------------------------------------------------------------
# phase 5  --  table 6, two prefixed operands
# ---------------------------------------------------------------------------


def _phase5(d):
    d.ins.phase = 5
    b = d.u8()
    hi, h3, lo = b >> 4, (b >> 3) & 1, b & 7
    w = d.pwidth

    if hi <= 0x6 and h3 == 0:                       # reg = a op b
        return d.done(_ALU1[hi], d.a(w), d.b(w), _reg(lo, w), width=w)
    if b == 0xE7:
        return d.done("MOV", d.a(w), d.b(w), width=w)
    if b == 0xEE:
        return d.done("DADDX", d.a(w), d.b(w), width=w)
    if b == 0xEF:
        return d.done("DSUBX", d.a(w), d.b(w), width=w)
    if 0xF8 <= b <= 0xFF:                           # b = b op a
        return d.done(_ALU1[b - 0xF8], d.a(w), d.b(w), width=w)
    return d.bad()


# ---------------------------------------------------------------------------
# phase 6  --  table 7, long operations and bit ops
# ---------------------------------------------------------------------------


def _phase6(d):
    d.ins.phase = 6
    b = d.u8()
    hi, h3, lo = b >> 4, (b >> 3) & 1, b & 7
    w = d.pwidth

    if hi <= 0x7:
        if h3 == 0:
            return d.done(_ALU1[hi], d.a("l"), _reg(lo, "l"), width="l")
        return d.done(_BITOPS[hi], _bit(d.a(w), lo), width=w)

    if hi == 0x8:
        if h3 == 0:
            return d.done("MOV", d.a("l"), _reg(lo, "l"), width="l")
        return d.done("MOV", _reg(lo, "l"), d.a("l"), width="l")

    if hi == 0x9:
        if h3 == 0:
            d.arg2 = Arg("predec", index=lo)
            return _phase5(d)
        return d.done("XCH", d.a(w), _reg(lo, w), width=w)

    if hi == 0xA:
        d.arg2 = Arg("postinc", index=lo)
        return _phase5(d)

    if hi == 0xC and h3 == 0:
        return d.done("MOVA", d.a(w), _reg(lo, "w"), width=w)
    if hi == 0xD:
        return d.done("MOVXU" if h3 else "MOVX", d.a(w), _reg(lo, "l"), width=w)
    if hi == 0xE:
        return d.done("MOVXU" if h3 else "MOVX", d.a(w), _reg(lo, "w"), width=w)
    return d.bad()


# ---------------------------------------------------------------------------
# phase 7  --  table 8, long immediates
# ---------------------------------------------------------------------------


def _phase7(d, mode, high=0):
    d.ins.phase = 7
    value = d.arg.value if d.arg is not None else 0
    if mode == 1:
        value |= (high & 0xFFFF) << 16
    d.arg = Arg("imm", value=value & 0xFFFFFFFF)

    b = d.u8()
    hi, h3, lo = b >> 4, (b >> 3) & 1, b & 7

    if hi <= 0x7 and h3 == 0:
        return d.done(_ALU1[hi], d.a("l"), _reg(lo, "l"), width="l")
    if hi == 0x8 and h3 == 0:
        return d.done("MOV", d.a("l"), _reg(lo, "l"), width="l")
    if hi == 0x9 and h3 == 0:
        d.arg2 = Arg("predec", index=lo)
        d.pwidth = "l"
        return _phase5(d)
    if hi == 0xA:
        d.arg2 = Arg("postinc", index=lo)
        d.pwidth = "l"
        return _phase5(d)
    return d.bad()


# ---------------------------------------------------------------------------
# public interface
# ---------------------------------------------------------------------------


def decode_one(image, ea, base=0):
    """Decode one instruction at *ea*; return an :class:`Insn`, or ``None`` if
    the address is out of range.  An undefined encoding comes back with
    ``mnem`` ``None`` and ``size`` 0."""
    off = ea - base
    if off < 0 or off >= len(image):
        return None
    d = _Dec(image, base, ea)
    try:
        return _phase0(d)
    except IndexError:
        return None


def target_of(ins):
    """Static code target of a branch/call, or None."""
    if ins is None or not ins.ops:
        return None
    for op in ins.ops:
        if op.mode == "code":
            return op.addr
    return None


def succ(ins):
    """Successor edges of *ins* as (kind, address) pairs."""
    m = ins.mnem
    nxt = ins.ea + ins.size
    tgt = target_of(ins)
    if m in isa.CALL:
        out = [("call", tgt)] if tgt is not None else []
        out.append(("fall", nxt))
        return out
    if m == "BRA":
        return [("jump", tgt)] if tgt is not None else []
    if m == "BRN":
        return [("fall", nxt)]
    if m in isa.JUMP:
        return [("jump", tgt)] if tgt is not None else []
    if m in isa.RET or m in isa.HALT:
        return []
    if m in isa.BRANCH or m in isa.BIT_BRANCH or m in isa.LOOP_BRANCH:
        out = [("jump", tgt)] if tgt is not None else []
        out.append(("fall", nxt))
        return out
    return [("fall", nxt)]


def decode(image, entries, base=0, valid=None):
    """Recursive-descent decode from *entries*.  Returns ``(insns, calls)``.

    *valid* is an optional predicate on an address; it keeps the walk inside
    the executable banks of a ROM that also contains data."""
    insns = {}
    calls = set()
    seen = set()

    def ok(a):
        if a is None or not (base <= a < base + len(image)):
            return False
        return valid(a) if valid is not None else True

    work = [e for e in entries if ok(e)]
    while work:
        ea = work.pop()
        if ea in seen or not ok(ea):
            continue
        seen.add(ea)
        ins = decode_one(image, ea, base)
        if ins is None or ins.size == 0 or ins.mnem is None:
            continue
        insns[ea] = ins
        for how, tgt in succ(ins):
            if not ok(tgt):
                continue
            if how == "call":
                calls.add(tgt)
            work.append(tgt)
    return insns, calls
