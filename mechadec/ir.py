"""
Intermediate representation for the SPC970 decompiler.

The statement classes match those in ``rl78dec`` and the Kirk/Spock
``startrekdec`` so the control-flow structurer and the highlighter carry over
unchanged; the expression layer is a register machine.

Flags
-----
The SPC970 condition codes read four PSW bits: ``Z`` (zero), ``X``
(carry/extension), ``V`` (overflow) and ``M`` (negative).  Unsigned relations
come from X and Z, signed ones from M^V.  A :class:`FlagDef` records what last
set them so a branch can be rendered as a real comparison instead of a flag
test.

``CMP src,dst`` on this machine evaluates ``dst - src``, so a ``cmp``
:class:`FlagDef` stores ``a`` = destination and ``b`` = source, and every
relation reads left-to-right as ``a <rel> b``.
"""


class Expr:
    pass


class Const(Expr):
    __slots__ = ("value", "width")

    def __init__(self, value, width="b"):
        self.width = width
        if width == "a":                     # an address: keep all 24 bits
            self.value = value & 0xFFFFFF
        elif width == "l":
            self.value = value & 0xFFFFFFFF
        elif width == "w":
            self.value = value & 0xFFFF
        else:
            self.value = value & 0xFF


class Reg(Expr):
    __slots__ = ("name", "width")

    def __init__(self, name, width=None):
        self.name = name
        self.width = width or "w"

    def __eq__(self, o):
        return isinstance(o, Reg) and o.name == self.name

    def __hash__(self):
        return hash(("reg", self.name))


class Mem(Expr):
    """A memory access at address *addr* (an ``Expr`` or an ``int``), of width
    b/w/l.  ``space`` is ``ram`` or ``io``."""

    __slots__ = ("addr", "width", "space", "name")

    def __init__(self, addr, width="b", space="ram", name=None):
        self.addr = addr
        self.width = width
        self.space = space
        self.name = name


class Bit(Expr):
    """A single bit of a byte/word location (base is a Reg or Mem)."""

    __slots__ = ("base", "bit")

    def __init__(self, base, bit):
        self.base = base
        self.bit = bit


class Bin(Expr):
    __slots__ = ("op", "l", "r")

    def __init__(self, op, l, r):
        self.op = op
        self.l = l
        self.r = r


class Un(Expr):
    __slots__ = ("op", "e")

    def __init__(self, op, e):
        self.op = op
        self.e = e


class IntrExpr(Expr):
    __slots__ = ("name", "args")

    def __init__(self, name, args):
        self.name = name
        self.args = args


# ---------------------------------------------------------------------------
# flags
# ---------------------------------------------------------------------------

class FlagDef:
    """kind == 'cmp'    : Z=(a==b), X=(a<b unsigned), M^V signed ordering
       kind == 'sub'    : same relations, and the result was written to a
       kind == 'result' : Z=(res==0), M=(res<0); X and V not recoverable"""

    __slots__ = ("kind", "a", "b")

    def __init__(self, kind, a=None, b=None):
        self.kind = kind
        self.a = a
        self.b = b


# ---------------------------------------------------------------------------
# statements
# ---------------------------------------------------------------------------

class Assign:
    __slots__ = ("ea", "dst", "src", "flag")

    def __init__(self, ea, dst, src, flag=None):
        self.ea = ea
        self.dst = dst
        self.src = src
        self.flag = flag


class Compare:
    __slots__ = ("ea", "flag")

    def __init__(self, ea, flag):
        self.ea = ea
        self.flag = flag


class Call:
    __slots__ = ("ea", "target", "expr", "far")

    def __init__(self, ea, target=None, expr=None, far=False):
        self.ea = ea
        self.target = target        # address for a direct call
        self.expr = expr            # Expr for an indirect call
        self.far = far


class Intrinsic:
    __slots__ = ("ea", "name", "args", "note")

    def __init__(self, ea, name, args, note=""):
        self.ea = ea
        self.name = name
        self.args = args
        self.note = note


class Ret:
    __slots__ = ("ea", "kind")

    def __init__(self, ea, kind="RTS"):
        self.ea = ea
        self.kind = kind


class Goto:
    __slots__ = ("ea", "target")

    def __init__(self, ea, target):
        self.ea = ea
        self.target = target


class Branch:
    __slots__ = ("ea", "cond", "target", "fallthrough", "flag", "bittest")

    def __init__(self, ea, cond, target, fallthrough, bittest=None):
        self.ea = ea
        self.cond = cond            # a token from isa.CC_COND, or None
        self.target = target
        self.fallthrough = fallthrough
        self.flag = None
        self.bittest = bittest      # (Expr, sense) for BBC/BBS


class Nop:
    __slots__ = ("ea",)

    def __init__(self, ea):
        self.ea = ea
