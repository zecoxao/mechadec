"""
Pseudo-C back-end for the SPC970 decompiler.

Registers print as themselves (``RB0``, ``RW4``, ``RL2``, ``FP``, ``SP`` ...);
memory is ``mem8`` / ``mem16`` / ``mem32`` indexed by an address expression,
with documented MechaCon RAM cells and I/O ports shown by name.  Relational
conditions come from the flag provenance in :mod:`mechadec.structure`; the
``ZF``/``XF``/``VF``/``MF`` pseudo-variables appear only where no comparison
could be recovered.
"""

from . import ir
from . import structure as S

_MEMFN = {"b": "mem8", "w": "mem16", "l": "mem32"}


class _Emit:
    def __init__(self, namer, block_starts=frozenset()):
        self.namer = namer
        self.block_starts = block_starts
        self.used_labels = set()
        self._pending = []

    # -- expressions --------------------------------------------------------

    def expr(self, e, top=True):
        if isinstance(e, ir.Const):
            if e.width == "a" and e.value >= 0x10000:
                return "0x%06X" % e.value
            return str(e.value) if e.value < 10 else "0x%X" % e.value
        if isinstance(e, ir.Reg):
            return e.name
        if isinstance(e, ir.Mem):
            return self._mem(e)
        if isinstance(e, ir.Bit):
            return "((%s >> %d) & 1)" % (self.expr(e.base, False), e.bit)
        if isinstance(e, ir.Bin):
            s = "%s %s %s" % (self.expr(e.l, False), e.op, self.expr(e.r, False))
            return s if top else "(%s)" % s
        if isinstance(e, ir.Un):
            return "%s%s" % (e.op, self.expr(e.e, False))
        if isinstance(e, ir.IntrExpr):
            if not e.args:
                return e.name
            return "%s(%s)" % (e.name, ", ".join(self.expr(a) for a in e.args))
        return "?"

    def _mem(self, e):
        fn = _MEMFN.get(e.width, "mem8")
        if isinstance(e.addr, ir.Expr):
            if isinstance(e.addr, ir.Const):
                return self.namer.cell(e.addr.value, e.space)
            return "%s[%s]" % (fn, self.expr(e.addr))
        return self.namer.cell(e.addr, e.space)

    # -- statements ---------------------------------------------------------

    def stmt(self, s):
        if isinstance(s, ir.Assign):
            return "%s = %s;" % (self.expr(s.dst), self.expr(s.src))
        if isinstance(s, ir.Call):
            if s.target is not None:
                return "%s();" % self.namer.code(s.target)
            return "(*%s)();" % self.expr(s.expr)
        if isinstance(s, ir.Intrinsic):
            call = "%s(%s);" % (s.name, ", ".join(self.expr(a) for a in s.args))
            return call + ("   /* %s */" % s.note if s.note else "")
        return "/* %s */" % type(s).__name__

    # -- tree ---------------------------------------------------------------

    def emit(self, nodes, ind):
        pad = "    " * ind
        for n in nodes:
            if isinstance(n, S.SLabel):
                self._pending.append((ind, None, n.ea))
            elif isinstance(n, S.SStmt):
                self._pending.append((ind, pad + self.stmt(n.stmt), None))
            elif isinstance(n, S.SRet):
                self._pending.append((ind, pad + "return;", None))
            elif isinstance(n, S.SGoto):
                if n.ea in self.block_starts:
                    self.used_labels.add(n.ea)
                    self._pending.append((ind, pad + "goto %s;" % self.namer.label(n.ea), None))
                else:
                    self._pending.append((ind, pad + "JUMPOUT(%s);" % self._ext(n.ea), None))
            elif isinstance(n, S.SIfGoto):
                if n.ea in self.block_starts:
                    self.used_labels.add(n.ea)
                    tail = "goto %s;" % self.namer.label(n.ea)
                else:
                    tail = "JUMPOUT(%s);" % self._ext(n.ea)
                self._pending.append((ind, pad + "if (%s) %s" % (self.expr(n.cond), tail), None))
            elif isinstance(n, S.SBreak):
                self._pending.append((ind, pad + "break;", None))
            elif isinstance(n, S.SBreakIf):
                self._pending.append((ind, pad + "if (%s) break;" % self.expr(n.cond), None))
            elif isinstance(n, S.SContinue):
                if n.cond is None:
                    self._pending.append((ind, pad + "continue;", None))
                else:
                    self._pending.append((ind, pad + "if (%s) continue;" % self.expr(n.cond), None))
            elif isinstance(n, S.SIf):
                self._pending.append((ind, pad + "if (%s) {" % self.expr(n.cond), None))
                self.emit(n.then, ind + 1)
                if n.els:
                    self._pending.append((ind, pad + "} else {", None))
                    self.emit(n.els, ind + 1)
                self._pending.append((ind, pad + "}", None))
            elif isinstance(n, S.SWhile):
                self._emit_while(n, ind)

    def _emit_while(self, n, ind):
        pad = "    " * ind
        body = list(n.body)
        tail = None
        if body and isinstance(body[-1], S.SContinue) and body[-1].cond is not None:
            tail = body[-1].cond
            body = body[:-1]
        if tail is not None:
            self._pending.append((ind, pad + "do {", None))
            self.emit(body, ind + 1)
            self._pending.append((ind, pad + "} while (%s);" % self.expr(tail), None))
        else:
            self._pending.append((ind, pad + "while (1) {", None))
            self.emit(body, ind + 1)
            self._pending.append((ind, pad + "}", None))

    def _ext(self, ea):
        n = self.namer.code_names.get(ea) if hasattr(self.namer, "code_names") else None
        return n or "0x%06X" % ea

    def flush(self):
        out = []
        for ind, text, label_ea in self._pending:
            if label_ea is not None:
                if label_ea in self.used_labels:
                    out.append("%s:" % self.namer.label(label_ea))
                continue
            out.append(text)
        return out


def generate(func, tree, namer, banner=None):
    em = _Emit(namer, block_starts=frozenset(func.blocks))
    em.emit(tree, 1)
    body = em.flush()
    out = []
    if banner:
        out.extend(banner)
    out.append("void %s(void)" % namer.code(func.entry))
    out.append("{")
    out.extend(body)
    out.append("}")
    return out
