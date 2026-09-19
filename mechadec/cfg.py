"""
Control-flow graph for SPC970.

Carves the decoded stream into functions and basic blocks and lifts each
block.  SPC970 specifics handled here: ``JSR``/``PJSR`` fall through,
``RTS``/``PRTS``/``REIT`` and an unconditional ``BRA``/``JMP``/``PJMP`` end a
block, ``BRN`` is a never-taken branch that simply falls through, and ``DBNZ``
is a decrement plus a conditional branch.

Flag provenance is resolved after lifting so a conditional branch renders as a
comparison: the pass walks each block carrying the last :class:`~mechadec.ir.FlagDef`
forward, and a block with a single predecessor inherits that predecessor's.
"""

from . import ir, isa
from .decoder import target_of, succ
from .lifter import lift_insn


class Block:
    __slots__ = ("start", "insns", "stmts", "succ", "term")

    def __init__(self, start):
        self.start = start
        self.insns = []
        self.stmts = []
        self.succ = []
        self.term = None


class Func:
    __slots__ = ("entry", "blocks", "calls", "name")

    def __init__(self, entry):
        self.entry = entry
        self.blocks = {}
        self.calls = set()
        self.name = None

    def ordered(self):
        return [self.blocks[k] for k in sorted(self.blocks)]


def _flow(insns, ins):
    """Intra-function successors of *ins* as (kind, address) pairs.  A call
    edge is not flow within the caller, so it is dropped; the taken edge of a
    conditional is relabelled ``cond`` for the structurer."""
    cond = _is_conditional(ins)
    return [("cond" if cond and how == "jump" else how, tgt)
            for how, tgt in succ(ins) if how != "call"]


def _is_conditional(ins):
    m = ins.mnem
    return (m in isa.BRANCH and m not in ("BRA", "BRN")) \
        or m in isa.BIT_BRANCH or m in isa.LOOP_BRANCH


def _collect_body(insns, entry, entry_set):
    body = set()
    work = [entry]
    while work:
        ea = work.pop()
        if ea in body or ea not in insns:
            continue
        body.add(ea)
        for how, tgt in _flow(insns, insns[ea]):
            if tgt in insns and (tgt == entry or tgt not in entry_set):
                work.append(tgt)
    return body


def _leaders(insns, body):
    leaders = set()
    for ea in body:
        ins = insns[ea]
        for how, tgt in _flow(insns, ins):
            if how in ("cond", "jump") and tgt in body:
                leaders.add(tgt)
        if _is_conditional(ins) or ins.mnem in isa.STOP or ins.mnem in isa.CALL:
            nxt = ea + ins.size
            if nxt in body:
                leaders.add(nxt)
    return leaders


def build_func(insns, entry, entry_set):
    body = _collect_body(insns, entry, entry_set)
    if not body:
        return None
    leaders = _leaders(insns, body)
    leaders.add(entry)

    f = Func(entry)
    cur = None
    for ea in sorted(body):
        ins = insns[ea]
        if ea in leaders or cur is None:
            cur = Block(ea)
            f.blocks[ea] = cur
        cur.insns.append(ins)

        edges = _flow(insns, ins)
        nxt = ea + ins.size
        term = None
        m = ins.mnem
        if m in isa.RET or m in isa.HALT:
            term = ("ret", [])
        elif m in ("BRA",) or m in isa.JUMP:
            tgt = target_of(ins)
            term = ("goto", edges) if tgt is not None and tgt in body else ("ret", [])
        elif _is_conditional(ins):
            term = ("branch", edges)
        elif nxt in leaders or nxt not in body:
            term = ("fall", [("fall", nxt)] if nxt in body else [])
        if term is not None:
            cur.term, cur.succ = term
            cur = None

    for b in f.blocks.values():
        for ins in b.insns:
            if ins.mnem in isa.CALL:
                tgt = target_of(ins)
                if tgt is not None:
                    f.calls.add(tgt)
            b.stmts.extend(lift_insn(ins))

    _resolve_flags(f)
    return f


def _resolve_flags(f):
    flag_out = {}
    preds = {}
    for b in f.blocks.values():
        for _, tgt in b.succ:
            preds.setdefault(tgt, []).append(b.start)

    def scan(block, incoming):
        cur = incoming
        for s in block.stmts:
            if isinstance(s, ir.Compare):
                cur = s.flag
            elif isinstance(s, ir.Assign) and s.flag is not None:
                cur = s.flag
            elif isinstance(s, ir.Branch) and s.cond is not None:
                s.flag = cur
            elif isinstance(s, (ir.Call, ir.Intrinsic)):
                cur = None                       # a call clobbers the PSW
        return cur

    for _ in range(4):
        changed = False
        for b in f.ordered():
            pl = preds.get(b.start, [])
            incoming = flag_out.get(pl[0]) if len(pl) == 1 else None
            out = scan(b, incoming)
            if flag_out.get(b.start) is not out:
                flag_out[b.start] = out
                changed = True
        if not changed:
            break


def build_functions(insns, calls, extra_entries=()):
    entry_set = {e for e in (set(calls) | set(extra_entries)) if e in insns}
    funcs = {}
    for entry in sorted(entry_set):
        fn = build_func(insns, entry, entry_set)
        if fn is not None:
            funcs[entry] = fn
    return funcs
