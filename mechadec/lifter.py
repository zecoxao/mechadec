"""
Lift decoded SPC970 :class:`~mechadec.decoder.Insn` objects into IR.

Semantics follow the p-code in DiscoStarslayer's ``ghidra-spc970`` SLEIGH
specification.  Two conventions from that encoding shape everything here:

* operands read *source first, destination last*, so a two-operand ALU
  instruction is ``ops[1] = ops[1] op ops[0]`` and a three-operand table-6
  instruction is ``ops[2] = ops[0] op ops[1]``;
* ``CMP src,dst`` evaluates ``dst - src``, so the recovered comparison is
  ``ops[1] <rel> ops[0]``.

Auto-modifying addressing (``@(-Rn)``, ``@(Rn+)``, ``@(SP+)``) is lowered to an
explicit pointer update emitted before or after the access, rather than hidden
inside the expression, so the side effect stays visible in the output.

Instructions that do not map cleanly onto C -- the decimal-adjust pair, the
context/trap group, LDM/STM, MagicGate-era bit plumbing -- are emitted honestly
as pseudo-calls rather than guessed at.
"""

from . import ir, isa

_BINOP = {"XOR": "^", "OR": "|", "AND": "&", "ADD": "+", "SUB": "-"}
_SHIFT_OP = {"SHAL": "<<", "SHLL": "<<", "SHLR": ">>"}
_SHIFT_INTR = {"SHAR": "sar", "ROTL": "rotl", "ROTR": "rotr",
               "SHXL": "shxl", "SHXR": "shxr"}
_WIDTH_STEP = {"b": 2, "w": 2, "l": 4}     # the stack always moves in words


def _reg(name, width="w"):
    return ir.Reg(name, width)


def op_expr(op, pre=None, post=None):
    """Convert a decoder Operand into an IR expression.

    Auto-modifying modes append their pointer update to *pre* (before the
    access) or *post* (after it); both are lists supplied by the caller."""
    m = op.mode
    if m == "reg" or m == "ctrl":
        return _reg(op.reg, op.width)
    if m == "imm":
        return ir.Const(op.value, op.width)
    if m == "abs":
        return ir.Mem(op.addr, op.width, op.space)
    if m == "disp":
        base = _reg(op.base_reg, "l")
        if op.disp == 0:
            addr = base
        elif op.disp < 0:                 # keep frame offsets readable
            addr = ir.Bin("-", base, ir.Const(-op.disp, "a"))
        else:
            addr = ir.Bin("+", base, ir.Const(op.disp, "a"))
        return ir.Mem(addr, op.width)
    if m == "ind":
        return ir.Mem(_reg(op.base_reg, "l"), op.width)
    if m == "predec":
        base = _reg(op.base_reg, "l")
        if pre is not None:
            pre.append((base, -_WIDTH_STEP[op.width]))
        return ir.Mem(base, op.width)
    if m == "postinc":
        base = _reg(op.base_reg, "l")
        if post is not None:
            post.append((base, _WIDTH_STEP[op.width]))
        return ir.Mem(base, op.width)
    if m == "pop":
        base = _reg("xSP", "l")
        if post is not None:
            post.append((base, _WIDTH_STEP[op.width]))
        return ir.Mem(base, op.width)
    if m == "bit":
        return ir.Bit(op_expr(op.base, pre, post), op.bit)
    if m == "addrof":
        inner = op_expr(op.base, pre, post)
        if isinstance(inner, ir.Mem):
            return inner.addr if isinstance(inner.addr, ir.Expr) \
                else ir.Const(inner.addr, "a")
        return inner
    if m == "code":
        return ir.Const(op.addr, "a")
    if m == "reglist":
        return ir.IntrExpr("regs", [_reg(r) for r in op.regs])
    return ir.Const(0)


def _adjust(ea, updates):
    out = []
    for base, delta in updates:
        op = "+" if delta > 0 else "-"
        out.append(ir.Assign(ea, base, ir.Bin(op, base, ir.Const(abs(delta), "a"))))
    return out


def _bit_mask(bit, width):
    return ir.Const(1 << bit, width)


def lift_insn(ins):
    """Lift one instruction to a list of IR statements."""
    ea, m, ops = ins.ea, ins.mnem, ins.ops
    w = ins.width or "b"
    pre, post = [], []

    def e(i):
        return op_expr(ops[i], pre, post)

    def wrap(body):
        return _adjust(ea, pre) + body + _adjust(ea, post)

    # --- data movement -----------------------------------------------------
    if m == "MOV":
        if len(ops) < 2:
            return wrap([ir.Intrinsic(ea, "MOV", [e(0)], note="incomplete")])
        src, dst = e(0), e(1)
        return wrap([ir.Assign(ea, dst, src, flag=ir.FlagDef("result", a=src))])

    if m == "MOVC":
        src, dst = e(0), e(1)
        return wrap([ir.Assign(ea, dst, src)])

    if m in ("MOVA", "MOVXU"):                      # zero-extend into a wider reg
        src, dst = e(0), e(1)
        return wrap([ir.Assign(ea, dst, ir.IntrExpr("zext", [src]),
                               flag=ir.FlagDef("result", a=src))])

    if m == "MOVX":                                 # sign-extend
        src, dst = e(0), e(1)
        return wrap([ir.Assign(ea, dst, ir.IntrExpr("sext", [src]),
                               flag=ir.FlagDef("result", a=src))])

    if m == "XCH":
        return wrap([ir.Intrinsic(ea, "xch", [e(0), e(1)])])

    if m == "SWAP":
        a = e(0)
        return wrap([ir.Assign(ea, a, ir.IntrExpr("swap_nibbles", [a]))])

    # --- arithmetic and logic ---------------------------------------------
    if m in _BINOP:
        if len(ops) == 3:                           # table 6: dst = a op b
            a, b, dst = e(0), e(1), e(2)
            res = ir.Bin(_BINOP[m], a, b)
            flag = ir.FlagDef("sub", a=a, b=b) if m == "SUB" \
                else ir.FlagDef("result", a=dst)
            return wrap([ir.Assign(ea, dst, res, flag=flag)])
        src, dst = e(0), e(1)
        flag = ir.FlagDef("sub", a=dst, b=src) if m == "SUB" \
            else ir.FlagDef("result", a=dst)
        return wrap([ir.Assign(ea, dst, ir.Bin(_BINOP[m], dst, src), flag=flag)])

    if m in ("ADDX", "SUBX"):                       # with the X (carry) flag
        op = "+" if m == "ADDX" else "-"
        x = ir.Reg("X", "b")
        if len(ops) == 3:
            a, b, dst = e(0), e(1), e(2)
            res = ir.Bin(op, ir.Bin(op, a, b), x)
        else:
            a, dst = e(0), e(1)
            res = ir.Bin(op, ir.Bin(op, dst, a), x)
        return wrap([ir.Assign(ea, dst, res, flag=ir.FlagDef("result", a=dst))])

    if m == "CMP":
        if len(ops) >= 2:
            src, dst = e(0), e(1)
            return wrap([ir.Compare(ea, ir.FlagDef("cmp", a=dst, b=src))])
        return wrap([ir.Compare(ea, ir.FlagDef("result", a=e(0)))])

    if m in ("INC", "DEC"):
        a = e(0)
        op = "+" if m == "INC" else "-"
        return wrap([ir.Assign(ea, a, ir.Bin(op, a, ir.Const(1, w)),
                               flag=ir.FlagDef("result", a=a))])

    if m == "NEG":
        a = e(0)
        return wrap([ir.Assign(ea, a, ir.Un("-", a),
                               flag=ir.FlagDef("result", a=a))])

    if m == "NOT":
        a = e(0)
        return wrap([ir.Assign(ea, a, ir.Un("~", a),
                               flag=ir.FlagDef("result", a=a))])

    if m in ("MUL", "MULU"):
        src, dst = e(0), e(1)
        name = "mul" if m == "MUL" else "mulu"
        return wrap([ir.Assign(ea, dst, ir.IntrExpr(name, [dst, src]),
                               flag=ir.FlagDef("result", a=dst))])

    if m in ("DIV", "DIVU"):
        src, dst = e(0), e(1)
        name = "div" if m == "DIV" else "divu"
        # The quotient lands in the low half of the destination and the
        # remainder in the high half, so this stays a single opaque result.
        return wrap([ir.Assign(ea, dst, ir.IntrExpr(name, [dst, src]),
                               flag=ir.FlagDef("result", a=dst))])

    if m in ("DADDX", "DSUBX"):                     # packed-BCD add/subtract
        src, dst = e(0), e(1)
        name = "bcd_add" if m == "DADDX" else "bcd_sub"
        return wrap([ir.Assign(ea, dst, ir.IntrExpr(name, [dst, src, ir.Reg("X", "b")]),
                               flag=ir.FlagDef("result", a=dst))])

    # --- shifts and rotates ------------------------------------------------
    if m in _SHIFT_OP or m in _SHIFT_INTR:
        # The two-operand table-4 form is a shift by a *variable count*: the
        # prefix register holds the value and receives the result, and the
        # op-byte register supplies the count.  (The SLEIGH reference models
        # it as a shift by one into the op-byte register, which leaves the
        # preceding count load dead; across this ROM the count register is
        # loaded with a small constant immediately before 131 of the 150
        # sites, and it is the prefix register that is read afterwards.)
        # Every other form shifts its single operand by one.
        dst = e(0)
        count = e(1) if (len(ops) > 1 and ins.phase == 3) else ir.Const(1, "b")
        if m in _SHIFT_OP:
            res = ir.Bin(_SHIFT_OP[m], dst, count)
        else:
            res = ir.IntrExpr(_SHIFT_INTR[m], [dst, count])
        return wrap([ir.Assign(ea, dst, res, flag=ir.FlagDef("result", a=dst))])

    # --- bit operations ----------------------------------------------------
    if m in ("BSET", "BCLR", "BNOT"):
        bit = e(0)
        base, mask = bit.base, _bit_mask(bit.bit, w)
        if m == "BSET":
            res = ir.Bin("|", base, mask)
        elif m == "BNOT":
            res = ir.Bin("^", base, mask)
        else:
            res = ir.Bin("&", base, ir.Un("~", mask))
        return wrap([ir.Assign(ea, base, res)])

    if m == "BLD":
        bit = e(0)
        return wrap([ir.Assign(ea, ir.Reg("X", "b"), bit)])

    if m == "BST":
        bit = e(0)
        return wrap([ir.Intrinsic(ea, "deposit_bit",
                                  [bit.base, ir.Const(bit.bit), ir.Reg("X", "b")])])

    if m in ("BXOR", "BOR", "BAND"):
        bit = e(0)
        op = {"BXOR": "^", "BOR": "|", "BAND": "&"}[m]
        x = ir.Reg("X", "b")
        return wrap([ir.Assign(ea, x, ir.Bin(op, x, bit))])

    # --- control flow ------------------------------------------------------
    if m in isa.BRANCH:
        cond = isa.CC_COND[isa.CC.index(m[1:])]
        target = ops[0].addr
        if m == "BRA":
            return [ir.Goto(ea, target)]
        if m == "BRN":
            return [ir.Nop(ea)]
        return [ir.Branch(ea, cond, target, ea + ins.size)]

    if m in isa.BIT_BRANCH:
        bit = e(0)
        return wrap([ir.Branch(ea, None, ops[1].addr, ea + ins.size,
                               bittest=(bit, m == "BBS"))])

    if m == "DBNZ":
        reg = e(0)
        return [ir.Assign(ea, reg, ir.Bin("-", reg, ir.Const(1, w))),
                ir.Branch(ea, "ne0", ops[1].addr, ea + ins.size,
                          bittest=(reg, True))]

    if m in ("JSR", "PJSR"):
        if ops and ops[0].mode == "code":
            return [ir.Call(ea, target=ops[0].addr, far=(m == "PJSR"))]
        return wrap([ir.Call(ea, expr=e(0), far=(m == "PJSR"))])

    if m == "TJSR":
        return [ir.Intrinsic(ea, "table_call", [e(0)],
                             note="implementation-defined call table")]

    if m in ("JMP", "PJMP"):
        if ops and ops[0].mode == "code":
            return [ir.Goto(ea, ops[0].addr)]
        return wrap([ir.Intrinsic(ea, "jump", [e(0)], note="indirect")])

    if m in isa.RET:
        return [ir.Ret(ea, m)]

    # --- stack and frame ---------------------------------------------------
    if m == "PUSH":
        return wrap([ir.Intrinsic(ea, "push", [e(0)])])
    if m == "PUSHA":
        return wrap([ir.Intrinsic(ea, "push", [e(0)], note="effective address")])
    if m == "PUSHC":
        return [ir.Intrinsic(ea, "push", [e(0)])]
    if m == "POPC":
        return [ir.Intrinsic(ea, "pop", [e(0)])]
    if m == "STM":
        return [ir.Intrinsic(ea, "push_regs", [e(0)])]
    if m == "LDM":
        return [ir.Intrinsic(ea, "pop_regs", [e(0)])]
    if m == "LINK":
        return [ir.Intrinsic(ea, "link", [e(0), e(1)], note="frame setup")]
    if m == "UNLK":
        return [ir.Intrinsic(ea, "unlink", [e(0)], note="frame teardown")]

    # --- control registers and traps --------------------------------------
    if m in ("ANDC", "ORC", "XORC"):
        src, dst = e(0), e(1)
        op = {"ANDC": "&", "ORC": "|", "XORC": "^"}[m]
        return wrap([ir.Assign(ea, dst, ir.Bin(op, dst, src))])

    if m == "TRAPA":
        return [ir.Intrinsic(ea, "trap", [e(i) for i in range(len(ops))])]
    if m == "TRAPE":
        return [ir.Intrinsic(ea, "trap_exception", [])]
    if m == "LDCTX":
        return [ir.Intrinsic(ea, "load_context", [])]
    if m in ("EI", "DI"):
        name = "enable_interrupts" if m == "EI" else "disable_interrupts"
        return [ir.Intrinsic(ea, name, [])]
    if m in ("SLEEP", "STOP"):
        return [ir.Intrinsic(ea, m.lower(), [])]
    if m == "NOP":
        return [ir.Nop(ea)]

    return wrap([ir.Intrinsic(ea, m, [e(i) for i in range(len(ops))],
                              note="unmodelled")])
