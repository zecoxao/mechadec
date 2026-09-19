# ----------------------------------------------------------------------
# Sony SPC970 processor module for IDA 9.x  (the CPU inside the PlayStation 2
# "MechaCon" optical-drive controller: CXR706080 / CXP102064 and relatives).
#
# The instruction set follows DiscoStarslayer's Ghidra SLEIGH specification
# (ghidra-spc970).  Rather than restating the encoding, this module drives
# mechadec's decoder, so the processor module and the decompiler can never
# disagree about what a byte sequence means.
#
# SPC970 is a prefix machine: the first byte usually selects an addressing
# mode and pushes the decoder into one of eight tables, and a later byte
# selects the operation that binds the pending operand.  Two prefixes can
# stack, which is how the memory-to-memory forms are encoded.  Instructions
# are 1..9 bytes and are not aligned.
#
# Install: copy this file into  %APPDATA%\Hex-Rays\IDA Pro\procs\  (or the IDA
# install's procs/ dir) together with the mechadec package, then pick
# processor "spc970" when loading a dump.
# ----------------------------------------------------------------------

import os
import sys

from ida_bytes import *
from ida_ua import *
from ida_idp import *
from ida_auto import *
from ida_funcs import *
from ida_lines import *
from ida_problems import *
from ida_offset import *
from ida_segment import *
from ida_name import *
from ida_xref import *
from ida_idaapi import *
import ida_frame
import idc

# mechadec lives in the sibling plugins directory of a normal IDA install, or
# alongside this file when both were dropped into the user directory.
for _cand in (os.path.dirname(os.path.abspath(__file__)),
              os.path.join(os.path.dirname(os.path.dirname(
                  os.path.abspath(__file__))), "plugins")):
    if _cand not in sys.path and os.path.isdir(_cand):
        sys.path.insert(0, _cand)

try:
    from mechadec import decoder as _dec
    from mechadec import isa as _isa
    from mechadec import sfr as _sfr
except ImportError:                                  # pragma: no cover
    raise ImportError(
        "spc970.py needs the 'mechadec' package on sys.path "
        "(put the mechadec directory next to this file or in IDA's plugins/)")


# operand flag markers carried in op.specval
FL_IND = 0x01        # @(Rn)
FL_PREDEC = 0x02     # @(-Rn)
FL_POSTINC = 0x04    # @(Rn+)
FL_IO = 0x08         # the operand addresses the I/O space
FL_ADDROF = 0x10     # the effective address, not the contents
FL_BIT = 0x20        # op.specflag1 holds a bit index
FL_SIGNED = 0x40     # the displacement is signed

MAX_INSN = 12        # longest SPC970 encoding, with slack


def _features(mnem):
    """Canonical IDA feature bits for a mnemonic."""
    f = 0
    if mnem in _isa.CALL:
        f |= CF_CALL
    if mnem in _isa.RET or mnem in _isa.JUMP or mnem in _isa.HALT:
        f |= CF_STOP
    if mnem == "BRA":
        f |= CF_STOP
    if mnem in _isa.BRANCH or mnem in _isa.BIT_BRANCH or mnem in _isa.LOOP_BRANCH:
        f |= CF_USE1
    return f


# Every mnemonic the decoder can emit, with a one-line description.
_INSN_DOC = {
    "MOV": "Move", "MOVC": "Move control register",
    "MOVA": "Move with zero extension to word",
    "MOVX": "Move with sign extension", "MOVXU": "Move with zero extension",
    "XCH": "Exchange", "SWAP": "Swap nibbles",
    "XOR": "Exclusive OR", "OR": "Logical OR", "AND": "Logical AND",
    "ADD": "Add", "ADDX": "Add with extend (carry)",
    "SUB": "Subtract", "SUBX": "Subtract with extend (borrow)",
    "CMP": "Compare", "NEG": "Negate", "NOT": "Complement",
    "INC": "Increment", "DEC": "Decrement",
    "MUL": "Multiply (signed)", "MULU": "Multiply (unsigned)",
    "DIV": "Divide (signed)", "DIVU": "Divide (unsigned)",
    "DADDX": "Decimal add with extend", "DSUBX": "Decimal subtract with extend",
    "SHAL": "Shift left arithmetic", "SHAR": "Shift right arithmetic",
    "SHLL": "Shift left logical", "SHLR": "Shift right logical",
    "ROTL": "Rotate left", "ROTR": "Rotate right",
    "SHXL": "Shift left through extend", "SHXR": "Shift right through extend",
    "BSET": "Set bit", "BCLR": "Clear bit", "BNOT": "Invert bit",
    "BLD": "Load bit into extend", "BST": "Store extend into bit",
    "BAND": "AND bit into extend", "BOR": "OR bit into extend",
    "BXOR": "XOR bit into extend",
    "BBC": "Branch if bit clear", "BBS": "Branch if bit set",
    "DBNZ": "Decrement and branch if not zero",
    "JMP": "Jump", "JSR": "Jump to subroutine",
    "PJMP": "Jump (far, page)", "PJSR": "Jump to subroutine (far, page)",
    "TJSR": "Jump to subroutine through the call table",
    "RTS": "Return from subroutine", "PRTS": "Return from subroutine (far)",
    "REIT": "Return from interrupt",
    "PUSH": "Push", "PUSHA": "Push effective address",
    "PUSHC": "Push control register", "POPC": "Pop control register",
    "STM": "Store multiple registers", "LDM": "Load multiple registers",
    "LINK": "Create a stack frame", "UNLK": "Remove a stack frame",
    "ANDC": "AND into control register", "ORC": "OR into control register",
    "XORC": "XOR into control register",
    "TRAPA": "Trap", "TRAPE": "Trap on exception",
    "LDCTX": "Load context", "EI": "Enable interrupts",
    "DI": "Disable interrupts", "SLEEP": "Sleep", "STOP": "Stop",
    "NOP": "No operation",
}
_INSN_DOC.update({"B" + cc: "Branch if " + cc for cc in _isa.CC})
_INSN_DOC["BRA"] = "Branch always"
_INSN_DOC["BRN"] = "Branch never"


class spc970_processor_t(processor_t):
    # third-party id (>0x8000)
    id = 0x8000 + 0x970
    flag = PR_USE32 | PR_DEFSEG32 | PRN_HEX | PR_RNAMESOK
    cnbits = 8
    dnbits = 8
    psnames = ["spc970"]
    plnames = ["Sony SPC970 (PlayStation 2 MechaCon)"]
    segreg_size = 0
    # RTS / PRTS
    retcodes = [b"\xfa", b"\xfb"]

    assembler = {
        "flag": ASH_HEXF3 | ASO_OCTF1 | ASB_BINF3 | AS_N2CHR | AS_COLON,
        "uflag": 0,
        "name": "SPC970 assembler",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": '"\'',
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".short",
        "a_dword": ".word",
        "a_qword": ".quad",
        "a_bss": ".space %s",
        "a_equ": ".equ",
        "a_seg": "seg",
        "a_curip": "$",
        "a_public": ".global",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
        "flag2": 0,
    }

    GPR = (list(_isa.RB) + ["RW0", "RW1", "RW2", "RW3", "RW4", "RW5", "FP", "SP"]
           + list(_isa.RL) + ["xFP", "xSP", "wFP", "wSP"])
    CR = ["PSW", "CCR", "PC", "CP", "DP", "EP", "UTP", "STP", "IM", "BCR",
          "USP", "SSP", "X"]

    def __init__(self):
        processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()

    # ------------------------------------------------------------------
    # tables
    # ------------------------------------------------------------------

    def init_instructions(self):
        names = ["MOV", "MOVC", "MOVA", "MOVX", "MOVXU", "XCH", "SWAP",
                 "XOR", "OR", "AND", "ADD", "ADDX", "SUB", "SUBX", "CMP",
                 "NEG", "NOT", "INC", "DEC", "MUL", "MULU", "DIV", "DIVU",
                 "DADDX", "DSUBX",
                 "SHAL", "SHAR", "SHLL", "SHLR", "ROTL", "ROTR", "SHXL", "SHXR",
                 "BSET", "BCLR", "BNOT", "BLD", "BST", "BAND", "BOR", "BXOR",
                 "BBC", "BBS", "DBNZ",
                 "JMP", "JSR", "PJMP", "PJSR", "TJSR",
                 "RTS", "PRTS", "REIT",
                 "PUSH", "PUSHA", "PUSHC", "POPC", "STM", "LDM",
                 "LINK", "UNLK", "ANDC", "ORC", "XORC",
                 "TRAPA", "TRAPE", "LDCTX", "EI", "DI", "SLEEP", "STOP", "NOP"]
        names += ["B" + cc for cc in _isa.CC]

        self.instruc = [{"name": "", "feature": 0}]
        self._itype = {}
        for name in names:
            self._itype[name] = len(self.instruc)
            self.instruc.append({"name": name.lower(),
                                 "feature": _features(name),
                                 "cmt": _INSN_DOC.get(name, "")})
        self.instruc_start = 0
        self.instruc_end = len(self.instruc)
        self.icode_return = self._itype["RTS"]

    def init_registers(self):
        self.reg_names = self.GPR + self.CR + ["cs", "ds"]
        self._rindex = {}
        for i, n in enumerate(self.reg_names):
            setattr(self, "ireg_" + n.replace(" ", "_"), i)
            self._rindex[n] = i
        self.reg_first_sreg = self._rindex["cs"]
        self.reg_last_sreg = self._rindex["ds"]
        self.reg_code_sreg = self._rindex["cs"]
        self.reg_data_sreg = self._rindex["ds"]

    def _reg(self, name):
        idx = self._rindex.get(name)
        if idx is None:                     # e.g. an alias the decoder invented
            idx = self._rindex.get(name.upper(), 0)
        return idx

    # ------------------------------------------------------------------
    # analysis
    # ------------------------------------------------------------------

    _DT = {"b": dt_byte, "w": dt_word, "l": dt_dword}

    def _fill(self, op, src):
        """Map a mechadec Operand onto an IDA op_t."""
        mode = src.mode
        dt = self._DT.get(src.width, dt_byte)

        if mode == "bit":
            self._fill(op, src.base)
            op.specval |= FL_BIT
            op.specflag1 = src.bit
            return
        if mode == "addrof":
            self._fill(op, src.base)
            op.specval |= FL_ADDROF
            return

        if mode in ("reg", "ctrl"):
            op.type = o_reg
            op.reg = self._reg(src.reg)
            op.dtype = dt
        elif mode == "imm":
            op.type = o_imm
            op.value = src.value
            op.dtype = dt
        elif mode == "abs":
            op.type = o_mem
            op.addr = src.addr
            op.dtype = dt
            if src.space == "io":
                op.specval |= FL_IO
        elif mode == "disp":
            op.type = o_displ
            op.reg = self._reg(src.base_reg)
            op.addr = src.disp & 0xFFFFFFFF
            op.dtype = dt
            op.specval |= FL_SIGNED
        elif mode == "ind":
            op.type = o_phrase
            op.reg = self._reg(src.base_reg)
            op.dtype = dt
            op.specval |= FL_IND
        elif mode == "predec":
            op.type = o_phrase
            op.reg = self._reg(src.base_reg)
            op.dtype = dt
            op.specval |= FL_PREDEC
        elif mode == "postinc":
            op.type = o_phrase
            op.reg = self._reg(src.base_reg)
            op.dtype = dt
            op.specval |= FL_POSTINC
        elif mode == "pop":
            op.type = o_phrase
            op.reg = self._reg("xSP")
            op.dtype = dt
            op.specval |= FL_POSTINC
        elif mode == "code":
            op.type = o_near
            op.addr = src.addr
            op.dtype = dt_code
        elif mode == "reglist":
            op.type = o_idpspec0
            op.value = 0
            for name in src.regs:
                op.value |= 1 << _isa.RW.index(name)
            op.dtype = dt_word
        else:
            op.type = o_void

    def ev_ana_insn(self, insn):
        buf = get_bytes(insn.ea, MAX_INSN)
        if not buf:
            return 0
        ins = _dec.decode_one(bytearray(buf), insn.ea, insn.ea)
        if ins is None or ins.size == 0 or ins.mnem is None:
            return 0
        itype = self._itype.get(ins.mnem)
        if itype is None:
            return 0
        insn.itype = itype
        insn.size = ins.size
        # the operand width is a property of the instruction, not the operand
        insn.auxpref = {"b": 1, "w": 2, "l": 4}.get(ins.width, 0)
        for i, src in enumerate(ins.ops[:4]):
            self._fill(insn[i], src)
        return insn.size

    # ------------------------------------------------------------------
    # emulation
    # ------------------------------------------------------------------

    def ev_emu_insn(self, insn):
        feat = insn.get_canon_feature()
        mnem = self.instruc[insn.itype]["name"].upper()
        is_call = (feat & CF_CALL) != 0

        for i in range(4):
            op = insn[i]
            if op.type == o_void:
                break
            if op.type == o_near:
                insn.add_cref(op.addr, op.offb, fl_CN if is_call else fl_JN)
            elif op.type == o_mem and not (op.specval & FL_IO):
                if not (op.specval & FL_ADDROF):
                    insn.create_op_data(op.addr, op)
                insn.add_dref(op.addr, op.offb, dr_R)
            elif op.type == o_displ and op.reg in (self._reg("xFP"), self._reg("FP")) \
                    and may_create_stkvars():
                if get_func(insn.ea) is not None:
                    disp = op.addr
                    if disp & 0x80000000:
                        disp -= 0x100000000
                    if insn.create_stkvar(op, disp, STKVAR_VALID_SIZE):
                        op_stkvar(insn.ea, op.n)

        # BRN never branches; everything else without CF_STOP falls through.
        if mnem == "BRN" or (feat & CF_STOP) == 0:
            insn.add_cref(insn.ea + insn.size, 0, fl_F)
        return True

    def ev_is_ret_insn(self, insn, flags):
        return 1 if self.instruc[insn.itype]["name"].upper() in _isa.RET else 0

    def ev_is_call_insn(self, insn):
        return 1 if self.instruc[insn.itype]["name"].upper() in _isa.CALL else 0

    def ev_get_autocmt(self, insn):
        return self.instruc[insn.itype].get("cmt")

    # ------------------------------------------------------------------
    # output
    # ------------------------------------------------------------------

    def ev_out_mnem(self, ctx):
        suffix = {1: ".b", 2: ".w", 4: ".l"}.get(ctx.insn.auxpref, "")
        if suffix:
            ctx.out_custom_mnem(self.instruc[ctx.insn.itype]["name"] + suffix, 9)
        else:
            ctx.out_mnem(9)
        return 1

    def _out_bit(self, ctx, op):
        if op.specval & FL_BIT:
            ctx.out_symbol(".")
            ctx.out_long(op.specflag1, 10)

    def ev_out_operand(self, ctx, op):
        if op.specval & FL_ADDROF:
            ctx.out_symbol("&")

        if op.type == o_reg:
            ctx.out_register(self.reg_names[op.reg])
        elif op.type == o_imm:
            ctx.out_symbol("#")
            ctx.out_value(op, OOFW_IMM)
        elif op.type == o_near:
            if not ctx.out_name_expr(op, op.addr, BADADDR):
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_btoa(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                remember_problem(PR_NONAME, ctx.insn.ea)
        elif op.type == o_mem:
            name = None
            if op.specval & FL_IO:
                name = _sfr.io_name(op.addr)
            if name:
                ctx.out_line(name, COLOR_IMPNAME)
            elif op.specval & FL_IO:
                ctx.out_line("io", COLOR_KEYWORD)
                ctx.out_symbol("[")
                ctx.out_btoa(op.addr, 16)
                ctx.out_symbol("]")
            elif not ctx.out_name_expr(op, op.addr, BADADDR):
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_btoa(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
        elif op.type == o_phrase:
            ctx.out_symbol("@")
            ctx.out_symbol("(")
            if op.specval & FL_PREDEC:
                ctx.out_symbol("-")
            ctx.out_register(self.reg_names[op.reg])
            if op.specval & FL_POSTINC:
                ctx.out_symbol("+")
            ctx.out_symbol(")")
        elif op.type == o_displ:
            ctx.out_symbol("@")
            ctx.out_symbol("(")
            ctx.out_value(op, OOF_ADDR | OOFW_32 | OOF_SIGNED)
            ctx.out_symbol(",")
            ctx.out_register(self.reg_names[op.reg])
            ctx.out_symbol(")")
        elif op.type == o_idpspec0:                  # LDM/STM register list
            ctx.out_symbol("{")
            first = True
            for i, name in enumerate(_isa.RW):
                if not (op.value & (1 << i)):
                    continue
                if not first:
                    ctx.out_symbol(",")
                ctx.out_register(name)
                first = False
            ctx.out_symbol("}")
        else:
            return False

        self._out_bit(ctx, op)
        return True

    def ev_out_insn(self, ctx):
        ctx.out_mnemonic()
        if ctx.insn.Op1.type != o_void:
            ctx.out_one_operand(0)
        for i in range(1, 4):
            if ctx.insn[i].type == o_void:
                break
            ctx.out_symbol(",")
            ctx.out_char(" ")
            ctx.out_one_operand(i)
        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return True

    # ------------------------------------------------------------------
    # frames
    # ------------------------------------------------------------------

    def ev_create_func_frame(self, func):
        """LINK xFP,#n opens a frame of n bytes below the saved frame pointer."""
        ea = func.start_ea
        buf = get_bytes(ea, MAX_INSN)
        if buf:
            ins = _dec.decode_one(bytearray(buf), ea, ea)
            if ins is not None and ins.mnem == "LINK" and len(ins.ops) > 1:
                ida_frame.add_frame(func, ins.ops[1].value, 2, 0)
                return 1
        ida_frame.add_frame(func, 0, 2, 0)
        return 1

    def ev_get_frame_retsize(self, frsize, func):
        # RTS pops a 16-bit PC; the far forms also pop CP, but the extra word
        # is not part of the caller's frame.
        frsize[0] = 2
        return 1


def PROCESSOR_ENTRY():
    return spc970_processor_t()
