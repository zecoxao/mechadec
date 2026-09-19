"""
C syntax highlighting for the mechadec viewer.

Token-level, using IDA's theme-aware ``SCOLOR_*`` tags.  Imported only inside
IDA; the tokenizer itself is pure and is exercised headlessly in the tests with
a stubbed ``ida_lines``.
"""

import re

import ida_lines

C_KEYWORDS = frozenset((
    "if", "else", "while", "do", "for", "return", "break", "continue",
    "goto", "switch", "case", "default", "sizeof", "typedef",
))
C_TYPES = frozenset((
    "void", "char", "short", "int", "long", "unsigned", "signed",
    "const", "u8", "u16", "u32",
))
# pseudo-calls the back-end emits for opaque / cpu-control opcodes
INTRINSICS = frozenset((
    "push", "pop", "push_regs", "pop_regs", "link", "unlink", "xch",
    "mul", "mulu", "div", "divu", "sar", "rotl", "rotr", "shxl", "shxr",
    "zext", "sext", "swap_nibbles", "deposit_bit", "bcd_add", "bcd_sub",
    "trap", "trap_exception", "table_call", "load_context", "jump",
    "enable_interrupts", "disable_interrupts", "sleep", "stop", "JUMPOUT",
))

_TOK = re.compile(r"""
      (?P<comment>/\*.*?\*/|//.*)
    | (?P<string>"(?:[^"\\]|\\.)*")
    | (?P<hex>-?\b0[xX][0-9A-Fa-f]+)
    | (?P<num>-?\b\d+\b)
    | (?P<ident>[A-Za-z_$][A-Za-z_0-9$]*)
    | (?P<ws>\s+)
    | (?P<op>.)
""", re.VERBOSE)

_CALL_AHEAD = re.compile(r"\s*\(")
_LABEL = re.compile(r"^[A-Za-z_]\w*:\s*$")


def _tag(text, color):
    return ida_lines.COLSTR(text, color)


def colorize(line):
    if not line:
        return line
    stripped = line.lstrip()
    if stripped.startswith(("//", "/*", "*", "*/")):
        return _tag(line, ida_lines.SCOLOR_AUTOCMT)
    if _LABEL.match(stripped):
        return _tag(line, ida_lines.SCOLOR_CREFTAIL)

    out = []
    pos, n = 0, len(line)
    while pos < n:
        m = _TOK.match(line, pos)
        if m is None:
            out.append(line[pos]); pos += 1; continue
        kind, text = m.lastgroup, m.group()
        pos = m.end()
        if kind == "ws":
            out.append(text)
        elif kind == "comment":
            out.append(_tag(text, ida_lines.SCOLOR_AUTOCMT))
        elif kind == "string":
            out.append(_tag(text, ida_lines.SCOLOR_STRING))
        elif kind in ("hex", "num"):
            out.append(_tag(text, ida_lines.SCOLOR_NUMBER))
        elif kind == "ident":
            out.append(_tag(text, _ident_color(text, line, pos)))
        else:
            out.append(_tag(text, ida_lines.SCOLOR_SYMBOL))
    return "".join(out)


def _ident_color(text, line, after):
    if text in C_KEYWORDS:
        return ida_lines.SCOLOR_KEYWORD
    if text in C_TYPES:
        return ida_lines.SCOLOR_TYPE
    if text.startswith(("loc_", "sub_")):
        return ida_lines.SCOLOR_CREFTAIL
    if text in INTRINSICS or _CALL_AHEAD.match(line, after):
        return ida_lines.SCOLOR_CNAME
    return ida_lines.SCOLOR_REG


def colorize_all(lines):
    return [colorize(ln) for ln in lines]
