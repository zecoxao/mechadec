"""
mechadec -- a decompiler for the Sony SPC970, targeting PlayStation 2
"MechaCon" optical-drive controller firmware.

The SPC970 is Sony's 16-bit MCU core; MechaCon (CXR706080 / CXP102064 and
relatives) is the chip that runs the PS2 disc mechanism, the RTC and EEPROM,
the SCMD/NCMD host protocol and MagicGate.  Its encoding is a prefix machine
with eight dispatch tables, so a byte only means something relative to the
decoder state that reached it; :mod:`mechadec.decoder` models that directly.

The ISA model is a Python re-implementation of DiscoStarslayer's
``ghidra-spc970`` SLEIGH specification.  The pipeline mirrors zecoxao's
``spudec``, ``rl78dec`` and the Kirk/Spock ``startrekdec``:

    loader -> decoder -> lifter -> cfg -> opt -> structure -> cgen
"""

from . import decoder, cfg, opt, structure, cgen, loader, mecha
from .names import Namer

__version__ = "0.1.0"

BANNER = [
    "/*",
    " * Decompiled by mechadec -- Sony SPC970 (PlayStation 2 MechaCon).",
    " * RB0-7/RW0-5/RL0-7 are the machine registers, FP/SP the frame and stack",
    " * pointers; mem8/mem16/mem32 index data memory (documented MechaCon cells",
    " * and I/O ports shown by name).  Comparisons derived from the X flag are",
    " * unsigned, those from M^V are signed.  Unmodelled opcodes are printed as",
    " * pseudo-calls.",
    " */",
    "",
]


class Function:
    def __init__(self, entry, name, func, tree, lines):
        self.entry = entry
        self.name = name
        self.cfg = func
        self.tree = tree
        self.lines = lines


class Program:
    def __init__(self, image, insns, funcs, namer, tables=None):
        self.image = image
        self.insns = insns
        self.funcs = funcs
        self.namer = namer
        self.tables = tables

    def listing(self, banner=True):
        out = list(BANNER) if banner else []
        if banner and self.tables is not None and self.tables.notes:
            out.append("/* MechaCon firmware tables recovered:")
            for note in self.tables.notes:
                out.append(" *   %s" % note)
            out.append(" */")
            out.append("")
        for entry in sorted(self.funcs):
            out.extend(self.funcs[entry].lines)
            out.append("")
        return "\n".join(out)


def decompile_image(image, entries=None, tables=None, cell_names=None,
                    code_names=None):
    """Decompile a loaded :class:`mechadec.loader.Image`."""
    if entries is None:
        entries, tables = loader.discover(image)
    insns, calls = decoder.decode(image.data, entries, image.base, image.is_code)
    funcs = cfg.build_functions(insns, calls, extra_entries=entries)

    names = dict(tables.code_names) if tables is not None else {}
    names.update(code_names or {})
    namer = Namer(cell_names=cell_names, code_names=names)

    out = {}
    for entry, f in funcs.items():
        opt.optimize(f)
        tree = structure.structure(f)
        lines = cgen.generate(f, tree, namer)
        out[entry] = Function(entry, namer.code(entry), f, tree, lines)
    return Program(image, insns, out, namer, tables)


def decompile_file(path, extra_entries=(), base=loader.isa.ROM_BASE, **kw):
    image = loader.load(path, base)
    entries, tables = loader.discover(image, extra_entries)
    return decompile_image(image, entries, tables, **kw)
