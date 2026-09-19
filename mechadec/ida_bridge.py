"""
IDA integration for mechadec.

There is no stock IDA processor module for the SPC970, so the bridge does not
depend on one: it reads the raw bytes out of the database, runs mechadec's own
decoder over them, and uses IDA's function boundaries as extra entry points on
top of the ones :mod:`mechadec.loader` discovers.  That means it works whether
the database was created with a custom SPC970 module, or loaded as a plain
binary blob at 0xFC0000.

The naming layer is wrapped so the decompilation reuses whatever labels the
analyst has already applied in IDA.

IDA is imported lazily so importing :mod:`mechadec` outside IDA stays clean.
"""

from . import cfg, decoder, cgen, isa, loader, opt, structure
from .names import Namer
from . import Program, Function, BANNER  # noqa: F401


class IdaNamer(Namer):
    def __init__(self, code_names=None):
        super().__init__(code_names=code_names)
        import ida_name
        self._ida_name = ida_name

    def _lookup(self, ea):
        try:
            return self._ida_name.get_name(ea) or None
        except Exception:
            return None

    def cell(self, addr, space="ram"):
        if space == "ram":
            n = self._lookup(addr)
            if n:
                return n
        return super().cell(addr, space)

    def code(self, ea):
        return self._lookup(ea) or super().code(ea)

    def label(self, ea):
        return self._lookup(ea) or super().label(ea)


def _read_image():
    """Rebuild the ROM image from the database segments."""
    import ida_bytes, ida_segment
    lo, hi = None, None
    seg = ida_segment.get_first_seg()
    while seg is not None:
        if seg.start_ea >= isa.ROM_BASE:
            lo = seg.start_ea if lo is None else min(lo, seg.start_ea)
            hi = seg.end_ea if hi is None else max(hi, seg.end_ea)
        seg = ida_segment.get_next_seg(seg.start_ea)
    if lo is None:
        lo, hi = isa.ROM_BASE, isa.ROM_BASE + isa.ROM_SIZE
    hi = min(hi, isa.ROM_END + 1)
    data = bytearray(hi - lo)
    got = ida_bytes.get_bytes(lo, hi - lo)
    if got:
        data[:len(got)] = got
    image = loader.Image(data, lo)
    image.primary_bank = loader.find_primary_bank(image)
    return image


def _ida_functions(image):
    import idautils
    out = []
    for ea in idautils.Functions():
        if image.is_code(ea):
            out.append(ea)
    return sorted(out)


def _prepare(extra=()):
    image = _read_image()
    entries, tables = loader.discover(image, tuple(_ida_functions(image)) + tuple(extra))
    insns, calls = decoder.decode(image.data, entries, image.base, image.is_code)
    return image, entries, tables, insns, calls


def decompile_program():
    image, entries, tables, insns, calls = _prepare()
    funcs = cfg.build_functions(insns, calls, extra_entries=entries)
    namer = IdaNamer(code_names=tables.code_names)
    out = {}
    for entry, f in funcs.items():
        opt.optimize(f)
        tree = structure.structure(f)
        out[entry] = Function(entry, namer.code(entry), f, tree,
                              cgen.generate(f, tree, namer))
    return Program(image, insns, out, namer, tables)


def decompile_one(ea):
    import ida_funcs
    f = ida_funcs.get_func(ea)
    entry = f.start_ea if f is not None else ea
    image, entries, tables, insns, calls = _prepare((entry,))
    entry_set = set(entries) | set(calls) | {entry}
    func = cfg.build_func(insns, entry, entry_set)
    if func is None:
        raise RuntimeError("mechadec: nothing decoded at 0x%06X" % entry)
    namer = IdaNamer(code_names=tables.code_names)
    opt.optimize(func)
    tree = structure.structure(func)
    return Function(entry, namer.code(entry), func, tree,
                    cgen.generate(func, tree, namer, banner=BANNER))


def apply_names():
    """Push the recovered MechaCon handler and table names into the database."""
    import ida_name, ida_bytes
    image = _read_image()
    _, tables = loader.discover(image)
    applied = 0
    for addr, label in list(tables.code_names.items()) + list(tables.data_names.items()):
        if not image.in_range(addr):
            continue
        if ida_name.get_name(addr):
            continue
        if ida_name.set_name(addr, label, ida_name.SN_NOCHECK | ida_name.SN_NOWARN):
            applied += 1
    return applied, tables
