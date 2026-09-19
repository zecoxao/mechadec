"""
Address and code naming for the SPC970 / MechaCon decompiler.

Data addresses resolve to the documented MechaCon RAM and I/O names
(:mod:`mechadec.sfr`), then to generic ``ram_``/``io_``/``rom_`` labels; code
addresses take a name recovered from a dispatch table when there is one, and
``sub_``/``loc_`` otherwise.  Inside IDA the :class:`Namer` is fed IDA's own
names so the decompilation reuses whatever the analyst has applied.
"""

from . import isa, sfr


class Namer:
    def __init__(self, cell_names=None, code_names=None):
        self.cell_names = dict(cell_names or {})
        self.code_names = dict(code_names or {})

    def cell(self, addr, space="ram"):
        if space == "io":
            port = addr & 0xFF
            return sfr.io_name(port) or ("io_%02X" % port)
        n = self.cell_names.get(addr)
        if n:
            return n
        n = sfr.ram_name(addr)
        if n:
            return n
        if isa.is_rom(addr):
            return "rom_%06X" % addr
        if addr < 0x100:
            return "ram_%02X" % addr
        if addr < isa.RAM_SIZE:
            return "ram_%04X" % addr
        return "m_%06X" % addr

    def code(self, ea):
        return self.code_names.get(ea) or ("sub_%06X" % ea)

    def label(self, ea):
        return self.code_names.get(ea) or ("loc_%06X" % ea)
