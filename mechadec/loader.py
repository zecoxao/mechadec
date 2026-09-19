"""
Image loading and entry-point discovery for SPC970 / MechaCon firmware.

A MechaCon dump is a flat 256 KiB mask-ROM image mapped at 0xFC0000, made of
four 64 KiB banks; unused banks are zero filled and every used bank has a zero
tail.  One bank holds the startup routine and is the *primary* bank -- it is
found by the fixed byte signature of that routine, exactly as the Ghidra
loader does.

Entry-point discovery is the part that decides how much of a ROM gets
decompiled.  SPC970 code is dense and prefix-driven, so decoding from a wrong
address produces plausible-looking garbage; the discovery here is deliberately
conservative and layered:

    1. the primary bank base, the far vectors at 0xFFFF90 / 0xFFFF9C, and the
       reset vector when it resolves to an executable address;
    2. the MechaCon dispatch tables (SCMD, NCMD, PMAP, MagicGate) and the
       signature-anchored helper routines;
    3. every 24-bit ROM pointer stored anywhere in the image whose target
       begins with a real function prologue (``LINK`` or ``STM``);
    4. the call targets that recursive descent finds from all of the above,
       iterated to a fixed point.

Step 3 only ever accepts a prologue, because accepting any decodable target
floods the result with data misread as code.
"""

import struct

from . import isa, mecha
from .decoder import decode, decode_one

RESET_VECTOR = 0xFFFFFE
FAR_VECTORS = (0xFFFF90, 0xFFFF9C)
LICENSE_MARKER = (b"Licensed bySonyComputerEntertainment"
                  b"of America(Europe)Inc.")

# The startup routine of every known MechaCon revision, with the two bytes
# that differ between builds left out.
_STARTUP = (
    (0x00, bytes((0xE6, 0x00, 0xD8, 0xE8))),
    (0x05, bytes((0x09, 0x36, 0xCC, 0x06, 0x0A, 0xD8, 0xE8))),
    (0x0D, bytes((0x09, 0xEA, 0x00, 0x01, 0xE8))),
    (0x13, bytes((0x09, 0xE8))),
    (0x16, bytes((0x09, 0xCC, 0x07, 0x04, 0xEC))),
)
_STARTUP_TAIL = (bytes((0xE5, 0xFF, 0xE2, 0x80)), bytes((0xE6, 0xFF, 0xE2, 0x80)))

# Prologues that mark a genuine function entry.
PROLOGUE = frozenset(("LINK", "STM"))


class Image:
    """A loaded ROM: the bytes, where they are mapped, and which parts of them
    are executable."""

    def __init__(self, data, base=isa.ROM_BASE):
        self.data = bytearray(data)
        self.base = base
        self.banks = []
        for start in range(0, len(self.data), isa.BANK_SIZE):
            end = min(start + isa.BANK_SIZE, len(self.data))
            tail = end
            while tail > start and self.data[tail - 1] == 0:
                tail -= 1
            self.banks.append((start, tail))
        self.primary_bank = None

    # -- geometry -----------------------------------------------------------

    def __len__(self):
        return len(self.data)

    def offset(self, addr):
        return addr - self.base

    def in_range(self, addr):
        o = addr - self.base
        return 0 <= o < len(self.data)

    def is_code(self, addr):
        """True when *addr* lies in the non-zero body of a mapped bank."""
        o = addr - self.base
        if not (0 <= o < len(self.data)):
            return False
        start, tail = self.banks[o // isa.BANK_SIZE]
        return start <= o < tail

    def u8(self, addr):
        o = addr - self.base
        return self.data[o] if 0 <= o < len(self.data) else 0

    def u16(self, addr):
        o = addr - self.base
        if o < 0 or o + 2 > len(self.data):
            return 0
        return struct.unpack_from("<H", self.data, o)[0]

    def u24(self, addr):
        o = addr - self.base
        if o < 0 or o + 3 > len(self.data):
            return 0
        return (self.data[o] | (self.data[o + 1] << 8)
                | (self.data[o + 2] << 16))

    def code_bytes(self):
        return sum(tail - start for start, tail in self.banks)


def load_raw(path):
    with open(path, "rb") as fp:
        return bytearray(fp.read())


def load(path, base=isa.ROM_BASE):
    img = Image(load_raw(path), base)
    img.primary_bank = find_primary_bank(img)
    return img


def find_primary_bank(image):
    """The bank that holds the startup routine, as an absolute address."""
    for index in range(len(image.banks)):
        addr = image.base + index * isa.BANK_SIZE
        if _startup_matches(image, addr):
            return addr
    return image.base


def _startup_matches(image, addr):
    for off, want in _STARTUP:
        o = image.offset(addr + off)
        if o < 0 or o + len(want) > len(image.data):
            return False
        if bytes(image.data[o:o + len(want)]) != want:
            return False
    o = image.offset(addr + 0x1C)
    got = bytes(image.data[o:o + 4])
    return got in _STARTUP_TAIL


def is_mechacon(image):
    """Recognise a MechaCon ROM: the right size, a startup routine, and the
    licence string Sony stamps into the last bank."""
    if len(image.data) != isa.ROM_SIZE:
        return False
    if not any(_startup_matches(image, image.base + i * isa.BANK_SIZE)
               for i in range(len(image.banks))):
        return False
    window = bytes(image.data[0x3B000:0x3B400])
    return LICENSE_MARKER in window


# ---------------------------------------------------------------------------
# entry-point discovery
# ---------------------------------------------------------------------------


def vector_entries(image):
    """Reset and far vectors, plus the primary bank base."""
    out = []
    primary = image.primary_bank or image.base
    out.append(primary)
    reset = image.u16(RESET_VECTOR)
    if reset not in (0, 0xFFFF):
        target = primary + reset
        if image.is_code(target):
            out.append(target)
    for vector in FAR_VECTORS:
        target = image.u24(vector)
        if image.is_code(target):
            out.append(target)
    return out


def prologue_entries(image):
    """Every 24-bit ROM pointer in the image whose target starts a function."""
    data = image.data
    base = image.base
    seen = set()
    out = []
    for o in range(len(data) - 2):
        value = data[o] | (data[o + 1] << 8) | (data[o + 2] << 16)
        if value < isa.ROM_BASE or value in seen or not image.is_code(value):
            continue
        seen.add(value)
        ins = decode_one(data, value, base)
        if ins is not None and ins.size and ins.mnem in PROLOGUE:
            out.append(value)
    return out


def discover(image, extra_entries=()):
    """Full entry discovery.  Returns ``(entries, tables)``."""
    primary = image.primary_bank or image.base
    tables = mecha.Tables()
    if is_mechacon(image):
        tables = mecha.discover(image.data, image.base, primary, image.is_code)

    seeds = set(vector_entries(image))
    seeds.update(tables.entries)
    seeds.update(prologue_entries(image))
    seeds.update(e for e in extra_entries if image.is_code(e))

    # Iterate: recursive descent finds call targets, which are themselves
    # entries, which may reach further calls.
    entries = {e for e in seeds if image.is_code(e)}
    for _ in range(8):
        _, calls = decode(image.data, sorted(entries), image.base, image.is_code)
        fresh = {c for c in calls if image.is_code(c)} - entries
        if not fresh:
            break
        entries |= fresh
    return sorted(entries), tables
