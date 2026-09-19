# ----------------------------------------------------------------------
# Sony MechaCon ROM loader for IDA 9.x.
#
# Recognises a 256 KiB PlayStation 2 MechaCon mask-ROM dump, maps its four
# 64 KiB banks at 0xFC0000, creates internal RAM and the I/O window, selects
# the companion "spc970" processor module, and applies the MechaCon platform
# symbols and dispatch-table names that mechadec recovers.
#
# Install: copy this file into  %APPDATA%\Hex-Rays\IDA Pro\loaders\  (or the
# IDA install's loaders/ dir) together with the mechadec package.
# ----------------------------------------------------------------------

import os
import sys

import ida_bytes
import ida_entry
import ida_idp
import ida_loader
import ida_name
import ida_segment
import ida_ua
import idc

for _cand in (os.path.dirname(os.path.abspath(__file__)),
              os.path.join(os.path.dirname(os.path.dirname(
                  os.path.abspath(__file__))), "plugins")):
    if _cand not in sys.path and os.path.isdir(_cand):
        sys.path.insert(0, _cand)

from mechadec import isa, loader as mloader, sfr  # noqa: E402

FORMAT = "Sony MechaCon ROM (SPC970)"


def _image(li):
    li.seek(0)
    return mloader.Image(bytearray(li.read(li.size())), isa.ROM_BASE)


def accept_file(li, filename):
    if li.size() != isa.ROM_SIZE:
        return 0
    try:
        image = _image(li)
    except Exception:
        return 0
    if not mloader.is_mechacon(image):
        return 0
    return {"format": FORMAT, "processor": "spc970"}


def _add_seg(start, end, name, cls, data=None):
    seg = ida_segment.segment_t()
    seg.start_ea = start
    seg.end_ea = end
    seg.bitness = 1                      # 32-bit addressing
    seg.perm = (ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC
                if cls == "CODE" else
                ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)
    ida_segment.add_segm_ex(seg, name, cls, ida_segment.ADDSEG_NOSREG)
    if data is not None:
        ida_bytes.put_bytes(start, bytes(data))


def load_file(li, neflags, format):
    ida_idp.set_processor_type("spc970", ida_idp.SETPROC_LOADER)
    image = _image(li)
    image.primary_bank = mloader.find_primary_bank(image)

    # Internal RAM, then the I/O window the short bit instructions address.
    _add_seg(0x000000, isa.RAM_SIZE, "INTERNAL_RAM", "DATA")

    # The four ROM banks.  A bank that is entirely zero is reserved; the zero
    # tail of a used bank is padding and is not marked executable, so IDA's
    # analysis does not wander into it.
    for index, (start, tail) in enumerate(image.banks):
        base = isa.ROM_BASE + index * isa.BANK_SIZE
        name = "%02X" % (base >> 16)
        body = image.data[start:tail]
        if not body:
            _add_seg(base, base + isa.BANK_SIZE, "RESERVED_" + name, "DATA",
                     image.data[start:start + isa.BANK_SIZE])
            continue
        _add_seg(base, base + len(body), "ROM_" + name, "CODE", body)
        if len(body) < isa.BANK_SIZE:
            pad_start = base + len(body)
            _add_seg(pad_start, base + isa.BANK_SIZE, "PADDING_" + name, "DATA",
                     image.data[tail:start + isa.BANK_SIZE])

    entries, tables = mloader.discover(image)
    _apply_symbols(image, tables)
    _apply_entries(image, entries, tables)

    print("mechacon: primary bank 0x%06X, %d entry points, %d named handlers"
          % (image.primary_bank, len(entries), len(tables.code_names)))
    for note in tables.notes:
        print("mechacon: %s" % note)
    return 1


def _apply_symbols(image, tables):
    for addr, name in sfr.RAM_NAMES.items():
        if ida_segment.getseg(addr) is not None:
            ida_name.set_name(addr, name, ida_name.SN_NOCHECK | ida_name.SN_NOWARN)
    for addr, name in tables.data_names.items():
        if ida_segment.getseg(addr) is not None:
            ida_name.set_name(addr, name, ida_name.SN_NOCHECK | ida_name.SN_NOWARN)


def _apply_entries(image, entries, tables):
    named = tables.code_names
    primary = image.primary_bank
    ida_entry.add_entry(primary, primary, "rom_start", True)

    # The reset vector and the two far vectors live at the top of the image.
    reset = image.u16(mloader.RESET_VECTOR)
    if reset not in (0, 0xFFFF) and image.is_code(primary + reset):
        ida_name.set_name(mloader.RESET_VECTOR, "RESET_VECTOR",
                          ida_name.SN_NOCHECK | ida_name.SN_NOWARN)
    for vector in mloader.FAR_VECTORS:
        target = image.u24(vector)
        if image.is_code(target):
            ida_name.set_name(vector, "VECTOR_%06X" % vector,
                              ida_name.SN_NOCHECK | ida_name.SN_NOWARN)
            ida_entry.add_entry(target, target, named.get(target, "vector_%06X" % target),
                                True)

    for addr in entries:
        if ida_segment.getseg(addr) is None:
            continue
        ida_ua.create_insn(addr)
        name = named.get(addr)
        if name:
            ida_name.set_name(addr, name, ida_name.SN_NOCHECK | ida_name.SN_NOWARN)
