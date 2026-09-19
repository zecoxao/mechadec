"""
IDA plugin entry point for mechadec, the Sony SPC970 / PlayStation 2 MechaCon
decompiler.

Install by copying this file *and* the ``mechadec`` package directory together
into IDA's user plugin directory:

    %APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\

mechadec carries its own SPC970 decoder, so it does not need a processor
module: it runs on a database created with the companion ``spc970`` processor
module, and equally on one where the ROM was loaded as a plain binary blob at
0xFC0000.

    Ctrl-Shift-S   decompile the function under the cursor
    Ctrl-F5        decompile every function in the database
"""

import os
import sys
import time
import traceback

import ida_idaapi
import ida_kernwin
import ida_funcs

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

HOTKEY_ONE = "Ctrl-Shift-S"
HOTKEY_ALL = "Ctrl-F5"

_views = []
_hotkeys = []


def _in_rom():
    """True when the database holds something mapped where SPC970 code lives."""
    try:
        import ida_segment
        from mechadec import isa
        seg = ida_segment.get_first_seg()
        while seg is not None:
            if seg.start_ea >= isa.ROM_BASE or seg.end_ea > isa.ROM_BASE:
                return True
            seg = ida_segment.get_next_seg(seg.start_ea)
    except Exception:
        pass
    return False


def _run_one():
    from mechadec import ida_bridge, view
    ea = ida_kernwin.get_screen_ea()
    if ida_funcs.get_func(ea) is None:
        if ida_kernwin.ask_yn(1, "mechadec: there is no function at 0x%06X.\n"
                                 "Decompile from this address anyway?" % ea) != 1:
            return
    try:
        fn = ida_bridge.decompile_one(ea)
    except Exception:
        ida_kernwin.warning("mechadec failed:\n\n%s" % traceback.format_exc())
        return
    v = view.show(fn)
    if v is not None:
        _views.append(v)
    print("mechadec: %s -> %d blocks" % (fn.name, len(fn.cfg.blocks)))


def _run_all():
    from mechadec import ida_bridge, view
    import ida_nalt
    ida_kernwin.show_wait_box("mechadec: decompiling all functions...")
    t0 = time.time()
    try:
        prog = ida_bridge.decompile_program()
    except Exception:
        ida_kernwin.hide_wait_box()
        ida_kernwin.warning("mechadec: decompile all failed:\n\n%s" % traceback.format_exc())
        return
    finally:
        try:
            ida_kernwin.hide_wait_box()
        except Exception:
            pass
    lines = prog.listing().splitlines()
    print("mechadec: %d functions in %.1fs" % (len(prog.funcs), time.time() - t0))

    default = os.path.splitext(ida_nalt.get_input_file_path() or "mechacon")[0] + ".c"
    path = ida_kernwin.ask_file(True, default, "Save the decompiled listing")
    if path:
        try:
            with open(path, "w", encoding="utf-8") as fp:
                fp.write("\n".join(lines) + "\n")
            print("mechadec: wrote %d lines to %s" % (len(lines), path))
        except Exception as exc:
            ida_kernwin.warning("mechadec: could not write %s:\n%s" % (path, exc))
    v = view.show_listing("mechadec - all functions", lines)
    if v is not None:
        _views.append(v)


def _apply_names():
    from mechadec import ida_bridge
    try:
        applied, tables = ida_bridge.apply_names()
    except Exception:
        ida_kernwin.warning("mechadec: naming failed:\n\n%s" % traceback.format_exc())
        return
    for note in tables.notes:
        print("mechadec: %s" % note)
    print("mechadec: applied %d MechaCon names" % applied)


class MechaDecPlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "Sony SPC970 (PS2 MechaCon) decompiler: lifter + structuring + pseudo-C"
    help = "%s decompiles the current function, %s decompiles everything." % (HOTKEY_ONE, HOTKEY_ALL)
    wanted_name = "SPC970 decompiler (mechadec)"
    wanted_hotkey = HOTKEY_ONE

    def init(self):
        ctx = ida_kernwin.add_hotkey(HOTKEY_ALL, _run_all)
        if ctx is not None:
            _hotkeys.append(ctx)
        ctx = ida_kernwin.add_hotkey("Ctrl-Shift-M", _apply_names)
        if ctx is not None:
            _hotkeys.append(ctx)
        print("mechadec: loaded -- %s = this function, %s = decompile all, "
              "Ctrl-Shift-M = apply MechaCon names" % (HOTKEY_ONE, HOTKEY_ALL))
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        _run_one()

    def term(self):
        for ctx in _hotkeys:
            try:
                ida_kernwin.del_hotkey(ctx)
            except Exception:
                pass
        del _hotkeys[:]
        del _views[:]


def PLUGIN_ENTRY():
    return MechaDecPlugin()
