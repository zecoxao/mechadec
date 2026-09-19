"""IDA custom viewer for mechadec output.  Imported only inside IDA."""

import re

import ida_kernwin
import idaapi

from . import highlight

_EA = re.compile(r"\b(?:loc_|sub_)([0-9A-Fa-f]+)\b")


def _line_ea(line):
    m = _EA.search(line)
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except ValueError:
        return None


class _Viewer(ida_kernwin.simplecustviewer_t):
    def __init__(self):
        super(_Viewer, self).__init__()
        self.line_ea = []

    def build(self, title, lines):
        if not ida_kernwin.simplecustviewer_t.Create(self, title):
            return False
        self.line_ea = []
        for ln in lines:
            self.AddLine(highlight.colorize(ln))
            self.line_ea.append(_line_ea(ln))
        return True

    def _jump(self):
        n = self.GetLineNo()
        if n is None or n >= len(self.line_ea):
            return False
        ea = self.line_ea[n]
        if ea is None:
            return False
        idaapi.jumpto(ea)
        return True

    def OnDblClick(self, shift):
        return self._jump()

    def OnKeydown(self, vkey, shift):
        if vkey == 13:
            return self._jump()
        if vkey == 27:
            self.Close()
            return True
        return False


def show(function):
    title = "mechadec: %s" % (function.name or "sub_%06X" % function.entry)
    v = _Viewer()
    if v.build(title, function.lines):
        v.Show()
        return v
    return None


def show_listing(title, lines):
    v = _Viewer()
    if v.build(title, lines):
        v.Show()
        return v
    return None
