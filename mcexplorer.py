import ctypes
import os
import sys

import ida_diskio
import ida_funcs
import ida_graph
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_pro


LEVELS = ["MMAT_GENERATED", "MMAT_PREOPTIMIZED", "MMAT_LOCOPT", "MMAT_CALLS",
          "MMAT_GLBOPT1", "MMAT_GLBOPT2", "MMAT_GLBOPT3", "MMAT_LVARS"]

class MCGraphView(ida_graph.GraphViewer):
    def __init__(self, mba, func, mmat):
        title = "MCGraph View - %s at %s" % (func, mmat)
        ida_graph.GraphViewer.__init__(self, title, True)
        self._mba = mba

    def OnRefresh(self):
        self.Clear()
        qty = self._mba.qty
        for src in range(qty):
            self.AddNode(src)
        for src in range(qty):
            mblock = self._mba.get_mblock(src)
            for dest in mblock.succset:
                self.AddEdge(src, dest)
        return True

    def OnGetText(self, node):
        mblock = self._mba.get_mblock(node)
        vp = ida_hexrays.qstring_printer_t(None, True)
        mblock._print(vp)
        return vp.s


class MCTextView(ida_kernwin.simplecustviewer_t):
    def __init__(self, mba, func, mmat):
        ida_kernwin.simplecustviewer_t.__init__(self)
        self._mba = mba
        self._func = func
        self._mmat = mmat
        title = "MCText View - %s at %s" % (func, mmat)
        self.Create(title)

        self.ClearLines()
        vp = ida_hexrays.qstring_printer_t(None, True)
        mba._print(vp)
        for line in vp.s.split('\n'):
            self.AddLine(line)

    def OnKeydown(self, vkey, shift):
        if shift == 0 and vkey == ord("G"):
            MCGraphView(self._mba, self._func, self._mmat).Show()
            return True
        return False

class MCExplorer(ida_idaapi.plugin_t):
    flags = 0
    comment = "Microcode Explorer"
    help = ""
    wanted_name = "MCExplorer"
    wanted_hotkey = "Ctrl+Shift+M"

    @staticmethod
    def ask_desired_maturity():
        class MaturityForm(ida_kernwin.Form):
            def __init__(self):
                ctrl = ida_kernwin.Form.DropdownListControl(LEVELS[::-1])
                form = """Select maturity level
                 <Select maturity level:{ctrl}>"""
                ida_kernwin.Form.__init__(self, form, {"ctrl": ctrl})

        form = MaturityForm()
        form, args = form.Compile()
        ok = form.Execute()
        mmat = 0
        if ok == 1:
            mmat = len(LEVELS) - form.ctrl.value
        form.Free()
        return mmat

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            return ida_idaapi.PLUGIN_SKIP
        print("[MCExplorer] Plugin initialized")
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        ida_hexrays.term_hexrays_plugin()
        print("[MCExplorer] Plugin terminated")

    def run(self, _):
        fn = ida_funcs.get_func(ida_kernwin.get_screen_ea())
        if fn is None:
            ida_kernwin.warning("Please position the cursor within a function")
            return True

        mmat = MCExplorer.ask_desired_maturity()
        if mmat == 0:
            return True

        hf = ida_hexrays.hexrays_failure_t()
        mbr = ida_hexrays.mba_ranges_t(fn)
        mba = ida_hexrays.gen_microcode(mbr, hf, None, 0, mmat)
        if not mba:
            return True

        fn_name = ida_funcs.get_func_name(fn.start_ea)
        mmat_name = LEVELS[mmat - 1]
        MCTextView(mba, fn_name, mmat_name).Show()
        return True


def PLUGIN_ENTRY():
    return MCExplorer()
