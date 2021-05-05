# Generate kwrite_instr calls that cover all functions of a kext
# for an xnuspy kernel hook

from idaapi import *
import idaapi
import idautils
import ida_kernwin
import idc

import os

seglist = []

class ChooseWindow(Choose):
    def __init__(self, title, items):
        Choose.__init__(self, title, [["Kext", 10]], flags=CH_MODAL,
                embedded=False)
        self.items = items
        self.icon = 5

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def OnSelectLine(self, n):
        segname = self.items[n][0]
        seg = ida_segment.get_segm_by_name(segname + ":__text")

        filename = segname.replace(".", "_") + "_massbp"

        fp = open(filename + ".h", "w")

        guard = filename.upper() + "_H"

        fp.write("#ifndef %s\n" % guard)
        fp.write("#define %s\n" % guard)

        # Put the ID of the function inside the immediate of the BRK
        brk = 0xd4200000
        fxnid = 0

        fxns = list(idautils.Functions(seg.start_ea, seg.end_ea))

        # orig instrs for sleh hook, indexed by function ID
        # one shot breakpoints
        fp.write("static uint32_t %s_orig_instrs[] = {\n" % filename)

        for fxnaddr in fxns:
            instr = int.from_bytes(idaapi.get_bytes(fxnaddr, 4, False), "little")
            fp.write(hex(instr) + ",\n")

        fp.write("};\n")

        fxnid = 0;

        fp.write("static void %s(void){\n" % filename)

        for fxnaddr in fxns:
            brk &= 0xffe0001f
            brk |= (fxnid << 5)
            fxnaddrh = hex(fxnaddr)
            # print("Current function {} with ID {}, brk {}".format(fxnaddrh, fxnid, hex(brk)))
            fp.write("kwrite_instr({}+kernel_slide, {}); /* FUNCTION {} */\n".format(fxnaddrh, hex(brk), hex(fxnid)))
            fxnid += 1

        fp.write("}\n")
        fp.write("#endif\n")

        print("Wrote header file to %s" % os.getcwd() + "/" + fp.name)

        fp.close()

        return n

def main():
    # Get list of segments and present to user
    for s in idautils.Segments():
        seg = idaapi.getseg(s)
        segname = ida_segment.get_segm_name(seg)

        # kext? And only add the text section
        if "com." in segname and "text" in segname:
            print("Adding segment {} to seglist".format(segname))
            seglist.append([segname.replace(":__text", "")])

    chooser = ChooseWindow("xnuspy Mass Breakpoint Generator", seglist)
    chooser.Show()

main()
