# Generate a comma separated value file for the basic blocks in a
# given virtual address range

from capstone import *
from capstone.arm import *
from capstone.arm64 import *

from idaapi import *

import idaapi
import idautils
import ida_funcs
import ida_gdl
import ida_kernwin
import ida_name
import ida_segment
import idc

cs = None

def capstone_disas(ea):
    global cs

    if cs == None:
        cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        cs.detail = True

    insn = ida_bytes.get_dword(ea)
    insn_bytes = insn.to_bytes(4, byteorder='little')

    return cs.disasm(insn_bytes, ea)

def get_imm(insn):
    for op in insn.operands:
        if op.type == ARM64_OP_IMM:
            return op.value.imm

def write_out_bbs(bbs):
    bbs_len = len(bbs)

    if bbs_len > 65535:
        print("WARNING: more than 65535 basic blocks, truncating")
        bbs_len = 65535

    csv = ida_kernwin.ask_file(1, "bb.csv", "Save Basic Block CSV")

    if csv == None:
        return
    
    csv_file = open(csv, "w")
    i = 0

    for bb in bbs:
        csv_file.write("0x%x" % (bb))

        if i != bbs_len - 1:
            csv_file.write(",")

        i += 1

    csv_file.flush()
    csv_file.close()

    return

def get_all_bbs_bruteforce(fxn):
    bbs = set()

    fc = idaapi.FlowChart(fxn)

    for block in fc:
        bbs.add(block.start_ea)

    return bbs

def get_all_bbs_detailed(fxn, bounds, bbs, visited):
    # First add the basic blocks from this function to the list
    bbs.update(get_all_bbs_bruteforce(fxn))

    cur = fxn.start_ea
    end = fxn.end_ea

    # Then scan the function for any other function calls
    # and do the same for those. This will miss calls through
    # function pointers, unfortunately
    while cur < end:
        insn = capstone_disas(cur)

        for disas in insn:
            # Don't follow recursion, don't follow a place
            # we've already visited, and make sure IDA has analyzed
            # the destination
            # TODO: CBZ, CBNZ, TBZ, TBNZ
            if disas.id == ARM64_INS_BL or disas.id == ARM64_INS_B:
                imm = get_imm(disas) & 0xffffffffffffffff

                if imm >= bounds[0] and imm < bounds[1]:
                    is_fxn = is_func(get_flags(imm))

                    if is_fxn and imm != fxn.start_ea and imm not in visited:
                        print("Following branch at 0x%x (to 0x%x)" % (cur, imm))
                        visited.add(imm)
                        get_all_bbs_detailed(get_func(imm), bounds, bbs, visited)

        cur += 4

    return

def detailed_bbsearch():
    sea = get_screen_ea()

    if not is_func(get_flags(sea)):
        print("Position the cursor at the start of a function")
        return

    seg = getseg(sea)

    bounds = [seg.start_ea, seg.end_ea]

    bbs = set() 
    visited = set()

    # Start search at where the cursor is
    get_all_bbs_detailed(get_func(sea), bounds, bbs, visited)

    write_out_bbs(bbs)

    return

def main():
    detailed = ida_kernwin.ask_yn(0, "Detailed basic block search?")

    if detailed == True:
        detailed_bbsearch()
        return

    start = get_screen_ea()

    end = ida_kernwin.ask_addr(0, "End?")

    if end < start:
        print("End is less than start")
        return

    fxns = idautils.Functions(start, end)
    bbs = set()

    for fxn in fxns:
        bbs.update(get_all_bbs_bruteforce(get_func(fxn)))

    write_out_bbs(bbs)

main()
