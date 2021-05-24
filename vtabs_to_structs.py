# meant to be used on a fully-symbolized iOS kernelcache/kext, then import the header
# to that symbolicated kcache, then generate header file from local types to
# import into another database
#
# Must delete the OS* from IDA before importing this, since this script
# makes its own to handle the inheritance correctly

from idaapi import *
from pathlib import Path

from capstone import *
from capstone.arm import *
from capstone.arm64 import *

from keystone import *

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

import idaapi
import ida_bytes
import ida_kernwin
import ida_name
import ida_segment
import ida_typeinf
import idautils
import idc
import os
import re

til = None

cs = None
uc = None

def capstone_disas(ea):
    global cs

    insn = ida_bytes.get_dword(ea)
    insn_bytes = insn.to_bytes(4, byteorder='little')

    return cs.disasm(insn_bytes, ea)

def capstone_init():
    global cs

    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    cs.detail = True

stack_bottom = 0

def unicorn_init():
    global stack_bottom
    global uc

    # Fingers crossed there are no holes in this VM region...
    start = ida_segment.get_first_seg().start_ea
    end = (ida_segment.get_last_seg().end_ea + 0x400) & ~0x3ff
    stack_bottom = end

    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)

    # Map the entire kc and stack only once
    uc.mem_map(start, end - start)
    uc.mem_map(stack_bottom, 0x400)

    uc.reg_write(UC_ARM64_REG_SP, stack_bottom + 0x400)
    uc.reg_write(UC_ARM64_REG_CPACR_EL1, 0x300000)

# important - order by length
c_keywords = ["volatile", "unsigned", "register", "struct", "static",
        "signed", "union", "const", "void", "enum", "auto"]
primitive_types = ["bool", "char", "short", "int", "long", "float", "double"]
stdint_types = ["int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t",
        "uint32_t", "int64_t", "uint64_t", "int128_t", "uint128_t",
        "intptr_t", "uintptr_t", "intmax_t", "uintmax_t", "int_fast8_t",
        "int_fast16_t", "int_fast32_t", "int_fast64_t", "int_least8_t",
        "uint_least16_t", "uint_least32_t", "uint_least64_t", "uint_fast8_t",
        "uint_fast16_t", "uint_fast32_t", "uint_fast64_t", "uint_least8_t",
        "uint_least16_t", "uint_least32_t", "uint_least64_t"]
kernel_types = ["SInt8", "UInt8", "SInt16", "UInt16", "SInt32", "UInt32",
        "SInt64", "UInt64", "task_t", "event_t"]
ida_types = ["_BOOL1", "_BOOL2", "_BOOL4", "__int8", "__int16", "__int32",
    "__int64", "__int128", "_BYTE", "_WORD", "_DWORD", "_QWORD", "_OWORD",
    "_TBYTE", "_UNKNOWN"]

def is_primitive_type(type_str):
    return type_str in primitive_types

def is_stdint_type(type_str):
    return type_str in stdint_types

def is_ida_type(type_str):
    return type_str in ida_types

def get_raw_type(type_str):
    raw_type = type_str

    # also, remove void pointers all-together
    # C static arrays
    raw_type = re.sub(r'\[\d+\]', "", raw_type)
    # C++ template args
    raw_type = re.sub(r'<.*>', "", raw_type)
    raw_type = raw_type.replace("*", "")
    raw_type = raw_type.replace("(", "")
    raw_type = raw_type.replace(";", "")
    raw_type = raw_type.replace(")", "")
    raw_type = raw_type.replace("&", "")
    raw_type = raw_type.replace("[]", "")

    # remove keywords 
    # but make sure we only remove keywords, not keywords which happen
    # to be part of object names
    # ex: "time_struct_t" is left unchanged
    raw_type_list = raw_type.split(" ")
    # print("Raw type list before: {}".format(raw_type_list))

    raw_type_list = [raw_arg_type for raw_arg_type in raw_type_list if raw_arg_type not in c_keywords]

    # print("Raw type list after: {}".format(raw_type_list))
    # print()

    raw_type = " ".join(raw_type_list)

    # print("Raw type string after: {}".format(raw_type))
    # print()

    # special case for fxn pointer args: add commas between argument types
    # so we can split it later when parsing for fwd decls
    if "," in raw_type:
        raw_type = raw_type.replace(",", " ")
        tokens = raw_type.split()
        # print("Function pointer arg tokens before: {}".format(tokens))
        # remove C keywords and primitive types from the list of function
        # pointer arguments
        # tokens = [token for token in tokens if is_primitive_type(token) == False and token not in c_keywords]
        # print("Function pointer arg tokens after: {}".format(tokens))

        raw_type = ",".join(sorted(set(tokens), key=tokens.index))
        # print(raw_type)
    else:
        # remove duplicate types (ex: "long long" --> "long")
        tokens = raw_type.split()
        raw_type = " ".join(sorted(set(tokens), key=tokens.index))
        # remove spaces
        raw_type = raw_type.replace(" ", "")

    # print("Final raw type string after: {}".format(raw_type))
    # print()

    return raw_type 

def should_fwd_decl(raw_type_str):
    global til

    return is_primitive_type(raw_type_str) == False and is_stdint_type(raw_type_str) == False and is_ida_type(raw_type_str) == False and len(raw_type_str) > 0 and raw_type_str != "..." #and ida_typeinf.get_named_type64(til, raw_type_str, NTF_TYPE) == None

def fix_type(type):
    # C++ templates
    type = re.sub(r'<.*>', "", type)
    type = type.replace(">", "");
    type = type.replace("~", "DTOR_");

    return type

# scan function args and build a list of argument types
# the complexity is to deal with the problem of function pointer arguments
def get_arg_type_list(fxn_args):
    paren_stack = []
    arg_list = []

    start = 0
    end = 0

    # print("fxn_args: {}".format(fxn_args))

    for c in fxn_args:
        if c == '(':
            paren_stack.append(c)
        elif c == ')':
            if len(paren_stack) > 0:
                paren_stack.pop()
        elif c == ',':
            if len(paren_stack) == 0:
                arg = fxn_args[start:end]
                # print("got arg {}".format(arg))
                arg_list.append(arg)
                # start = fxn_args.find(",", start) + 2
                start = end + 2

        end += 1

    # print("Got args: {}".format(arg_list))

    # fix up some buggy corner cases
    for i in range(len(arg_list)):
        arg_list[i] = re.sub(r'[\w\d]+::\*', '*', arg_list[i])

    return arg_list

# don't forget to handle argument lists inside function pointers
def get_fwd_decls(arg_type_list):
    fwd_decls = []

    for arg_type in arg_type_list:
        raw_arg_type = get_raw_type(arg_type)

        if should_fwd_decl(raw_arg_type):
            # check if we got a function pointer argument
            # in this case, we need to scan all its args and forward
            # declare those as needed
            if "," in raw_arg_type:
                # fxn_ptr_raw_arg_types = raw_arg_type.split(",")
                # remove C keywords and primitive types from the list of function
                # pointer arguments
                fxn_ptr_raw_arg_types = [raw_arg_type for raw_arg_type in raw_arg_type.split(",") if is_primitive_type(raw_arg_type) == False and raw_arg_type not in c_keywords]
                for fxn_ptr_raw_arg_type in fxn_ptr_raw_arg_types:
                    if should_fwd_decl(fxn_ptr_raw_arg_type):
                        fwd_decls.append(fix_type(fxn_ptr_raw_arg_type))
            else:
                fwd_decls.append(fix_type(raw_arg_type))

    return fwd_decls

# really weird corner cases which I don't feel like dealing with
# and can be excluded without degrading the quality of the database
# ios 12 beta kernel & ios 14 beta 4 research kernel blacklist
BLACKLIST = ["SimpleEval", "IOAVService::DisplayIDParser::readDisplayID",
        "IOAVService::DisplayIDParser::parseDisplayID",
        "IOMFB::TypedProp",
        "UPPipe_H10P_Trampoline::ActiveCallback",
        "UPPipe_H10P_Trampoline::EventCallback",
        "IOMFB::LateralLeakageHandler::CurveEvaluator", "AppleBCMWLANParseRing",
        "UPPipe_H11P_Trampoline::EventCallback",
        "scaled_twopfour_degamma", "scaled_sRGB_degamma", "VideoInterfaceStub",
        "VideoInterface", "VideoInterfaceIOAV", "VideoInterfaceMipi",
        "CurveType0", "CurveType2", "CurveType4", "FnCurve", "LUTSampler",
        "NullWrap", "CurveConvolver", "SysGamma", "HDRGammaFunc"]

def read_cstring(ea):
    len = ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C)
    return ida_bytes.get_strlit_contents(ea, len, ida_nalt.STRTYPE_C)

class SymbolicatedVtable:
    # name: class name this vtable is for
    # fields: list of strings, each representing one virtual function
    def __init__(self, name):
        self.name = name
        self.fields = []

    def add(self, field):
        if field not in self.fields:
            self.fields.append(field)

class IOKitClass:
    # svt: pointer to SymbolicatedVtable object
    def __init__(self, svt):
        self.svt = svt

class InheritanceHierarchy:
    # parent: pointer to InheritanceHierarchy for the parent class
    # children: list of the children InheritanceHierarchy objs of this
    #           class, can be empty
    # name: name of this class
    # sz: size of this class, without inheritance
    # totsz: size of this class, including the inheritance
    # ioc: pointer to IOKitClass for this given class
    def __init__(self, parent, name, sz, totsz=0, ioc=None):
        self.parent = parent
        self.children = []
        self.name = name
        self.sz = sz
        self.totsz = totsz
        self.ioc = ioc

    def add_child(self, child):
        for c in self.children:
            if c.name == child.name:
                return
        # if self.name == "IO80211InfraInterface":
        # print("Adding {} to {}'s children".format(child.name, self.name))
        self.children.append(child)
        # print("Child list size {}".format(len(self.children)))

def get_OSMetaClass_ctor():
    all_fxns = list(idautils.Functions())

    for fxnea in all_fxns:
        # print(hex(fxnea))
        mangled = ida_funcs.get_func_name(fxnea)
        demangled = idc.demangle_name(mangled, get_inf_attr(idc.INF_LONG_DN))

        if demangled == "OSMetaClass::OSMetaClass(char const*, OSMetaClass const*, unsigned int)":
            return fxnea

    return 0

def hook_invalid(mu, access, address, size, value, user_data):
    print("Invalid memory access at 0x%x..." %(address));
    mu.mem_map(address, 1024)
    return True

def hook_invalid_insn(uc):
    print("Invalid instruction ")
    return

# Overrides for x1, x2, and x3, may get set in hook_code
reg_overrides = [0, 0, 0]

# Take care of cases where we load a pointer that's meant to be
# resolved later. This will save the address of that pointer so
# we can use IDAPython to determine what it is supposed to be
#
# We just save the last non-zero value of x1, x2, and x3, and then
# if any of those regs end up being zero after emulation is done,
# we swap them with that value.
def hook_code(uc, address, size, user_data):
    global reg_overrides

    insn = int.from_bytes(uc.mem_read(address, size), byteorder='little')

    # print(">>> Tracing 0x%x at 0x%x, instruction size = 0x%x" %(insn, address, size))

    # Skip any PAC instrs
    # if (insn & 0xfffff01f) == 0xd503201f:
    #     print("SKIPPING POTENTIAL PAC INSTR")
    #     uc.reg_write(UC_ARM64_REG_PC, address + 4)
    #     return

    cd = list(capstone_disas(address))

    if len(cd) == 0:
        # print("SKIPPING INSN {}".format(hex(insn)))
        uc.reg_write(UC_ARM64_REG_PC, address + 4)
        return

    x1 = uc.reg_read(UC_ARM64_REG_X1)
    x2 = uc.reg_read(UC_ARM64_REG_X2)
    w3 = uc.reg_read(UC_ARM64_REG_W3)

    # If this is an LDR, then calculate its immediate now, in case
    # the dereference ends up setting the register to zero
    # LDR (W|X)n, [Xn, #n]
    # disas = capstone_disas(address)

    ldr_dst = 0
    ldr_src = 0
    ldr_disp = 0

    for disas in cd:
        # print("{} {}: ID {}".format(disas.mnemonic, disas.op_str, disas.id))
        # If we're gonna execute a BL while trying to reach the
        # current xref, just skip it
        if disas.id == ARM64_INS_BL:
            # print("SKIPPING BL")
            uc.reg_write(UC_ARM64_REG_PC, address + 4)
            return

        if disas.id == ARM64_INS_LDR:
            for op in disas.operands:
                # print("{}".format(op.type))
                if op.type == ARM64_OP_MEM:
                    # print("LDR imm: {}".format(hex(op.value.imm)))
                    ldr_src = op.mem.base
                    ldr_disp = op.mem.disp
                if op.type == ARM64_OP_REG:
                    ldr_dst = op.value.reg
            
            # print("Dst {} src {} disp {}".format(disas.reg_name(ldr_dst), disas.reg_name(ldr_src), hex(ldr_disp)))
            # print(uc.mem_read(address + ldr_disp, 8))

            a = uc.mem_read(address + ldr_disp, 8)
            target = int.from_bytes(a, byteorder='little')

            if target == 0:
                if ldr_src == ARM64_REG_X1:
                    x1 += ldr_disp
                    reg_overrides[0] = x1

                if ldr_src == ARM64_REG_X2:
                    x2 += ldr_disp
                    reg_overrides[1] = x2

# Emulate up to some point and return (x1, x2, w3)
def emulate(startea, endea):
    global reg_overrides
    global stack_bottom
    global uc

    # Align on a 1024-byte boundry
    aligned_startea = startea & ~0x3ff
    aligned_endea = (endea + 0x400) & ~0x3ff

    len = aligned_endea - aligned_startea

    # print("startea {} endea {}".format(hex(startea), hex(endea)))
    # print("start {} end {} len {}".format(hex(aligned_startea), \
    #         hex(aligned_endea), hex(len)))

    uc.reg_write(UC_ARM64_REG_SP, stack_bottom + 0x400)
    uc.mem_write(aligned_startea, ida_bytes.get_bytes(aligned_startea, len))
    uc.hook_add(UC_HOOK_CODE, hook_code, begin=startea, end=endea)
    uc.hook_add(UC_HOOK_INSN_INVALID, hook_invalid_insn)
    # uc.hook_add(UC_HOOK_INSN, hook_invalid_insn)
    uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_invalid)
    # try:
    uc.emu_start(startea, endea)
    # except UcError as e:
    #     print("ERROR: %s" % e)
    # print("Done")

    x1 = uc.reg_read(UC_ARM64_REG_X1)
    x2 = uc.reg_read(UC_ARM64_REG_X2)
    w3 = uc.reg_read(UC_ARM64_REG_W3)

    if x1 == 0:
        x1 = reg_overrides[0]

    if x2 == 0:
        x2 = reg_overrides[1]

    if w3 == 0:
        w3 = reg_overrides[2]

    return [x1, x2, w3]

# Get the arguments to OSMetaClass::OSMetaClass, where PC-relative
# addressing of class name is resolved to a string
# ea points to a BL to OSMetaClass::OSMetaClass
def get_OSMetaClass_ctor_args(ea):
    # args = idaapi.get_arg_addrs(ea)

    # Lazy solution - just let unicorn emulate it up to the BL
    # First we gotta figure out the start of this function
    fxnstart = ida_funcs.get_func(ea).start_ea

    # Then we emulate it up to the function call
    params = emulate(fxnstart, ea)

    # for i in range(len(params)):
    #     print("x{}: {}".format(i+1, hex(params[i])))

    classname = read_cstring(params[0])
    superclass = params[1]
    superclass_name = None

    if superclass != 0:
        superclass_name = idc.demangle_name(idaapi.get_name(params[1]), get_inf_attr(idc.INF_LONG_DN))
        
        # In case the superclass pointer references a pointer that is
        # meant to be resolved later
        if superclass_name == None:
            superclass_name = idaapi.get_name(ida_bytes.get_qword(params[1]))
            superclass_name = idc.demangle_name(superclass_name, get_inf_attr(idc.INF_LONG_DN))

        superclass_name = superclass_name[0:superclass_name.find("::")]

    args = [ superclass_name, classname.decode(), params[2] ]

    # if superclass_name == "AUAUnitDictionary":
    #     for i in range(len(params)):
    #         print("x{}: {}".format(i+1, hex(params[i])))

    #     print(args)

        # return

    return args

def write_spaces(amt):
    while amt > 0:
        print("    ", end="")
        amt -= 1

def desc_ih(ih):
    # print("{} ({} bytes, total {} bytes)".format(ih.name, ih.sz, ih.totsz), end="")
    # if ih.parent != None:
        # print("{} (parent: {}, parent class size: {} bytes, child class size: {} bytes," \
        #         " parent class total size: {} bytes, child class total size: {} bytes)".format(ih.name,    \
        #             ih.parent.name, ih.parent.sz, ih.sz, ih.parent.totsz, \
        #             ih.totsz))
        # print("{} (parent: {}, ME:{}/P:{}, TOTAL:{})".format(ih.name, ih.parent.name, \
        #         ih.sz, ih.parent.sz, ih.totsz))
    print("{} ({} bytes)".format(ih.name, ih.sz))
    # else:
        # print("{} (parent: none, child class size: {} bytes, child class total size: {} bytes)".format(ih.name,    \
        #             ih.sz, ih.totsz))
        # print("{} ({})".format(ih.name, ih.sz))
        # print("{} (parent: none, {} bytes, total {} bytes)".format(ih.name, ih.sz, ih.totsz))

def dump_ih(ih, level):
    # if level == 1:
    write_spaces(level)
    # print("[{}]  ".format(level), end="")
    desc_ih(ih)
    # print(" ---> ", end="")

    for child in ih.children:
        # desc_ih(child)
        # print()
        dump_ih(child, level + 1)
        # print()

    # print(" [END({})]".format(ih.name))
    # print()

def write_spaces_to_file(file, amt):
    while amt > 0:
        file.write(" ")
        amt -= 1

def dump_hierarchy_to_file(file, ih, level):
    write_spaces_to_file(file, level*4)
    file.write("{} ({} bytes)\n".format(ih.name, ih.sz))

    for child in ih.children:
        dump_hierarchy_to_file(file, child, level + 1)

    return

# We subtract 8 from the padding to account for the vtable (which is
# not included in the member structure)
def generate_structs_for_children(file, ih, padname):
    if len(ih.children) == 0:
        return

    for child in ih.children:
        file.write("struct /*VFT*/ {}_vtbl {{\n".format(child.name))

        if child.ioc != None:
            for vtab_field in child.ioc.svt.fields:
                file.write("\t{}\n".format(vtab_field))
        else:
            print("Child {} has no vtable...".format(child.name))

        file.write("};\n\n")

        if child.parent != None:
            file.write("struct __cppobj {}_mbrs : {}_mbrs {{\n".format(child.name,
                child.parent.name))

            # Child class size is child.sz - the sum of the parent class
            # sizes - 8 (for the vtable)
            # Child class size is (child.sz - 8) - (parent.sz - 8) (to exclude vtables)
            # totsz = child.sz - 8
            # p = child.parent

            # while p != None:
            #     totsz = totsz - p.sz
            #     p = p.parent

            # padsz = child.sz - 8
            # padsz = totsz

            padsz = (child.sz - 8) - (child.parent.sz - 8)

            if padsz < 0:
                print("Negative padsz:")
                print("Parent: {} child: {}".format(child.parent.name, child.name))
                print("Parent size: {} child size: {}".format(child.parent.sz, child.sz))
                # dummy = ida_kernwin.ask_yn(0, "Halt")

            if padsz > 2:
                # Include two guard vars at the start and end
                # The biggest goal for this script is to generate structs
                # that work with "Add missing fields" inside IDA
                # But, when I try and create a gap out of the pad vars,
                # it completely destroys the structure itself and wrecks 
                # any struct that happened to inherit from the struct
                # which I tried to create a gap in.
                #
                # Including two guards prevents this from happening.
                # For "Add missing fields inside IDA":
                #   1. undefine the pad field inside the struct, to make
                #      a gap
                #   2. set offset delta to -8, because we are messing
                #      with the members struct and not the actual class
                #      struct (therefore does not include the vtable)
                #   3. add missing fields will work

                file.write("\tuint8_t __start_guard;\n")
                file.write("\tuint8_t __pad{}[{}];\n".format(padname, padsz - 2))
                file.write("\tuint8_t __end_guard;\n")
            elif padsz == 0:
                file.write("\n")
            else:
                file.write("\tuint8_t __pad{}[{}];\n".format(padname, padsz))

            file.write("};\n\n")

            file.write("struct __cppobj {} {{\n".format(child.name))
            file.write("\t{}_vtbl *__vftable /*VFT*/;\n".format(child.name))
            file.write("\t{}_mbrs m;\n".format(child.name))
            file.write("};\n\n")
        else:
            print("******Child {} has no parent???".format(child.name))

        generate_structs_for_children(file, child, padname + 1)

def generate_header_file(file, ihs):
    for ih in ihs:
        if ih.ioc != None:
            file.write("struct /*VFT*/ {}_vtbl {{\n".format(ih.name))

            for vtab_field in ih.ioc.svt.fields:
                file.write("\t{}\n".format(vtab_field))

            file.write("};\n\n")

            file.write("struct __cppobj {}_mbrs {{\n".format(ih.name))

            padsz = ih.sz - 8

            if padsz > 2:
                file.write("\tuint8_t __start_guard;\n")
                file.write("\tuint8_t __pad0[{}];\n".format(padsz - 2))
                file.write("\tuint8_t __end_guard;\n")
            else:
                file.write("\tuint8_t __pad0[{}];\n".format(padsz))

            file.write("};\n\n")

            file.write("struct __cppobj {} {{\n".format(ih.name))
            file.write("\t{}_vtbl *__vftable /*VFT*/;\n".format(ih.name))
            file.write("\t{}_mbrs m;\n".format(ih.name))
            file.write("};\n\n")

        generate_structs_for_children(file, ih, 1)

# Delete any forward decls that already exist inside IDA
# All typedefs go first, so the moment we see a vtable we can be done
def fixup_header_file(file):
    newfile = open("{}/iOS/Scripts/structs_from_vtabs.h".format(str(Path.home())), "w")
    done_fixing = False

    for line in file:
        line.strip()

        if done_fixing:
            newfile.write(line)
            continue

        if "vtbl" in line:
            print("Done fixing up")
            done_fixing = True
            continue

        # We are on a line that fwd decls, test to see if it
        # already exists in IDA. If it does, we don't write
        # that line to the new file
        if "struct" in line:
            type = line[line.find("__cppobj")+9:len(line)-1]


    newfile.close()

def main():
    global til

    til = ida_typeinf.get_idati()

    capstone_init()
    unicorn_init()

    all_names = list(idautils.Names())

    # First, get inheritance tree for all classes
    # We do this in two passes:
    #   First pass: for each class, gather class name, parent class name,
    #               and superclass name, and connect them
    #   Second pass: for each inheritance hierarchy object, we check
    #                   if the parent pointer is None (signaling a top-level
    #                   class), and add that to the `ihs` list
    # We can do this whole thing by processing xrefs to OSMetaClass::OSMetaClass
    OSMetaClass_ctor = get_OSMetaClass_ctor()

    if OSMetaClass_ctor == 0:
        print("Could not find OSMetaClass::OSMetaClass")
        return

    print("Got OSMetaClass::OSMetaClass at {}".format(hex(OSMetaClass_ctor)))

    # key,value pairs of all inheritance hierarchy objects
    ih_dict = {}

    # only those inheritance hierarchy objects which represent
    # a top-level parent class (aka inheriting from OSObject)
    ihs = []

    xrefs = list(idautils.XrefsTo(OSMetaClass_ctor))

    num = 0

    for xref in xrefs:
        frm = xref.frm
        # test
        # frm = 0x63920
        # print("xref from {}".format(hex(frm)))
        args = get_OSMetaClass_ctor_args(frm)

        pname = args[0]
        cname = args[1]

        if cname == "OSMetaClassBase":
            print("xref from {}".format(hex(frm)))
            print(args)

        if pname == cname:
            continue

        csz = args[2]

        # if pname == "AUAUnitDictionary" and cname == "AUAMixerUnitDictionary":
        #     print(args)
            # return

        new_parent = pname is not None and pname not in ih_dict
        new_child = cname not in ih_dict

        if new_parent:
            ih_dict[pname] = InheritanceHierarchy(None, pname, csz, csz)

        if new_child:
            ih_dict[cname] = InheritanceHierarchy(None, cname, csz)
        else:
            # Update class size for only child classes
            ih_dict[cname].sz = csz

        if pname == None:
            # If this class has no superclass, it must be parent class,
            # so make its InheritanceHierarchy object
            ih_dict[cname] = InheritanceHierarchy(None, cname, csz)
        else:
            child_ih = ih_dict[cname]
            parent_ih = ih_dict[pname]
            parent_ih.add_child(child_ih)
            child_ih.parent = parent_ih
            child_ih.totsz = child_ih.sz + parent_ih.totsz

        # if cname == "AUAUnitDictionary":
        #     print("AUAUnitDictionary sz: {}".format(ih_dict[pname].sz))
        #     print(args)
        #     return
        # if cname == "AUAMixerUnitDictionary":
        #     print("AUAMixerUnitDictionary sz: {}".format(ih_dict[cname].sz))
        #     print(args)
        #     return


        num += 1
        # if num == 10:
        #     break

    print("First pass: {} classes processed".format(num))
    num = 0

    # Second pass
    for ih in ih_dict.values():
        if ih.parent == None:
            # print("Adding {} to the ihs list".format(ih.name))
            num += 1
            ihs.append(ih)

    print("Second pass: {} classes added to ihs list".format(num))
    num = 0

    wants_class_hierarchy = ida_kernwin.ask_yn(0, "Dump class hierarchy?")

    if wants_class_hierarchy:
        hierch_file = open("{}/iOS/Scripts/iokit_hier.txt".format(str(Path.home())), "w")
        for ih in ihs:
            dump_hierarchy_to_file(hierch_file, ih, 0)
        print("File written to {}".format(hierch_file.name))
        hierch_file.close()
        return

    vtables = []

    for cur_name in all_names:
        ea = cur_name[0]
        name = cur_name[1]

        if "ZTV" in name:
            vtables.append(cur_name)

    struct_file = open("{}/iOS/Scripts/structs_from_vtabs.h".format(str(Path.home())), "w")

    is_standalone_kext = ida_kernwin.ask_yn(0, "Standalone kext?")

    if is_standalone_kext:
        # If this is from a standalone kext, I need to write some
        # definitions for common objects that follow my struct format,
        # otherwise, things get really screwed
        struct_file.write(
                "struct __cppobj ExpansionData {};\n\n"
                "struct __cppobj OSMetaClassBase_vtbl;\n\n"
                "struct __cppobj OSMetaClassBase_mbrs {};\n\n"
                "struct __cppobj OSMetaClassBase {\n"
                "\tOSMetaClassBase_vtbl *__vftable /*VFT*/;\n"
                "\tOSMetaClassBase_mbrs m;\n"
                "};\n\n"
                "struct __cppobj OSObject_mbrs : OSMetaClassBase_mbrs {\n"
                "\tint retainCount;\n"
                "};\n\n"
                "struct __cppobj OSObject_vtbl : OSMetaClassBase_vtbl {};\n\n"
                "struct __cppobj OSObject {\n"
                "\tOSObject_vtbl *__vftable;\n"
                "\tOSObject_mbrs m;\n"
                "};\n\n"
                "struct __cppobj OSMetaClass_mbrs : OSMetaClassBase_mbrs {\n"
                "\tExpansionData *reserved;\n"
                "\tconst OSMetaClass *superClassLink;\n"
                "\tconst OSSymbol *className;\n"
                "\tunsigned int classSize;\n"
                "\tunsigned int instanceCount;\n"
                "};\n\n"
                "struct __cppobj OSMetaClass {\n"
                "\tOSMetaClassBase_vtbl *__vftable;\n"
                "\tOSMetaClass_mbrs m;\n"
                "};\n\n"
                "struct __cppobj OSCollection_vtbl;\n"
                "struct __cppobj OSCollection_mbrs : OSObject_mbrs {\n"
                "\tunsigned int updateStamp;\n"
                "\tunsigned int fOptions;\n"
                "};\n\n"
                "struct __cppobj OSCollection {\n"
                "\tOSCollection_vtbl *__vftable;\n"
                "\tOSCollection_mbrs m;\n"
                "};\n\n"
                "struct __cppobj OSArray_vtbl;\n"
                "struct __cppobj OSArray_mbrs : OSCollection_mbrs {\n"
                "\tunsigned int count;\n"
                "\tunsigned int capacity;\n"
                "\tunsigned int capacityIncrement;\n"
                "\tvoid *array;\n"
                "};\n\n"
                "struct __cppobj OSArray {\n"
                "\tOSArray_vtbl *__vftable;\n"
                "\tOSArray_mbrs m;\n"
                "};\n\n"
                "struct __cppobj OSDictionary::dictEntry {\n"
                "\tconst OSSymbol *key;\n"
                "\tconst OSMetaClassBase *value;\n"
                "};\n\n"
                "struct __cppobj OSDictionary_vtbl;\n"
                "struct __cppobj OSDictionary_mbrs : OSCollection_mbrs {\n"
                "\tunsigned int count;\n"
                "\tunsigned int capacity;\n"
                "\tunsigned int capacityIncrement;\n"
                "\tOSDictionary::dictEntry *dict;\n"
                "};\n\n"
                "struct __cppobj OSDictionary {\n"
                "\tOSDictionary_vtbl *__vftable;\n"
                "\tOSDictionary_mbrs m;\n"
                "};\n\n"
                "struct __cppobj OSSet_vtbl;\n"
                "struct __cppobj OSSet_mbrs : OSCollection_mbrs {\n"
                "\tOSArray *members;\n"
                "};\n\n"
                "struct __cppobj OSSet {\n"
                "\tOSSet_vtbl *__vftable;\n"
                "\tOSSet_mbrs m;\n"
                "};\n\n"
                "struct __cppobj OSString_mbrs : OSObject_mbrs {\n"
                "\tunsigned __int32 flags : 14;\n"
                "\tunsigned __int32 length : 18;\n"
                "\tchar *string;\n"
                "};\n\n"
                "struct __cppobj OSString {\n"
                "\tOSObject_vtbl *__vftable;\n"
                "\tOSString_mbrs m;\n"
                "};\n\n"
                "struct __cppobj OSSymbol : OSString {};\n\n"
                )
    

    num_failed_get_type = 0
    cnt = 0

    for vtable in vtables:
        demangled_name = idc.demangle_name(vtable[1], get_inf_attr(idc.INF_LONG_DN))

        # unless this is a vtable for OSMetaClassBase, OSMetaClassMeta,
        # or OSMetaClass, skip anything metaclass related
        if "::MetaClass" in demangled_name:
            continue

        class_name = ida_name.extract_name(demangled_name, len("`vtable for'"))

        if class_name in BLACKLIST:
            continue

        ea = vtable[0]#+ 8;

        while ida_bytes.get_qword(ea) == 0:
            ea += 8

        # print("EA: {}".format(hex(ea)))
        if is_unknown(ida_bytes.get_flags(ea)):
            continue


        # if class_name != "IOSkywalkPacket":
        #     continue
        # if class_name != "AHTHSBufferStatic":
        #     continue
        # if class_name != "HSMSPITest":
        #     continue
        # if class_name != "AppleMesa":
        #     continue
        # if class_name != "AppleUSBHostController":
        #     continue
        # if class_name != "AppleEmbeddedPCIE":
        #     continue
        # if class_name != "SimpleEval":
        #     continue
        # if class_name != "AppleUSBCDCControl":
        #     continue
        # if class_name != "IOHDCP2TransmitterAuthSession":
        #     continue
        # if class_name != "IOAVService::DisplayIDParser::readDisplayID":
        #     continue
        # if class_name != "IOMFB::TypedProp":
        #     continue
        # if class_name != "IOMFB::UPBlock_GenPipe_v2":
        #     continue
        # if class_name != "AppleMesaSEPDriver":
        #     continue
        # if class_name != "IOAVController":
        #     continue
        # if class_name != "AppleConvergedIPCICEBBBTIInterface":
        #     continue
        # if class_name != "ApplePPM":
        #     continue


        cnt += 1

        # print("{}".format(class_name))

        # skip NULL pointers until we hit a function
        while ida_bytes.get_qword(ea) == 0:
            ea += 8

        num_virts = 0
        num_dtors = 0
        num_untyped = 0
        num_noname = 0

        fxn_name_list = []
        fxn_name_dict = {}

        struct_fields = []

        fwd_decls = set()
        fwd_decls.add(class_name)

        svt = SymbolicatedVtable(class_name)
        ioc = IOKitClass(svt)
        ioc.svt = svt

        # vtables seem to be NULL terminated
        while True:
            fxn_ea = ida_bytes.get_qword(ea)

            # end of vtable for this class
            if fxn_ea == 0:
                break

            # print("Type for {}/{} @ {}: {}".format(hex(fxn_ea), fxn_name, hex(ea), fxn_type))

            # if fxn_type == None:
            #     num_failed_get_type += 1
            #     ea += 8
            #     continue

            # default to this for ___cxa_pure_virtual
            fxn_args = "void"
            fxn_call_conv = ""
            fxn_mangled_name = ida_name.get_ea_name(fxn_ea)
            fxn_name = ida_name.demangle_name(fxn_mangled_name, get_inf_attr(idc.INF_LONG_DN))

            if fxn_name == None:
                # ___cxa_pure_virtual
                fxn_name = ida_name.get_ea_name(fxn_ea)

                # some other thing?
                if len(fxn_name) == 0:
                    fxn_name = "noname{}".format(num_noname)
            else:
                fxn_type = idc.get_type(fxn_ea)

                if fxn_type == None:
                    # sometimes this happens, don't know why
                    # the only thing fxn_type would have provided was
                    # the calling convention, so we need to manually
                    # reconstruct parameter list, and assume calling
                    # convention is __fastcall

                    # if mangled_fxn_name == "__ZN25IOGeneralMemoryDescriptor7doUnmapEP7_vm_mapyy":
                    #     exit(0)
                    fxn_return_type = "__int64"
                    fxn_call_conv = "__fastcall"

                    fxn_args_string = fxn_name[fxn_name.find("(")+1:fxn_name.rfind(")")]

                    # if fxn_args_string == "IOService *, unsigned int, void *, void (*)(OSObject *, AppleUSBCDCControl*, void *, USBCDCNotification *)":
                    #     # print("Hello")
                    #     fxn_args_string = "IOService *, unsigned int, void *, void (*)(OSObject *, void (*)(TestType *, AppleUSBCDCControl*, void *, USBCDCNotification *), AppleUSBCDCControl*, void *, USBCDCNotification *)"

                    # print("fxn args: {}".format(fxn_args_string))


                    # if fxn_args_string == "OSObject *, void (*)(OSObject *, IOHDCPAuthSession *), IOHDCPMessageTransport *, IOHDCPInterface *":
                    #     fxn_args_string = "OSObject *, void (*)(OSObject *, IOHDCPAuthSession *), IOHDCPMessageTransport *, IOHDCPInterface *, unsigned long long"
                    
                    fxn_args_string = fxn_args_string.replace("{block_pointer}", "*")

                    if fxn_args_string.find(",") != -1:
                        # print("More than one arg: {}".format(fxn_args_list))

                        # extra comma makes the parser happy
                        fxn_args_types_list = get_arg_type_list(fxn_args_string + ",")
                        
                        # print("More than one arg for {}: {}".format(fxn_name, fxn_args_types_list))
                        # print()

                        fxn_args = ""
                        argnum = 0

                        # print(type(fxn_args_types_list))
                        to_fwd_decl = get_fwd_decls(fxn_args_types_list)

                        if len(to_fwd_decl) > 0:
                            fwd_decls.update(to_fwd_decl)

                        for arg_type in fxn_args_types_list:
                            if argnum == 0:
                                fxn_args += "{} *__hidden this, ".format(class_name)
                            else:
                                fxn_args += "{}, ".format(fix_type(arg_type))

                            argnum += 1

                        fxn_args = fxn_args[:-2]
                    else:
                        fxn_args = "{} *__hidden this".format(class_name)

                        arg_type = fxn_name[fxn_name.find("(")+1:fxn_name.rfind(")")]

                        # print("Only one arg for {}: {}".format(fxn_name, arg_type))
                        arg_type_list = [arg_type]
                        # print("Only one arg: {}".format(arg_type_list))
                        to_fwd_decl = get_fwd_decls(arg_type_list)

                        if len(to_fwd_decl) > 0:
                            fwd_decls.update(to_fwd_decl)

                        if arg_type != "void" and len(arg_type) > 0:
                            fxn_args += ", {}".format(fix_type(arg_type))
                else:
                    all_except_args = fxn_type[:fxn_type.find("(")]

                    # first, if there's no spaces, there's no calling
                    # convention specifed
                    if all_except_args.find(" ") == -1:
                        fxn_return_type = all_except_args
                        
                        # Also, this having no spaces could mean IDA messed
                        # up, so we should use the demangled name instead
                        # and parse that
                        fxn_type = "(" + fxn_name[fxn_name.find("(")+1:]
                        # print("No spaces in args, using {} as fxn_type".format(fxn_type))
                    else:           
                        double_underscore = all_except_args.rfind("__")

                        if double_underscore != -1:
                            fxn_return_type = all_except_args[:double_underscore]
                            fxn_call_conv = all_except_args[double_underscore:]
                        else:
                            fxn_return_type = all_except_args

                    # get args
                    # print("fxn_type: {}".format(fxn_type))
                    fxn_args = fxn_type[fxn_type.find("(")+1:fxn_type.rfind(")")]
                    fxn_args_type_list = get_arg_type_list(fxn_args + ",")
                    fixed_fxn_args_type_list = []

                    # Fix up args
                    for arg_type in fxn_args_type_list:
                        # Remove __hidden
                        arg_type = arg_type.replace("__hidden", "")

                        # Check for a pointer. This is an easy case, we
                        # just delete everything from the first *
                        star = arg_type.find("*")
                        
                        if star != -1:
                            arg_type = arg_type[0:star]
                        else:
                            # Otherwise, find the last space, and delete
                            # from there
                            # But in case there was no name for this
                            # parameter, check if the token after the last
                            # space is not an IDA type or primitive type
                            lspace = arg_type.rfind(" ")

                            if lspace != -1:
                                token = arg_type[lspace:].replace(" ", "")

                                if not is_primitive_type(token) and not is_ida_type(token):
                                    arg_type = arg_type[0:lspace]

                        # print("arg_type: {}".format(arg_type))
                        
                        fixed_fxn_args_type_list.append(arg_type)

                    # to_fwd_decl = get_fwd_decls(fxn_args_type_list)
                    to_fwd_decl = get_fwd_decls(fixed_fxn_args_type_list)

                    if len(to_fwd_decl) > 0:
                        fwd_decls.update(to_fwd_decl)

                    # print("fxn_type is not None for {}: fxn args: {}".format(fxn_name, fxn_args_type_list))
                    # print("fxn_type is not None: will fwd declare: {}".format(to_fwd_decl))

                # get function name
                # remove 'classname::' and params
                fxn_name = fxn_name[fxn_name.find("::")+2:fxn_name.find("(")+1]
                fxn_name = fxn_name[:fxn_name.find("(")]
                # replace any '~'
                fxn_name = fxn_name.replace("~", "DTOR{}_".format(num_dtors))
                # remove any < and >
                fxn_name = fxn_name.replace("<", "")
                fxn_name = fxn_name.replace(">", "")

                if fxn_name in list(fxn_name_dict.keys()):
                    fxn_name_dict[fxn_name] += 1
                    fxn_name += "_{}".format(fxn_name_dict[fxn_name])
                else:
                    fxn_name_dict[fxn_name] = -1

                if "DTOR" in fxn_name:
                    num_dtors += 1

            curfield = ""

            if fxn_name == "___cxa_pure_virtual":
                # struct_fields.append("\tvoid __noreturn (__cdecl *___cxa_pure_virtual{})({});".format(num_virts,
                #     fxn_args))
                curfield = "\tvoid __noreturn (__cdecl *___cxa_pure_virtual{})({});".format(num_virts, fxn_args)
                num_virts += 1
            else:
                # struct_fields.append("\t{} ({} *{})({});".format(fxn_return_type,
                #     fxn_call_conv, fxn_name, fxn_args))
                curfield = "\t{} ({} *{})({});".format(fxn_return_type,
                        fxn_call_conv, fxn_name, fxn_args)

            svt.add(curfield)

            ea += 8

        # return
        # Some classes won't have xrefs to OSMetaClass::OSMetaClass,
        # like OSMetaClassBase
        if class_name in ih_dict:
            ih_dict[class_name].ioc = ioc

        # Just write forward decls for now
        for decl in fwd_decls:
            struct_file.write("struct __cppobj {};\n".format(decl))

        struct_file.write("\n")

        # cnt += 1

        # if cnt == 5:
        #     break

    print("{} IOKit vtables".format(len(vtables)))

    # Now create the header file to import into IDA
    # for ih in ihs:
    #     dump_ih(ih, 0)

    generate_header_file(struct_file, ihs)
    # fixup_header_file(struct_file)

    struct_file.close()

main()
