# meant to be used on a fully-symbolized iOS kernelcache, then import the header
# to that symbolicated kcache, then generate header file from local types to
# import into another database

from idaapi import *
from pathlib import Path

import ida_bytes
import ida_kernwin
import ida_name
import idautils
import idc
import re

# important - order by length
c_keywords = ["volatile", "unsigned", "register", "struct", "static",
        "signed", "union", "const", "void", "enum", "auto"]
primitive_types = ["bool", "char", "short", "int", "long", "float", "double"]

def is_primitive_type(type_str):
    return type_str in primitive_types

def get_raw_type(type_str):
    raw_type = type_str

    # also, remove void pointers all-together
    # c_keywords = ["volatile", "unsigned", "register", "struct", "static",
    #         "signed", "union", "const", "void", "enum", "auto"]

    # print("Type string: {}".format(type_str))

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

    # print("Raw type: {}".format(raw_type))

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
    return is_primitive_type(raw_type_str) == False and len(raw_type_str) > 0

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

    # print("get_fwd_decls: {}, {}".format(arg_type_list, type(arg_type_list)))
    for arg_type in arg_type_list:
        # print("get_fwd_decls: current arg is {}".format(arg_type))
        raw_arg_type = get_raw_type(arg_type)

        # print("get_fwd_decls: raw type {}".format(raw_arg_type))

        if should_fwd_decl(raw_arg_type):
            # print(raw_arg_type)

            # check if we got a function pointer argument
            # in this case, we need to scan all its args and forward
            # declare those as needed
            if "," in raw_arg_type:
                # fxn_ptr_raw_arg_types = raw_arg_type.split(",")
                # remove C keywords and primitive types from the list of function
                # pointer arguments
                fxn_ptr_raw_arg_types = [raw_arg_type for raw_arg_type in raw_arg_type.split(",") if is_primitive_type(raw_arg_type) == False and raw_arg_type not in c_keywords]
                # print("get_fwd_decls: fxn_ptr_raw_arg_types: {}".format(fxn_ptr_raw_arg_types))
                for fxn_ptr_raw_arg_type in fxn_ptr_raw_arg_types:
                    if should_fwd_decl(fxn_ptr_raw_arg_type):
                        # print(fxn_ptr_raw_arg_type)
                        fwd_decls.append(fix_type(fxn_ptr_raw_arg_type))
            else:
                fwd_decls.append(fix_type(raw_arg_type))

        # primitive types don't need to be fwd declared
        # if is_primitive(raw_arg_type):
        #     continue

        # print(raw_arg_type)

    return fwd_decls

# really weird corner cases which I don't feel like dealing with
# and can be excluded without degrading the quality of the database
BLACKLIST = ["SimpleEval", "IOAVService::DisplayIDParser::readDisplayID",
        "IOAVService::DisplayIDParser::parseDisplayID",
        "IOMFB::TypedProp",
        "UPPipe_H10P_Trampoline::ActiveCallback",
        "UPPipe_H10P_Trampoline::EventCallback",
        "IOMFB::LateralLeakageHandler::CurveEvaluator"]

def main():
    all_names = list(idautils.Names())
    vtables = []

    for cur_name in all_names:
        ea = cur_name[0]
        name = cur_name[1]

        if "ZTV" in name:
            vtables.append(cur_name)

    struct_file = open("{}/iOS/Scripts/structs_from_vtabs.h".format(str(Path.home())), "w")

    num_failed_get_type = 0

    cnt = 0

    for vtable in vtables:
        ea = vtable[0] + 8;
        demangled_name = idc.demangle_name(vtable[1], get_inf_attr(idc.INF_LONG_DN))

        # unless this is a vtable for OSMetaClassBase, OSMetaClassMeta,
        # or OSMetaClass, skip anything metaclass related
        if "::MetaClass" in demangled_name:
            continue

        class_name = ida_name.extract_name(demangled_name, len("`vtable for'"))

        if class_name in BLACKLIST:
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

        #make_vtable_struct(struct_file, vtable, class_name)

        cnt += 1

        # if cnt == 5:
        #     break


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
                    else:           
                        double_underscore = all_except_args.rfind("__")

                        if double_underscore != -1:
                            fxn_return_type = all_except_args[:double_underscore]
                            fxn_call_conv = all_except_args[double_underscore:]
                        else:
                            fxn_return_type = all_except_args

                    # get args
                    fxn_args = fxn_type[fxn_type.find("(")+1:fxn_type.rfind(")")]

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

            if fxn_name == "___cxa_pure_virtual":
                struct_fields.append("\tvoid __noreturn (__cdecl *___cxa_pure_virtual{})({});".format(num_virts,
                    fxn_args))
                num_virts += 1
            else:
                struct_fields.append("\t{} ({} *{})({});".format(fxn_return_type,
                    fxn_call_conv, fxn_name, fxn_args))

            ea += 8

        for decl in fwd_decls:
            struct_file.write("struct {};\n".format(decl))

        struct_file.write("\n")

        # sym so I don't conflict with other structs in my current database
        # change to 'vtable' when I make a new database
        struct_file.write("struct {}_sym_vtable {{\n".format(class_name))

        for field in struct_fields:
            struct_file.write("\t{}\n".format(field));

        struct_file.write("};\n\n")
        
        if "::" in class_name:
            struct_file.write("struct {}::fields {{\n".format(class_name))
        else:
            struct_file.write("struct {}_fields {{\n".format(class_name))

        struct_file.write("\tuint8_t pad[0x3000];\n")
        struct_file.write("};\n\n")
        struct_file.write("struct {} {{\n".format(class_name))
        struct_file.write("\tstruct {}_sym_vtable *vt;\n".format(class_name))

        if "::" in class_name:
            struct_file.write("\tstruct fields f0;\n")
        else:
            struct_file.write("\tstruct {}_fields f0;\n".format(class_name))

        struct_file.write("};\n\n")

        cnt += 1

        # if cnt == 5:
        #     break

        # break



    print("{} IOKit vtables".format(len(vtables)))
    struct_file.close()
    # print("{} failed get_type's".format(num_failed_get_type))

main()
