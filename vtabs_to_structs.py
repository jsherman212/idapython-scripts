# meant to be used on a fully-symbolized iOS kernelcache

import idaapi
import ida_bytes
import ida_kernwin
import ida_name
import idautils
import idc

from pathlib import Path

all_names = list(idautils.Names())
vtables = []

for cur_name in all_names:
    ea = cur_name[0]
    name = cur_name[1]

    if "ZTV" in name:
        #vtables.append({ea, idc.demangle_name(name, get_inf_attr(idc.INF_LONG_DN))})
        vtables.append(cur_name)
        #print("{}: {}".format(hex(ea), name))

struct_file = open("{}/iOS/Scripts/structs_from_vtabs.h".format(str(Path.home())), "w")

num_failed_get_type = 0

for vtable in vtables:
    ea = vtable[0] + 8;
    demangled_name = idc.demangle_name(vtable[1], get_inf_attr(idc.INF_LONG_DN))

    # unless this is a vtable for OSMetaClassBase, OSMetaClassMeta,
    # or OSMetaClass, skip anything metaclass related
    if "::MetaClass" in demangled_name:
        continue

    class_name = ida_name.extract_name(demangled_name, len("`vtable for'"))

    print("{}".format(class_name))

    # sym so I don't conflict with other imported types in my current database
    struct_file.write("struct {}_sym_vtable {{\n".format(class_name))

    # skip NULL pointers until we hit a function
    while ida_bytes.get_qword(ea) == 0:
        ea += 8

    num_virts = 0
    num_dtors = 0
    num_untyped = 0

    # vtables seem to be NULL terminated
    while True:
        fxn_ea = ida_bytes.get_qword(ea)

        # end of vtable for this class
        if fxn_ea == 0:
            break


        print("Type for {}/{} @ {}: {}".format(hex(fxn_ea), fxn_name, hex(ea), fxn_type))

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

                if fxn_name.find(",") != -1:
                    fxn_args_list = fxn_name.split(",")
                    fxn_args_list[0] = fxn_args_list[0][fxn_args_list[0].find("(")+1:]
                    fxn_args_list[len(fxn_args_list)-1] = fxn_args_list[len(fxn_args_list)-1][:-1]
                    fxn_args_list = [arg.replace(" ", "", 1) for arg in fxn_args_list]

                    fxn_args = ""
                    argnum = 0

                    for arg in fxn_args_list:
                        if argnum == 0:
                            fxn_args += "this, "
                        else:
                            fxn_args += "{}, ".format(arg)

                        argnum += 1

                    fxn_args = fxn_args[:-2]

                # if fxn_mangled_name == "__ZN25IOGeneralMemoryDescriptor7doUnmapEP7_vm_mapyy":
                #     print("Function: {}".format(fxn_name))
                #     exit(0)

                num_untyped += 1
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
            #fxn_name = fxn_name[fxn_name.rfind("::")+2:fxn_name.rfind("(")]
            fxn_name = fxn_name[fxn_name.find("::")+2:fxn_name.find("(")+1]
            # fxn_name = fxn_name[fxn_name.find("::"):]
            # remove params
            # fxn_name = fxn_name[:fxn_name.rfind("(")]
            fxn_name = fxn_name[:fxn_name.find("(")]
            # replace any '~'
            fxn_name = fxn_name.replace("~", "DTOR{}_".format(num_dtors))

            if "DTOR" in fxn_name:
                num_dtors += 1

            #print(get_type(fxn_ea).find("("))
            # print("Function return type: {}".format(fxn_return_type))
            # print("Function calling conv: {}".format(fxn_call_conv))
            # print("Function name: {}".format(fxn_name))
            # print("Function args: {}".format(fxn_args))

        if fxn_name == "___cxa_pure_virtual":
            struct_file.write("\tvoid __noreturn (__cdecl *___cxa_pure_virtual{})({});\n".format(num_virts, fxn_args))
            num_virts += 1
        else:
            struct_file.write("\t{} ({} *{})({});\n".format(fxn_return_type, fxn_call_conv, fxn_name, fxn_args))

        print()

        # if ea == 0xfffffff0079dcb50:
        #     struct_file.close()
        #     exit(0)

        # print("\t{}: {}".format(hex(ea), fxn_name))
        ea += 8

    #struct_file.write("\t__int64 vCallOffset;\n");
    # struct_file.write("\tchar pad0[0x1000];\n")
    struct_file.write("};\n\n")

    #break

# print("{} failed get_type's".format(num_failed_get_type))
print("{} IOKit vtables".format(len(vtables)))

struct_file.close()
