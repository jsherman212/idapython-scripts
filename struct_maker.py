import idaapi
import ida_kernwin
import idc

struct_name = ida_kernwin.ask_str("", 4, "Enter struct name")
start = ida_kernwin.ask_addr(0, "Enter start address")
num_structs = ida_kernwin.ask_long(0, "Enter struct count")
should_number = ida_kernwin.ask_yn(0, "Number the structs as they're created?")

cur_struct_num = 0

struct_id = idaapi.get_struc_id(struct_name)

if struct_id == -1:
    exit("No such struct {}".format(struct_name))

struct_size = idaapi.get_struc_size(struct_id)

cur = start

for i in range(num_structs):
    create_struct(cur, struct_size, struct_name)

    if should_number:
        set_cmt(cur, str(cur_struct_num), 0)
        cur_struct_num += 1

    cur += struct_size
