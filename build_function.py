import idc
import idautils
import idaapi
import ida_bytes
import ida_funcs

def is_function(ea):
    f = idaapi.get_func(ea)
    if not f:
        return False
    return True

def is_rel_unconditional_jmp(ea):
    return idc.GetDisasm(ea).startswith("jmp") and idc.get_operand_type(ea, 0) == idc.o_near

def is_rel_conditional_jmp(ea):
    disasm = idc.GetDisasm(ea)
    return disasm.startswith("j") and (not disasm.startswith("jmp")) and (idc.get_operand_type(ea, 0) == idc.o_near)

def get_rel_jmp_dest(ea):
    return idc.get_operand_value(ea, 0)

def ensure_code(ea):
    if idc.is_code(ida_bytes.get_full_flags(ea)):
        return idautils.DecodeInstruction(ea).size

    ida_bytes.del_items(ea, 0, 8)
        
    if not ida_bytes.create_data(ea, idc.FF_QWORD, 8, idc.BADADDR):
        return 0
    
    ida_bytes.del_items(ea, 0, 8)
    return idc.create_insn(ea)

def ensure_code_block(ea):
    size = 0
    while True:
        insn_size = ensure_code(ea)
        if insn_size == 0:
            print("[ensure_code_block] Error: insn_size is 0, total block size is {}".format(size))
            return 0
        size += insn_size
        
        disasm = idc.GetDisasm(ea)
        if disasm.startswith("jmp"):
            print("[ensure_code_block] Encountered jmp")
            break
        if disasm.startswith("ret"):
            print("[ensure_code_block] Encountered ret*")
            break
        ea += insn_size
    return size
        
def repair_block(fea, ea, visited):
    if not ensure_code_block(ea):
        print("[repair_block] ensure_code_block failed: {:X}".format(ea))
        return

    chunk_end = ea + ensure_code_block(ea)
    if chunk_end == ea:
        print("[repair_block] Error processing chunk: chunk_end is chunk_start")
        return False
    
    print("[repair_block] chunk: ({:X}->{:X}) size({})".format(ea, chunk_end, chunk_end - ea))
    
    func = idaapi.get_func(ea)
    if func and (func.start_ea != fea):
        ida_funcs.del_func(func.start_ea)
        idc.auto_wait()
        
    while True:
        if ea in visited:
            return
        visited.append(ea)

        if is_rel_conditional_jmp(ea):
            repair_block(fea, get_rel_jmp_dest(ea), visited)
        elif is_rel_unconditional_jmp(ea):
            repair_block(fea, get_rel_jmp_dest(ea), visited)
            return

        if idautils.DecodeInstruction(ea).itype in [idaapi.NN_retn]:
            print("[repair_block] Encountered return: {:X}".format(ea))
            return
        ea = idc.next_head(ea)
    idc.auto_wait()

def build_function(fea, visited):
    if is_function(fea):
        ida_funcs.del_func(idaapi.get_func(fea).start_ea)
        
    if not ensure_code(fea):
        print("[build_function] Failed to ensure code: {:X}".format(fea))
        return False
    
    repair_block(fea, fea, visited)
    return ida_funcs.add_func(fea)
