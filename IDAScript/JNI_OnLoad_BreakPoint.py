import idautils
import idc
import idaapi


def main():    
    print '[*]begin to find .rodata segment'

    # locate to .rodata segment
    rodata_ea_start = 0
    local_sections = Segments()
    for section in local_sections:
        seg_name = SegName(section)
        if seg_name == '.rodata':
            rodata_ea_start = section
            break
            
    if rodata_ea_start == 0:
        print '\t[-]can not locate .rodata segment'
        return
    
    rodata_ea_end = SegEnd(rodata_ea_start)  
    # search for string "[Calling JNI_OnLoad in"
    
    print '\t[-]begin to search JNI_OnLoad'
    string_jni_on_load_ea = 0
    for ea_offset in range(rodata_ea_start, rodata_ea_end):
        cur_string = GetString(ea_offset)
        if cur_string != None and cur_string.find('[Calling JNI_OnLoad in')>=0:
            string_jni_on_load_ea = ea_offset
            break
    
    print '\t[-]found string JNI_OnLoad 0x%08X' % string_jni_on_load_ea
    
    # xref to JNI_OnLoad...
    refs = XrefsTo(string_jni_on_load_ea)
    useful_ref = 0
    for ref in refs:
        useful_ref = ref.frm
        break
    
    # locate call(fn_jni_on_load)
    target_address = 0
    
    func_items = FuncItems(useful_ref)
    for fun_addr in func_items:
        if fun_addr >= useful_ref:
            op_bytes = idaapi.get_word(fun_addr)
            
            # call to jni_onload  opcode = 0xE494
            if 0xE494 == op_bytes:
                # calc target address, Thumb-2 instruction, refer about B <target_address>
                target_address = (op_bytes & 0xFFF) << 1
                
                # extra the sign flag to 32bit wide
                if target_address & 0x800 == 0x800:
                    target_address = target_address | 0xFFFFF000
                
                # generate the real address
                target_address = (target_address + (fun_addr + 4)) & 0xFFFFFFFF
                print '\t[-]found jump address:0x%08X, follow it' % target_address
                break
            
    if target_address == 0:
        print '[*]no target address to follow, just return'
        return
        
    # relocate target_address func item
    func_items = FuncItems(target_address)
    
    # search BLX R12 instruction
    b_can_start_search = False
    for fun_addr in func_items:
        if fun_addr == target_address:
            b_can_start_search = True
            continue
        
        if b_can_start_search == True and 0x47E0 == idaapi.get_word(fun_addr):
            print '[*]found call JNI_OnLoad Statement, addr=>0x%08X' % fun_addr)
            print '\t[-]try set breakpoint there'
            AddBpt(fun_addr)
            
            print '[*]script by freakish, enjoy~~'
            
    print '[*]script finish'
    
main()