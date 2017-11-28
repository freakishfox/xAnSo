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
    # search for string "DT_INIT"
    
    print '\t[-]begin to search DT_INIT'
    string_dt_init_ea = 0
    for ea_offset in range(rodata_ea_start, rodata_ea_end):
        cur_string = GetString(ea_offset)
        if cur_string != None and cur_string == 'DT_INIT':
            string_dt_init_ea = ea_offset
            break
    
    print '\t[-]found string DT_INIT 0x%08X' % string_dt_init_ea
    
    # xref to DT_INIT...
    refs = XrefsTo(string_dt_init_ea)
    useful_ref = 0
    for ref in refs:
        useful_ref = ref.frm
        break
    
    print '\t[-]try set breakpoint there=>DT_INIT'
    AddBpt(useful_ref)
    
    # xref to DT_INIT_ARRAY
    string_dt_init_array_ea = 0
    for ea_offset in range(rodata_ea_start, rodata_ea_end):
        cur_string = GetString(ea_offset)
        if cur_string != None and cur_string == 'DT_INIT_ARRAY':
            string_dt_init_array_ea = ea_offset
            break
    
    print '\t[-]found string DT_INIT_ARRAY 0x%08X' % string_dt_init_array_ea
    
    # xref to DT_INIT_ARRAY...
    refs = XrefsTo(string_dt_init_array_ea)
    useful_ref = 0
    for ref in refs:
        useful_ref = ref.frm
        break
    
    print '\t[-]try set breakpoint there=>DT_INIT_ARRAY'
    AddBpt(useful_ref)
    
    # xref to DT_PREINIT_ARRAY
    string_dt_pre_init_array_ea = 0
    for ea_offset in range(rodata_ea_start, rodata_ea_end):
        cur_string = GetString(ea_offset)
        if cur_string != None and cur_string == 'DT_PREINIT_ARRAY':
            string_dt_pre_init_array_ea = ea_offset
            break
    
    print '\t[-]found string DT_PREINIT_ARRAY 0x%08X' % string_dt_pre_init_array_ea
    
    # xref to DT_PREINIT_ARRAY...
    refs = XrefsTo(string_dt_pre_init_array_ea)
    useful_ref = 0
    for ref in refs:
        useful_ref = ref.frm
        break
    
    print '\t[-]try set breakpoint there=>DT_PREINIT_ARRAY'
    AddBpt(useful_ref)
          
    print '[*]script by freakish, enjoy~~'       
    print '[*]script finish'
    
main()