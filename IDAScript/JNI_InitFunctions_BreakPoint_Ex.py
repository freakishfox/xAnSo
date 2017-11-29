import idautils
import idc
import idaapi

#linker call init and init_array functions
#.text:000026DE 20 46                          MOV             R0, R4
#.text:000026E0 D4 F8 F0 20                    LDR.W           R2, [R4,#0xF0]
#.text:000026E4 79 44                          ADD             R1, PC  ; "DT_INIT"
#.text:000026E6 FF F7 A9 FE                    BL              __dl__ZN6soinfo13call_functionEPKcPFvvE
#.text:000026EA 0D 49                          LDR             R1, =(aDt_init_array - 0x26F6)
#.text:000026EC 00 22                          MOVS            R2, #0
#.text:000026EE 00 92                          STR             R2, [SP,#0x18+var_18]


#linker call pre_init_array, but in shared library like android so, pre_init_array will not be called

def main():
    # begin to locate linker module base
    
    has_art = False
    module_base = GetFirstModule()
    while module_base != None:
        module_name = GetModuleName(module_base)
        if module_name.find('linker') >= 0:
            has_art = True
            break
        
        module_base = GetNextModule(module_base)
    
    if has_art == False:
        print '[*]unable to find libart.so module base'
        return
    
    module_size = GetModuleSize(module_base)
    print '[*]found linker base=>0x%08X, Size=0x%08X' % (module_base, module_size)
    
    
    print("\t[-]begin to search DT_INIT And DT_INIT_ARRAY")
    init_func_ea = 0
    init_array_ea = 0
    for ea_offset in range(module_base, module_base + module_size):
        # i don't want to write a huge single line like 'if x and x and x and...', so many ifs apear
        
        if 0x4620 == idaapi.get_word(ea_offset):
            if 0x20F0F8D4 == idaapi.get_long(ea_offset + 2):
                if 0x4479 == idaapi.get_word(ea_offset + 6):
                    if 0xFEA9F7FF == idaapi.get_word(ea_offset + 8):
                        if 0x490D == idaapi.get_word(ea_offset + 12):
                            if 0x2200 == idaapi.get_long(ea_offset + 14):
                                if 0x9200 == idaapi.get_word(ea_offset + 16):
                                    init_func_ea = ea_offset + 8
                                    init_array_ea = ea_offset + 30
                                    break
    
    print "\t[-]found INIT=>0x%08X INIT_ARRAY=>0x%08X" % (init_func_ea, init_array_ea)
    print("\t[-]try set breakpoint there")
    AddBpt(init_func_ea)
    AddBpt(init_array_ea)
            
    print("[*]script by freakish, enjoy~~")    
    print("[*]script finish")
    
main()