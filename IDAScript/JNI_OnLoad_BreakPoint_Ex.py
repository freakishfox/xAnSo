import idautils
import idc
import idaapi

#libart BLX R12, this statement call jni_onload
#libart.so:F4C80BA2 00 21          MOVS            R1, #0
#libart.so:F4C80BA4 30 46          MOV             R0, R6
#libart.so:F4C80BA6 E0 47          BLX             R12
#libart.so:F4C80BA8 71 68          LDR             R1, [R6,#4]
#libart.so:F4C80BAA 84 46          MOV             R12, R0
#libart.so:F4C80BAC D1 F8 CC 02    LDR.W           R0, [R1,#0x2CC]
#libart.so:F4C80BB0 03 1C          MOVS            R3, R0

def main():
    # begin to locate libart.so module base
    
    has_art = False
    module_base = GetFirstModule()
    while module_base != None:
        module_name = GetModuleName(module_base)
        if module_name.find('libart.so') >= 0:
            has_art = True
            break
        
        module_base = GetNextModule(module_base)
    
    if has_art == False:
        print '[*]unable to find libart.so module base'
        return
    
    module_size = GetModuleSize(module_base)
    print '[*]found libart.so base=>0x%08X, Size=0x%08X' % (module_base, module_size)
    
    
    print("\t[-]begin to search JNI_OnLoad")
    blx_r12_ea = 0
    for ea_offset in range(module_base, module_base + module_size):
        # i don't want to write a huge single line like 'if x and x and x and...', so many ifs apear
        
        if 0x2100 == idaapi.get_word(ea_offset):
            if 0x4630 == idaapi.get_word(ea_offset + 2):
                if 0x47E0 == idaapi.get_word(ea_offset + 4):
                    if 0x6871 == idaapi.get_word(ea_offset + 6):
                        if 0x4684 == idaapi.get_word(ea_offset + 8):
                            if 0x02CCF8D1 == idaapi.get_long(ea_offset + 10):
                                if 0x1C03 == idaapi.get_word(ea_offset + 14):
                                    blx_r12_ea = ea_offset + 4
                                    break
    
    print "\t[-]found string JNI_OnLoad BLX R12 addr=>0x%X" % blx_r12_ea
    print("\t[-]try set breakpoint there")
    AddBpt(blx_r12_ea)
            
    print("[*]script by freakish, enjoy~~")    
    print("[*]script finish")
    
main()