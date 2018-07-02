import idaapi
import idc
import idautils

print '[*]begin to find...'

rodata_ea_start = 0
local_sections = Segments()
for section in local_sections:
    seg_name = SegName(section)
    if seg_name != '[anon:libc_malloc]':
        continue
		
    # 准备查找
    rodata_ea_start = section
    rodata_ea_end = SegEnd(rodata_ea_start)  
    print('\t[-]begin to search segment:%x' % rodata_ea_start)
    for ea_offset in range(rodata_ea_start, rodata_ea_end):
        cur_dword = idaapi.get_dword(ea_offset)
        if cur_dword != None and cur_dword == 0x1:
            print('found target addr=%x' % ea_offset)
       
print '[*]script by freakish, enjoy~~'       
print '[*]script finish'