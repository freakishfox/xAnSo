
# 从IDA 中Dump指定段的内存
# freakishfox@敌法

import idautils
import idc
import idaapi
import struct


def main(ea_start, ea_end, save_file):    
    print '[*]begin to dump segment'
    
    handle_f = open(save_file, 'wb')
    for byte_addr in range(ea_start, ea_end):
        byte_value = idaapi.get_byte(byte_addr)
        handle_f.write(struct.pack('B',byte_value))
    
    handle_f.close()
          
    print '[*]script by freakish, enjoy~~'       
    print '[*]script finish'

# 在这里修改参数

ea_start = 0xE20
ea_end = 0x173C8
save_file = 'c:/text.seg'

main(ea_start, ea_end, save_file)