
# dump memory from IDA Debugger
#

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
    hooks = idaapi.DBG_Hooks()
    hooks.hook()
          
    print '[*]script by freakish, enjoy~~'       
    print '[*]script finish'


ea_start = 0xE20
ea_size = 0x7000

ea_end = ea_start + ea_size
save_file = 'd:/text.so'

main(ea_start, ea_end, save_file)