from func_disasm import get_func_cfgs_disasm
from read_disasm import ReadDisasm
import os

filePath = './data/ftpserver_disassembly.txt'
fileName = os.path.basename(filePath)

# funcs = ReadDisasm(filePath, 'arm')

# for func in funcs:
#     if func['funcname'] == '__asan::InitializeAsanInterceptors':
#         print(func['funcname'])
#         index = 0
#         for block in func['blocks']:
#             for ins in block:
#                 print(func['bb_addr_list'][index], ins)
#                 index += 1
#             print('')
#         print(func['edges'])

cfgs = get_func_cfgs_disasm(filePath, fileName, 'arm')

for cfg in cfgs.raw_graph_list:
    if (len(cfg.old_g.nodes)==0):
        print(cfg.name)
    