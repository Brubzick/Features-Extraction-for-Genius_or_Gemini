from radare2_utils import R2Helper
from cfg_constructor import get_cfg
from discovRe import get_discoverRe_feature
from raw_graphs import *
from graph_analysis import *
import os

filePath = 'busybox-mips'
fileName = os.path.basename(filePath)

ins = R2Helper(filePath)

res = ins.calc_cfg_info()

# for func in res:
#     print(func['func_name'])
#     for one in func['pdf']['ops']:
#         print(one['offset'],one['disasm'])
#     print('')
    # cfg = get_cfg(func)
    # f = get_discoverRe_feature(func,cfg)
    # print(func['func_name'], f)

raw_cfgs = raw_graphs(fileName)
