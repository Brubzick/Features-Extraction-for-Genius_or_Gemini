from func_ida import get_func_cfgs_ida
from func_windbg import get_func_cfgs_windbg
from raw_graphs import *

def isIDA(filePath):
    # 读取前20行，看开头判断是否是IDA的TSL文件
    with open(filePath, 'r', encoding='utf-8', errors='ignore') as f:
        i = 20
        line = f.readline()
        while i > 0 and line != '':
            if line[0] != '.':
                return False
            i -= 1
            line = f.readline()
        return True

def get_func_cfgs_disasm(filePath, fileName):
    isida = isIDA(filePath)
    if isida:
        print('ida disasm')
        return get_func_cfgs_ida(filePath, fileName)
    else:
        print('windbg disasm')
        return get_func_cfgs_windbg(filePath, fileName)
