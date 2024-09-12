from read_disasm import ReadDisasm
from cfg_constructor_disasm import get_cfg_disasm
from discovRe_disasm import get_discoverRe_feature
from raw_graphs import *
from graph_analysis_disasm import *

def get_func_cfgs_disasm(filePath, fileName, arch):

    res = ReadDisasm(filePath, arch)

    raw_cfgs = raw_graphs(fileName)

    for func in res:
        func_name = func['funcname']
        cfg = get_cfg_disasm(func, arch)
        func_f = get_discoverRe_feature(func, cfg, arch)
        raw_g = raw_graph(func_name, cfg, func_f)
        raw_cfgs.append(raw_g)

    return raw_cfgs
