from read_windbg import ConstructFuncs
from cfg_constructor_windbg import get_cfg_windbg
from discovRe_windbg import get_discoverRe_feature
from raw_graphs import *

def get_func_cfgs_windbg(filePath, fileName):

    funcs = ConstructFuncs(filePath)

    raw_cfgs = raw_graphs(fileName)

    for func in funcs:
        func_name = func['funcname']
        cfg = get_cfg_windbg(func)
        func_f = get_discoverRe_feature(func, cfg)
        raw_g = raw_graph(func_name, cfg, func_f)
        raw_cfgs.append(raw_g)

    return raw_cfgs
