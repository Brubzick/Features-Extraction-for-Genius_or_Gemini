from radare2_utils import R2Helper
from cfg_constructor import get_cfg
from discovRe import get_discoverRe_feature
from raw_graphs import *
from graph_analysis import *

def get_func_cfgs_c(filePath, fileName):

    ins = R2Helper(filePath)

    res = ins.calc_cfg_info()

    raw_cfgs = raw_graphs(fileName)

    for func in res:
        func_name = func['func_name']
        cfg = get_cfg(func)
        func_f = get_discoverRe_feature(func, cfg)
        raw_g = raw_graph(func_name, cfg, func_f)
        raw_cfgs.append(raw_g)

    return raw_cfgs

