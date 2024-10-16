import sys
import os
curDir = os.path.dirname(__file__)
preDir = os.path.abspath(os.path.join(curDir, os.pardir))
sys.path.append(preDir)
from read_windbg import ConstructFuncs
from cfg_constructor_windbg import get_cfg_windbg
from discovRe_windbg import get_discoverRe_feature
from raw_graphs import *
from graph_analysis_windbg import *

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
