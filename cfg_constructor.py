import networkx as nx
from graph_analysis import *

def get_cfg(func):
    cfg = nx.DiGraph()
    addr2node_id = {}
    opcodeIndex = 0
    for bb in func['bb_addr_list']:
        node_id = len(cfg)
        cfg.add_node(node_id)
        addr2node_id[bb[0]] = node_id
        ops = func['pdf']['ops']
        block = []
        for addr in bb[1]:
            if addr == ops[opcodeIndex]['offset']:
                block.append(ops[opcodeIndex]['disasm'])
            opcodeIndex += 1
        cfg.nodes[node_id]['addr'] = bb[0]
        cfg.nodes[node_id]['ins_addr_list'] = bb[1]
        cfg.nodes[node_id]['label'] = block
        cfg.nodes[node_id]['suc'] = []
        cfg.nodes[node_id]['pre'] = []

    for edge in func['edges']:
        node1 = addr2node_id[edge[0]]
        node2 = addr2node_id[edge[1]]
        cfg.add_edge(node1, node2)
        cfg.nodes[node1]['suc'].append(node2)
        cfg.nodes[node2]['pre'].append(node1)
    
    cfg = attributingRe(cfg)

    return cfg
        

def attributingRe(cfg):  # 为每个基本块生成自定义的属性
    for node_id in cfg:
        bl = cfg.nodes[node_id]['label']
        numIns = calInsts(bl)  # No. of Instruction
        cfg.nodes[node_id]['numIns'] = numIns
        numCalls = calCalls(bl)  # No. of Calls
        cfg.nodes[node_id]['numCalls'] = numCalls
        numLIs = calLogicInstructions(bl)  # 这个不再Genius的范围内
        cfg.nodes[node_id]['numLIs'] = numLIs
        numAs = calArithmeticIns(bl)  # No. of Arithmetic Instructions
        cfg.nodes[node_id]['numAs'] = numAs
        strings, consts = getBBconsts(bl)  # String and numeric constants
        cfg.nodes[node_id]['numNc'] = len(strings) + len(consts)
        cfg.nodes[node_id]['consts'] = consts
        cfg.nodes[node_id]['strings'] = strings
        externs = retrieveExterns(bl, ea_externs)
        cfg.nodes[node_id]['externs'] = externs
        numTIs = calTransferIns(bl)  # No. of Transfer Instruction
        cfg.nodes[node_id]['numTIs'] = numTIs
    return cfg