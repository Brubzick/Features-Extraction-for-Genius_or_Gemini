import networkx as nx
from graph_analysis import *
import sys

def get_cfg(func, arch):
    cfg = nx.DiGraph()
    addr2node_id = {}
    # opcodeIndex = 0
    ops = func['pdf']['ops']
    offset2ops = {}
    for one in ops:
        offset2ops[one['offset']] = one
    for bb in func['bb_addr_list']:
        node_id = len(cfg)
        cfg.add_node(node_id)
        addr2node_id[bb[0]] = node_id
        
        block = []
        opcode = []
        for addr in bb[1]:
            if addr in offset2ops:
                block.append(offset2ops[addr]['disasm'])
                opcode.append(offset2ops[addr]['opcode'])
        # for addr in bb[1]:
        #     if addr == ops[opcodeIndex]['offset']:
        #         block.append(ops[opcodeIndex]['disasm'])
        #         opcode.append(ops[opcodeIndex]['opcode'])
        #     else:
        #         print(opcodeIndex)
        #         print(bb[1])
        #         sys.exit(0)
        #     opcodeIndex += 1

        cfg.nodes[node_id]['addr'] = bb[0]
        cfg.nodes[node_id]['ins_addr_list'] = bb[1]
        cfg.nodes[node_id]['label'] = block
        cfg.nodes[node_id]['opcode'] = opcode
        cfg.nodes[node_id]['suc'] = []
        cfg.nodes[node_id]['pre'] = []
    
    for edge in func['edges']:
        if (addr2node_id.get(edge[0]) == None or addr2node_id.get(edge[1]) == None):
            continue
        node1 = addr2node_id[edge[0]]
        node2 = addr2node_id[edge[1]]
        cfg.add_edge(node1, node2)
        cfg.nodes[node1]['suc'].append(node2)
        cfg.nodes[node2]['pre'].append(node1)
    
    cfg = attributingRe(cfg, func, arch)

    return cfg
        

def attributingRe(cfg, func, arch):  # 为每个基本块生成自定义的属性
    call = func['call'].copy()
    call.reverse()
    for node_id in cfg:
        bl = cfg.nodes[node_id]['label']
        op = cfg.nodes[node_id]['opcode']
        numIns = calInsts(bl)  # No. of Instruction
        cfg.nodes[node_id]['numIns'] = numIns
        numCalls = calCalls(bl,arch)  # No. of Calls
        cfg.nodes[node_id]['numCalls'] = numCalls
        numLIs = calLogicInstructions(bl,arch)  # 这个不再Genius的范围内
        cfg.nodes[node_id]['numLIs'] = numLIs
        numAs = calArithmeticIns(bl,arch)  # No. of Arithmetic Instructions
        cfg.nodes[node_id]['numAs'] = numAs
        strings = getBBstrings(bl,arch)  # String and numeric constants
        consts = getBBconsts(op,arch)
        cfg.nodes[node_id]['numNc'] = len(strings) + len(consts)
        cfg.nodes[node_id]['consts'] = consts
        cfg.nodes[node_id]['strings'] = strings
        externs = retrieveExterns(bl, call)
        cfg.nodes[node_id]['externs'] = externs
        numTIs = calTransferIns(bl,arch)  # No. of Transfer Instruction
        cfg.nodes[node_id]['numTIs'] = numTIs
    return cfg