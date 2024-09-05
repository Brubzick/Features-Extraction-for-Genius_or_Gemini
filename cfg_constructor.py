import networkx as nx

class CFGNode:
    def __init__(self, addr, ins_addr_list):
        self.addr = addr
        self.ins_addr_list = ins_addr_list
        # self.block = []
        # self.successors = []
        # self.predecessors = []

def get_cfg(func):
    cfg = nx.DiGraph()
    addr2node = {}
    opcodeIndex = 0
    for bb in func['bb_addr_list']:
        node = CFGNode(bb[0], bb[1])
        cfg.add_node(node)
        ops = func['pdf']['ops']
        block = []
        for addr in bb[1]:
            if addr == ops[opcodeIndex]['offset']:
                block.append(ops[opcodeIndex]['disasm'])
            opcodeIndex += 1
        addr2node[bb[0]] = node
        cfg.nodes[node]['addr'] = bb[0]
        cfg.nodes[node]['ins_addr_list'] = bb[1]
        cfg.nodes[node]['block'] = block
        cfg.nodes[node]['suc'] = []
        cfg.nodes[node]['pre'] = []

    for edge in func['edges']:
        node1 = addr2node[edge[0]]
        node2 = addr2node[edge[1]]
        cfg.add_edge(node1, node2)
        cfg.nodes[node1]['suc'].append(node2)
        cfg.nodes[node2]['pre'].append(node1)

    return cfg
        
    
