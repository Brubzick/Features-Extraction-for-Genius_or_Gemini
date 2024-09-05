import networkx as nx

# No. of calls
def getFuncCalls(func):
    return func['callNum']

def CalCalls(block):
    calls = {'call': 1, 'jal': 1, 'jalr': 1, 'bl': 1, 'blx': 1, 'bx': 1}

    callnum = 0
    for ins in block:
        ins = ins.split()
        if ins[0] in calls:
            callnum += 1

    return callnum

# No. of logic instructions
def getLogicInsts(cfg):
    sumInsts = 0
    for node in cfg.nodes:
        block = cfg.nodes[node]['block']
        instNum = calLogicInstructions(block)
        sumInsts += instNum
    return sumInsts

def calLogicInstructions(bl):
    x86_LI = {'and': 1, 'andn': 1, 'andnpd': 1, 'andpd': 1, 'andps': 1, 'andnps': 1, 'test': 1, 'xor': 1, 'xorpd': 1,
              'pslld': 1}
    mips_LI = {'and': 1, 'andi': 1, 'or': 1, 'ori': 1, 'xor': 1, 'nor': 1, 'slt': 1, 'slti': 1, 'sltu': 1}
    arm_LI = {'and': 1, 'orr': 1, 'eor': 1, 'bic': 1, 'mvn': 1, 'tst': 1, 'teq': 1, 'cmp': 1, 'cmn': 1}

    calls = {}
    calls.update(x86_LI)
    calls.update(mips_LI)
    calls.update(arm_LI)

    invoke_num = 0
    for ins in bl:
        ins = ins.split()
        if ins[0] in calls:
            invoke_num += 1

    return invoke_num

# No. of transfer instructions
def getTransferInsts(cfg):
    sumInsts = 0
    for node in cfg.nodes:
        block = cfg.nodes[node]['block']
        instNum = calTransferIns(block)
        sumInsts += instNum
    return sumInsts

def calTransferIns(bl):
    x86_TI = {'jmp': 1, 'jz': 1, 'jnz': 1, 'js': 1, 'je': 1, 'jne': 1, 'jg': 1, 'jle': 1, 'jge': 1, 'ja': 1, 'jnc': 1,
              'call': 1}
    mips_TI = {'beq': 1, 'bne': 1, 'bgtz': 1, "bltz": 1, "bgez": 1, "blez": 1, 'j': 1, 'jal': 1, 'jr': 1, 'jalr': 1}
    arm_TI = {'mvn': 1, "mov": 1}
    calls = {}
    calls.update(x86_TI)
    calls.update(mips_TI)
    calls.update(arm_TI)

    invoke_num = 0
    for ins in bl:
        ins = ins.split()
        if ins[0] in calls:
            invoke_num += 1

    return invoke_num

# No. basic blocks
def getBasicBlocks(cfg):
    nodes = cfg.nodes
    return len(nodes)

# Between
def retrieveGP(g):
	bf = betweeness(g)
	#close = closeness_centrality(g)
	#bf_sim = 
	#close_sim = 
	x = sorted(bf.values())
	value = sum(x)/len(x)
	return round(value,5)

def betweeness(g):
	#pdb.set_trace()
	betweenness = nx.betweenness_centrality(g)
	return betweenness

# No. of instructions
def getIntrs(cfg):
    sumIns = 0
    for node in cfg.nodes:
        ins_addr_list = cfg.nodes[node]['ins_addr_list']
        insNum = calInsts(ins_addr_list)
        sumIns += insNum
    return sumIns

def calInsts(insts):
    num = len(insts)
    return num

# No. of local variables
def getLocalVariables(func):
    return func['argsNum']

# No. of being called
def getIncommingCalls(func):
    return func['calledNum']

# constants
def getfunc_consts(cfg):
    strings = []
    consts = []
    for node in cfg.nodes:
        block = cfg.nodes[node]['block']
        strs, cons = getBBconst(block)
        strings += strs
        consts += cons
    
    return strings, consts

def getBBconst(block):
    strings = []
    consts = []
    for ins in block:
        ins = ins.split()
        if ins[0] in ['la', 'jalr', 'call', 'jal','ldr', 'str', 'mov', 'bl', 'b', 'bx', 'blx']:
            continue
        for op in ins:
            if op.startswith('str.'):
                strings.append(op[4:])
            else:
                if op[-1] == ',':
                    op = op[:-1]
                if op.isdigit():
                    consts.append(int(op))
                elif op.startswith('0x'):
                    op = op[2:]
                    try:
                        con = int(op,16)
                        consts.append(con)
                    except:
                        pass
    
    return strings, consts
        
