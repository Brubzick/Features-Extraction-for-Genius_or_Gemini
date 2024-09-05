import networkx as nx

# No. of calls
def getFuncCalls(func):
    return len(func['call'])

def calCalls(block):
    calls = {'call': 1, 'jal': 1, 'jalr': 1, 'bl': 1, 'blx': 1, 'bx': 1, 'BL': 1, 'BLX': 1, 'BX': 1}

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
        block = cfg.nodes[node]['label']
        instNum = calLogicInstructions(block)
        sumInsts += instNum
    return sumInsts

def calLogicInstructions(bl):
    x86_LI = {'and': 1, 'andn': 1, 'andnpd': 1, 'andpd': 1, 'andps': 1, 'andnps': 1, 'test': 1, 'xor': 1, 'xorpd': 1,
              'pslld': 1}
    mips_LI = {'and': 1, 'andi': 1, 'or': 1, 'ori': 1, 'xor': 1, 'nor': 1, 'slt': 1, 'slti': 1, 'sltu': 1}
    arm_LI = {'AND': 1, 'ORR': 1, 'EOR': 1, 'BIC': 1, 'MVN': 1, 'TST': 1, 'TEQ': 1, 'CMP': 1, 'CMN': 1}
    arm_LI_little = {'and': 1, 'orr': 1, 'eor': 1, 'bic': 1, 'mvn': 1, 'tst': 1, 'teq': 1, 'cmp': 1, 'cmn': 1}

    calls = {}
    calls.update(x86_LI)
    calls.update(mips_LI)
    calls.update(arm_LI)
    calls.update(arm_LI_little)

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
        block = cfg.nodes[node]['label']
        instNum = calTransferIns(block)
        sumInsts += instNum
    return sumInsts

def calTransferIns(bl):
    x86_TI = {'jmp': 1, 'jz': 1, 'jnz': 1, 'js': 1, 'je': 1, 'jne': 1, 'jg': 1, 'jle': 1, 'jge': 1, 'ja': 1, 'jnc': 1,
              'call': 1}
    mips_TI = {'beq': 1, 'bne': 1, 'bgtz': 1, "bltz": 1, "bgez": 1, "blez": 1, 'j': 1, 'jal': 1, 'jr': 1, 'jalr': 1}
    arm_TI = {'MVN': 1, "MOV": 1}
    arm_TI_little = {'mvn': 1, "mov": 1}
    calls = {}
    calls.update(x86_TI)
    calls.update(mips_TI)
    calls.update(arm_TI)
    calls.update(arm_TI_little)

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
    return len(func['called'])

# constants
def getfunc_consts(cfg):
    strings = []
    consts = []
    for node in cfg.nodes:
        block = cfg.nodes[node]['label']
        strs, cons = getBBconsts(block)
        strings += strs
        consts += cons
    
    return strings, consts

def getBBconsts(block):
    strings = []
    consts = []
    for ins in block:
        ins = ins.split()
        if ins[0] in ['la', 'jalr', 'call', 'jal','ldr', 'str', 'mov', 'bl', 'b', 'bx', 'blx', 'BL', 'B', 'BX', 'BLX']:
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
        
def calArithmeticIns(bl):
    # 定义各架构中的算术指令
    x86_AI = {'add': 1, 'sub': 1, 'div': 1, 'imul': 1, 'idiv': 1, 'mul': 1, 'shl': 1, 'dec': 1, 'inc': 1}
    mips_AI = {'add': 1, 'addu': 1, 'addi': 1, 'addiu': 1, 'mult': 1, 'multu': 1, 'div': 1, 'divu': 1}
    arm_AI = {'ADD': 1, 'SUB': 1, 'MUL': 1, 'MLA': 1, 'MLS': 1, 'SDIV': 1, 'UDIV': 1, 'RSB': 1, 'RSC': 1}  # ARM 架构中的算术指令
    arm_AI_little = {'add': 1, 'sub': 1, 'mul': 1, 'mla': 1, 'mls': 1, 'sdiv': 1, 'udiv': 1, 'rsb': 1, 'rsc': 1}

    calls = {}
    calls.update(x86_AI)
    calls.update(mips_AI)
    calls.update(arm_AI)
    calls.update(arm_AI_little)

    invoke_num = 0
    for ins in bl:
        ins = ins.split()
        if ins[0] in calls:
            invoke_num += 1

    return invoke_num

def retrieveExterns(bl, call):
    externs = []
    for ins in bl:
        if call == []: break
        extern = call[-1]
        if extern in ins:
            externs.append(extern)
            call.remove(call[-1])
        # for extern in call:
        #     if extern in ins:
        #         externs.append(extern)
        #         call.remove(extern)
        #         break
    return externs