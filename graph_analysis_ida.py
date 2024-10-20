import networkx as nx
import re

def is_hex(s):
    return bool(re.match(r'^[0-9a-fA-F]+$', s))


# No. of calls
def getFuncCalls(cfg):
    sumcall = 0
    for node in cfg.nodes:
        block = cfg.nodes[node]['block']
        callmun = calCalls(block)
        sumcall += callmun
    return sumcall

def calCalls(block):
    calls = {'call', 'bl', 'blx', 'bx'}

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
    x86_calls = {'and': 1, 'andn': 1, 'andnpd': 1, 'andpd': 1, 'andps': 1, 'andnps': 1, 'test': 1, 'xor': 1, 'xorpd': 1,
                'pslld': 1}
    x64_calls = {'andq': 1, 'andnq': 1, 'andnpdq': 1, 'andpdq': 1, 'andpsq': 1, 'andnpsq': 1, 'testq': 1, 'xorq': 1, 'xorpdq': 1,'pslldq': 1,
                    'andl': 1, 'andnl': 1, 'andnpdl': 1, 'andpdl': 1, 'andpsl': 1, 'andnpsl': 1, 'testl': 1, 'xorl': 1, 'xorpdl': 1,'pslldl': 1}
    arm_calls = {'and': 1, 'orr': 1, 'eor': 1, 'bic': 1, 'mvn': 1, 'tst': 1, 'teq': 1, 'cmp': 1, 'cmn': 1}
    calls = {}
    calls.update(x64_calls)
    calls.update(x86_calls)
    calls.update(arm_calls)

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
    x86_calls = {'jmp': 1, 'jz': 1, 'jnz': 1, 'js': 1, 'je': 1, 'jne': 1, 'jg': 1, 'jle': 1, 'jge': 1, 'ja': 1, 'jnc': 1,
                'call': 1}
    arm_calls = {'mvn': 1, "mov": 1, 'beq': 1, 'bne': 1, 'bgtz': 1, "bltz": 1, "bgez": 1, "blez": 1}
    calls = {}
    calls.update(x86_calls)
    calls.update(arm_calls)

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
    x = sorted(bf.values())
    if len(x) == 0:
        value = 0
    else:
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
    x86_64_regs = {'rdi','rsi','rdx','rcx','r8','r9',
                   'edi','esi','edx','ecx','r8d','r9d'}
    # arm_regs = {'r0','r1','r2','r3',
    #             'x0','x1','x2','x3','x4','x5','x6','x7',
    #             'w0','w1','w2','w3','w4','w5','w6','w7'}
    x86_64_stack = {'rbp','ebp'}
    # arm_stack = {'sp','fp','x29'}
    push = {'push','pushq','pushl'}
    calls = {'jz','jnz','jc','jnc','jo','jno','js','jns','jp','jnp','je','jne','jcxz','jecxz','jrcxz',
            'ja','jnbe','jae','jnb','jb','jnae','jbe','jna','jg','jnle','jge','jnl','jl','jnge','jle',
            'jmp','call'}
            # 'beq','bne','bcs','bcc','bmi','bpl','bvs','bvc','bhi','bls','bge','blt','bgt','ble','bal',
            # 'bxeq','bxne','bxcs','bxcc','bxmi','bxpl','bxvs','bxvc','bxhi','bxls','bxge','bxlt','bxgt','bxle','bxal',
            # 'bleq','blne','blcs','blcc','blmi','blpl','blvs','blvc','blhi','blls','blge','bllt','blgt','blle','blal',
            # 'blxeq','blxne','blxcs','blxcc','blxmi','blxpl','blxvs','blxvc','blxhi','blxls','blxge','blxlt','blxgt','blxle','blxal',
            # 'bl', 'b', 'bx', 'blx'}
    movs = {'mov', 'movl', 'movq'}

    block = func['blocks'][0] # 第一个基本块
    stacking = True
    fList = []
    paras = []
    argsNum = 0

    ins = block[0].split()
    if ins[0] in push:
        x86_64_stack.add(ins[1])

    for ins in block:
        inst = ins.split()
        # x86
        if inst[0] in movs:
            for stack in x86_64_stack:
                index1 = inst[1].find('['+stack)
                index2 = inst[2].find('['+stack)
                if index1 > -1 or index2 > -1:
                    break

            if index1 > -1: # 从参数寄存器中读取参数入栈
                if stacking == False: # 已开始从栈中读取
                    return argsNum
                if inst[2] not in x86_64_regs: # 非参数寄存器
                    return argsNum
                if inst[2] in paras: # 重复
                    return argsNum
                paras.append(inst[2])
                argsNum += 1
                fList.append(inst[1][:-1]) # 最后一个是','
            elif index2 > -1: # 从栈中读取参数 
                if stacking:
                    firstF = fList.copy()
                    stacking = False # 开始从栈中读取参数

                ftmp = inst[2]
                if ftmp in fList:
                    if ftmp in firstF:
                        firstF.remove(ftmp)
                    else:
                        return argsNum
                else:
                    if firstF != []:
                        continue
                    fList.append(ftmp)
                    argsNum += 1
        #arm
        # elif inst[0] in {'str', 'stur'}:
        #     # 从寄存器中读取参数时
        #     if inst[1][0:-1] in arm_regs:
        #         if stacking == False: # 已开始从栈中读取
        #             return argsNum
        #         if inst[1][0:-1] in paras: # 重复
        #             return argsNum
        #         paras.append(inst[1][0:-1])
        #         if inst[2][0] == '[':
        #             index = max(inst[2].find(stack) for stack in arm_stack)
        #             if index == -1: # 读到了别的地方
        #                 return argsNum
                    
        #             for i in range(2, len(inst)):
        #                 if inst[i].endswith(']'):
        #                     break
        #             f = ' '.join(inst[2:i+1])

        #             if f in fList:
        #                 return argsNum
        #             fList.append(f)
        #             argsNum += 1
        #     else:
        #         # 非参数寄存器
        #         if stacking == False:
        #             return argsNum
        # # 从栈中读取参数    
        # elif inst[0] in {'ldr', 'ldur'}:
        #     if stacking:
        #         firstF = fList.copy()
        #     if inst[2][0] == '[':
        #             index = max(inst[2].find(stack) for stack in arm_stack)
        #             if index > -1:

        #                 for i in range(2, len(inst)):
        #                     if inst[i].endswith(']'):
        #                         break
        #                 f = ' '.join(inst[2:i+1])

        #                 if f in fList:
        #                     stacking = True
        #                     if f in firstF:
        #                         firstF.remove(f)
        #                     else:
        #                         return argsNum
        #                 else:
        #                     if firstF == []:
        #                         argsNum += 1
        #                         fList.append(f)
        #                     else:
        #                         continue
        
        elif inst[0] in calls:
            return argsNum
    
    return argsNum

# No. of being called
def getIncommingCalls(func):
    return len(func['called'])

# constants
def getfunc_consts(cfg):
    strings = []
    consts = []
    for node in cfg.nodes:
        block = cfg.nodes[node]['block']
        strs = getBBstrings(block)
        cons = getBBconsts(block)
        strings += strs
        consts += cons
    
    return strings, consts

def getBBstrings(block):
    
    calls = {'jz','jnz','jc','jnc','jo','jno','js','jns','jp','jnp','je','jne','jcxz','jecxz','jrcxz',
            'ja','jnbe','jae','jnb','jb','jnae','jbe','jna','jg','jnle','jge','jnl','jl','jnge','jle',
            'jmp','call'}
            # 'beq','bne','bcs','bcc','bmi','bpl','bvs','bvc','bhi','bls','bge','blt','bgt','ble','bal',
            # 'bxeq','bxne','bxcs','bxcc','bxmi','bxpl','bxvs','bxvc','bxhi','bxls','bxge','bxlt','bxgt','bxle','bxal',
            # 'bleq','blne','blcs','blcc','blmi','blpl','blvs','blvc','blhi','blls','blge','bllt','blgt','blle','blal',
            # 'blxeq','blxne','blxcs','blxcc','blxmi','blxpl','blxvs','blxvc','blxhi','blxls','blxge','blxlt','blxgt','blxle','blxal',
            # 'bl', 'b', 'bx', 'blx'}

    strings = []
    for ins in block:
        inst = ins.split()
        if len(inst) < 2:
            continue
        if inst[0] in calls:
            continue
        
        i1 = ins.find(';')
        if i1 >= 0:
            com = ins[i1:]
            left = com.find('"')
            if left >= 0:
                for i in range(len(com)-1, -1, -1):
                    if com[i] == '"':
                        right = i
                        break
                if right > left:
                    strPart = com[left+1:right]
                    strings.append(strPart)

    return strings

def getBBconsts(opcode):
    x86_calls = {'jz','jnz','jc','jnc','jo','jno','js','jns','jp','jnp','je','jne','jcxz','jecxz','jrcxz',
                'ja','jnbe','jae','jnb','jb','jnae','jbe','jna','jg','jnle','jge','jnl','jl','jnge','jle',
                'jmp','call','mov','movq','movl'}
    # arm_calls = {'beq','bne','bcs','bcc','bmi','bpl','bvs','bvc','bhi','bls','bge','blt','bgt','ble','bal',
    #              'bxeq','bxne','bxcs','bxcc','bxmi','bxpl','bxvs','bxvc','bxhi','bxls','bxge','bxlt','bxgt','bxle','bxal',
    #              'bleq','blne','blcs','blcc','blmi','blpl','blvs','blvc','blhi','blls','blge','bllt','blgt','blle','blal',
    #              'blxeq','blxne','blxcs','blxcc','blxmi','blxpl','blxvs','blxvc','blxhi','blxls','blxge','blxlt','blxgt','blxle','blxal',
    #              'moveq','movne','movcs','movcc','movmi','movpl','movvs','movvc','movhi','movls','movge','movlt','movgt','movle','moval',
    #              'ldr', 'str', 'stur', 'ldur' 'mov', 'bl', 'b', 'bx', 'blx','movw','movt'}

    calls = x86_calls

    consts = []
    for ins in opcode:
        ins = ins.split()

        if ins[0] in calls:
            continue

        for op in ins:
            minus = False
            if op[-1] == ',':
                op = op[:-1]
            if op[0] == '-':
                op = op[1:] 
                minus = True   
            
            if len(op) > 0:
                if op[-1] == 'h':
                    digit = op[:-1]
                    if is_hex(digit):
                        if minus:
                            consts.append(-int(digit,16))
                        else:
                            consts.append(int(digit,16))
                elif op == '0':
                    consts.append(0)
    
    return consts
        
def calArithmeticIns(bl):
    # 定义各架构中的算术指令
    x86_calls = {'add': 1, 'sub': 1, 'div': 1, 'imul': 1, 'idiv': 1, 'mul': 1, 'shl': 1, 'dec': 1, 'inc': 1}
    x64_calls = {'addl': 1, 'subl': 1, 'divl': 1, 'imull': 1, 'idivl': 1, 'mull': 1, 'shll': 1, 'decl': 1, 'incl': 1,
                 'addq': 1, 'subq': 1, 'divq': 1, 'imulq': 1, 'idivq': 1, 'mulq': 1, 'shlq': 1, 'decq': 1, 'incq': 1}
    arm_calls = {'add': 1, 'sub': 1, 'mul': 1, 'mla': 1, 'mls': 1, 'sdiv': 1, 'udiv': 1, 'rsb': 1, 'rsc': 1}  # ARM 架构中的算术指令
    calls = {}
    calls.update(x64_calls)
    calls.update(x86_calls)
    calls.update(arm_calls)

    invoke_num = 0
    for ins in bl:
        ins = ins.split()
        if ins[0] in calls:
            invoke_num += 1

    return invoke_num

def retrieveExterns(bl, call):
    externs = []
    for ins in bl:
        inst = ins.split()
        if call == []: break
        extern = call[-1]
        if extern in inst:
            externs.append(extern)
            call.pop()
    return externs