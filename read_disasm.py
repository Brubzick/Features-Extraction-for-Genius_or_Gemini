import os
import re

def is_hex(s):
    return bool(re.match(r'^[0-9a-fA-F]+$', s))

def is_invalid(sl):
    for s in sl:
        if is_hex(s) or ('.' in s):
            pass
        else:
            return False
    return True

def ReadDisasm(disasmPath, arch):
    x86_conjmps = ['jz','jnz','jc','jnc','jo','jno','js','jns','jp','jnp','je','jne','jcxz','jecxz','jrcxz',
                'ja','jnbe','jae','jnb','jb','jnae','jbe','jna','jg','jnle','jge','jnl','jl','jnge','jle']
    x86_jmps = ['jmp']
    x86_calls = ['call']

    arm_conjmps = ['beq','bne','bcs','bcc','bmi','bpl','bvs','bvc','bhi','bls','bge','blt','bgt','ble','bal']
    arm_jmps = ['b']
    arm_calls = ['bleq','blne','blcs','blcc','blmi','blpl','blvs','blvc','blhi','blls','blge','bllt','blgt','blle','blal',
                 'blxeq','blxne','blxcs','blxcc','blxmi','blxpl','blxvs','blxvc','blxhi','blxls','blxge','blxlt','blxgt','blxle','blxal',
                 'bxeq','bxne','bxcs','bxcc','bxmi','bxpl','bxvs','bxvc','bxhi','bxls','bxge','bxlt','bxgt','bxle','bxal',
                 'bl','blx','bx']

    if arch == 'x86':
        conjmps = x86_conjmps
        jmps = x86_jmps
        calls = x86_calls
    elif arch == 'arm':
        conjmps = arm_conjmps
        jmps = arm_jmps
        calls = arm_calls

    funcs = []
    lines = []
    # rodata = {}
    with open(disasmPath, 'r', encoding='utf-8') as f:
        for line in f:
            if line[-1] == '\n':
                lines.append(line[0:-1])
            else:
                lines.append(line)
            '''
            ELF: 只有.init和.fini这两个section之间的部分是汇编指令
            PE: 只有.text section是汇编指令
            MachO: 只有__text和__stub_helper之间
            '''
            if line.startswith('.init (PROGBITS) section started') or line.startswith('.text section started') or line.startswith('__text (PURE_CODE) section started'):
                lines = []
            elif line.startswith('.fini (PROGBITS) section ended') or line.startswith('.text section ended') or line.startswith('__stub_helper (PURE_CODE) section ended'):
                break
        # 如果有.rodata
        # record = False
        # for line in f:
        #     if record:
        #         if '=' in line:
        #             line_s = line.split()
        #             index = line.index('=')
        #             dataName = line[index-1]

        #     if line.startswith('.rodata (PROGBITS) section started'):
        #         record = True
        #     elif line.startswith('.rodata (PROGBITS) section ended'):
        #         break


    func = {'offset': -1}
    addr2func = {}
    blocks = []
    block = []
    bb_addr_list = []
    continuation = False # 不考虑Continuation的部分
    for i in range(len(lines)):
        line = lines[i]
        if line.startswith('.') or line.startswith('__'):
            continue
        if line.startswith('{ Continuation of'):
            continuation = True
            continue
        if line == '': # 基本块的结尾
            if block != []:
                blocks.append(block)
                block = []
        else:
            line = line.split()
            hex_addr = line[0]
            if is_hex(hex_addr):

                if i+2 < len(lines):
                    line_t = lines[i+2].split()
                if len(line_t) < 2:
                    line_t = lines[i+3].split()
                if len(line_t) < 2:
                    tmp = ''
                else:
                    tmp = line_t[0]
            
                if (line[0] == tmp) and (not is_hex(line[1])): # 函数名
                    # 存储上一个函数
                    if bb_addr_list != []:
                        func['blocks'] = blocks
                        func['bb_addr_list'] = bb_addr_list
                        funcs.append(func)
                        addr2func[func['offset']] = func

                    # 初始化
                    func = {'offset': int(line[0], 16), 'header': ' '.join(line[1:])}
                    blocks = []
                    block = []
                    bb_addr_list = []
                    continuation = False
                
                else:
                    if continuation:
                        continue
                    if len(line) < 2:
                        continue
                        
                    # 当前地址
                    int_addr = int(hex_addr, 16)

                    if '…' in line[1]:
                        sep = line[1].split('…')
                        if len(sep) == 2 and is_hex(sep[0]):
                            line.insert(2, sep[1])
                            bb_addr_list.append(int_addr)
                            block.append(' '.join(line[2:]))

                    else:
                        if len(line) < 3:
                            continue
                        if is_hex(line[1]):
                            if is_invalid(line[2:]):
                                continue
                            else:
                                bb_addr_list.append(int_addr)
                                block.append(' '.join(line[2:]))
            else:
                continue
            
    # 存储最后一个函数
    if block != []:
        blocks.append(block)
    if bb_addr_list != []:
        func['blocks'] = blocks
        func['bb_addr_list'] = bb_addr_list
        funcs.append(func)

    # funcs.remove(funcs[0]) # 删除dummy

    name2called = {} # 用于记录被调用的情况
    name2addr = {} # 通过函数名得到函数offset

    for func in funcs:
        # 函数的参数
        head = func['header']
        l = len(head)
        start = -1
        end = -1
        rightCount = 0
        leftCount = 0
        for i in range(l-1,-1,-1):
            if head[i] == ')':
                if end < 0: end = i
                leftCount += 1
            elif head[i] == '(':
                start = i
                rightCount += 1
                if rightCount == leftCount:
                    break
        args = head[start:end+1]
        num = args.count(',')
        if num == 0:
            if args == '()':
                argsNum = 0
            else:
                argsNum = 1
        else:
            if '...' in args:
                argsNum = num
            else:
                argsNum = num + 1
        
        func['argsNum'] = argsNum

        # 函数名
        for i in range(start-1,-1,-1):
            if head[i] == ' ':
                break
        funcname = head[i+1:start]

        func['funcname'] = funcname
        name2addr[funcname] = func['offset']

    for func in funcs:
        # 调用和被调用，顺便记录地址到基本块的字典
        addrIndex = 0
        addr2block = {}
        namecall = []
        for block in func['blocks']:
            addr = func['bb_addr_list'][addrIndex]
            addr2block[addr] = block
            addrIndex += len(block)
            for ins in block:
                ins = ins.split()
                if ins[0] in calls:
                    name = ins[1]
                    namecall.append(name)
                    if name2called.get(name):
                        name2called[name].append(func['offset'])
                    else:
                        name2called[name] = [func['offset']]
                elif (ins[0] in jmps) or (ins[0] in conjmps):
                    if ins[1].startswith('0x'):
                        offset = int(ins[1][2:], 16)
                        if addr2func.get(offset):
                            name = addr2func[offset]['funcname']
                            if name2called.get(name):
                                name2called[name].append(func['offset'])
                            else:
                                name2called[name] = [func['offset']]
        
        func['call'] = namecall

        # 记录边 edges
        edges = []
        addrIndex = 0
        for block in func['blocks']:
            ins = block[-1]
            curAddr = func['bb_addr_list'][addrIndex]
            addrIndex += len(block)
            ins = ins.split()

            if ins[0] in jmps:
                # jump
                if ins[1].startswith('0x'):
                    toAddr = int(ins[1][2:], 16)
                    if toAddr in func['bb_addr_list']:
                        if (curAddr, toAddr) not in edges:
                            edges.append((curAddr, toAddr))

            elif ins[0] in conjmps:
                # conditional jump
                if ins[1].startswith('0x'):
                    toAddr = int(ins[1][2:], 16)
                    if toAddr in func['bb_addr_list']:
                        if (curAddr, toAddr) not in edges:
                            edges.append((curAddr, toAddr))
                if addrIndex < len(func['bb_addr_list']):
                    nextAddr = func['bb_addr_list'][addrIndex]
                    if (curAddr, nextAddr) not in edges:
                        edges.append((curAddr, nextAddr))
            
            elif ins[0] in calls:
                # call
                calledFunc = addr2func.get(name2addr.get(ins[1]))
                if calledFunc != None:
                    lastIns = calledFunc['blocks'][-1][-1].split()

                    if arch == 'arm':
                        if len(lastIns) >= 2:
                            if (lastIns[0] == 'bx' and lastIns[1] == 'lr') or (lastIns[0] == 'pop'):
                                if addrIndex < len(func['bb_addr_list']):
                                    nextAddr = func['bb_addr_list'][addrIndex]
                                    if (curAddr, nextAddr) not in edges:
                                        edges.append((curAddr, nextAddr))
                    
                    elif arch == 'x86':
                        if lastIns[0] == 'ret' or lastIns[0] == 'retn':
                            if addrIndex < len(func['bb_addr_list']):
                                nextAddr = func['bb_addr_list'][addrIndex]
                                if (curAddr, nextAddr) not in edges:
                                    edges.append((curAddr, nextAddr))
                
                else:
                    if addrIndex < len(func['bb_addr_list']):
                        nextAddr = func['bb_addr_list'][addrIndex]
                        if (curAddr, nextAddr) not in edges:
                            edges.append((curAddr, nextAddr))
                    
            else:
                #others
                if addrIndex < len(func['bb_addr_list']):
                    nextAddr = func['bb_addr_list'][addrIndex]
                    if (curAddr, nextAddr) not in edges:
                        edges.append((curAddr, nextAddr))
            

        func['edges'] = edges

        # 初始化called
        func['called'] = []

    # 记录被调用的情况
    for name in name2called:
        if name2addr.get(name):
            addr = name2addr[name]
            if addr2func.get(addr):
                func = addr2func[addr]
                func['called'] = name2called[name]

    return funcs

'''
func的key:
'offset'
'header'
'blocks'
'bb_addr_list'
'argsNum'
'funcname'
'edges'
'call': 调用别的函数, 只考虑call
'called':被调用(包括jump)
'''
