import sys

def ReadIda(filePath):
    disasmLines = []
    with open(filePath, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('.text'):

                sline = line.split()
                if len(sline) <= 1:
                    continue
                tmp = sline[1]
                if tmp == ';' or tmp == 'align' or tmp == 'public':
                    continue

                if line[-1] == '\n':
                    line = line[:-1]
                addr = sline[0][6:].lstrip('0')
                opcode = line[len(sline[0])+1:]
                disasmLines.append([addr, opcode])
    
    return disasmLines

def isFunctionStart(line):
    opcode = line[1]
    if opcode[0] != ' ':
        sopcode = opcode.split() 
        if len(sopcode) > 1:
            if sopcode[1] == 'proc': # 函数的开头
                return True
    return False

def isFunctionEnd(line):
    opcode = line[1]
    if opcode[0] != ' ':
        sopcode = opcode.split() 
        if len(sopcode) > 1:
            if sopcode[1] == 'endp': # 函数的结尾
                return True
    return False

def Split2Functions(disasmLines):
    funcRanges = []
    start = 0
    end = 0

    # 移到第一个函数的开头
    for i in range(len(disasmLines)):
        line = disasmLines[i]
        if isFunctionStart(line):
            start = i
            end = i
            break

    # 遍历函数
    for i in range(start, len(disasmLines)):
        line = disasmLines[i]
        if isFunctionStart(line):
            start = i
        elif isFunctionEnd(line):
            end = i
            if end > start + 1:
                funcRanges.append((start, end))

    return funcRanges

def isBlockEnd(opcode, prevOpcode):
    sopcode = opcode.split()
    sprevOpcode = prevOpcode.split()
    return (opcode[0] != ' ' and sopcode[0][-1] == ':') or (prevOpcode[0] == ' ' and (sprevOpcode[0][0] == 'j' or ('ret' in sprevOpcode[0])))

def Split2BBlocks(disasmLines, funcRange):
    start = funcRange[0]
    end = funcRange[1]

    offset = disasmLines[start][0]
    funcHead = disasmLines[start][1].split()
    funcname = funcHead[0]

    # 到开始位置
    for i in range(start+1, len(disasmLines)):
        opcode = disasmLines[i][1]
        if opcode[0] == ' ':
            start = i
            break
    
    func = {'funcname': funcname, 'offset':offset}
    
    blocks = []
    block = {'bName': '', 'id': start}
    name2addr = {}
    bStart = start
    bEnd = start
    for i in range(start, end):
        opcode = disasmLines[i][1]
        addr = disasmLines[i][0]
        if isBlockEnd(opcode, disasmLines[i-1][1]):
            bEnd = i
            block['bRange'] = (bStart, bEnd) # 不包括bEnd
            blocks.append(block)
            
            # 下一个block
            if opcode[0] != ' ':
                sopcode = opcode.split()
                bName = sopcode[0][:-1]
                block = {'bName': bName, 'id': i+1}
                name2addr[bName] = addr
                bStart = i+1
            else:
                block = {'bName': '', 'id': i}
                bStart = i
    
    bEnd = end
    block['bRange'] = (bStart, bEnd)
    blocks.append(block)
    
    func['blocks'] = blocks
    func['name2addr'] = name2addr
    return func

def ConstructFuncs(filePath):
    disasmLines = ReadIda(filePath)
    funcRanges = Split2Functions(disasmLines)
    funcs = []
    allFuncNames = set()
    for fRange in funcRanges:
        func = Split2BBlocks(disasmLines, fRange)
        funcs.append(func)
        allFuncNames.add(func['funcname'])
    
    jmps = ['jmp']
    conJumps = ['jz','jnz','jc','jnc','jo','jno','js','jns','jp','jnp','je','jne','jcxz','jecxz','jrcxz','ja','jnbe','jae',
                'jnb','jb','jnae','jbe','jna','jg','jnle','jge','jnl','jl','jnge','jle']
    calls = ['call']

    name2called = {}
    conFuncs = []
    
    for func in funcs:
        conFunc  = {'funcname': func['funcname']}
        blocks = []
        bb_addr_list = []
        call = []

        for b in func['blocks']:
            start = b['bRange'][0]
            end = b['bRange'][1]
            block = []
            blockLines = disasmLines[start:end]

            for line in blockLines:
                opcode = line[1]
                inst = opcode.split()
                addr = line[0]

                # 记录调用被调用
                if inst[0] in calls:
                    callName = inst[1]
                    if name2called.get(callName)  != None:
                        name2called[callName].append(func['funcname'])
                    else:
                        name2called[callName] = [func['funcname']]
                    call.append(callName)
                elif (inst[0] in jmps) or (inst[0] in conJumps):
                    callName = inst[1]
                    if callName in allFuncNames:
                        call.append(callName)

                block.append(opcode.lstrip(' '))
                bb_addr_list.append(addr)
            
            if block != []:
                blocks.append(block)
        
        if blocks != []:
            conFunc['blocks'] = blocks
            conFunc['bb_addr_list'] = bb_addr_list
            conFunc['call'] = call
            conFunc['bName2addr'] = func['name2addr']
            conFunc['offset'] = func['offset']

            conFuncs.append(conFunc)

    # 边和被调用
    for conFunc in conFuncs:
        # 被调用
        if name2called.get(conFunc['funcname']) != None:
            conFunc['called'] = name2called[conFunc['funcname']]
        else:
            conFunc['called'] = []

        # 边 edges
        edges = []
        addr_index = 0
        bName2addr = conFunc['bName2addr']
        for block in conFunc['blocks']:
            curAddr = conFunc['bb_addr_list'][addr_index]
            inst = block[-1].split()
            
            if inst[0] in jmps:
                if len(inst) < 3:
                    target = inst[1]
                else:
                    target = inst[2]
                if bName2addr.get(target) != None:
                    edges.append(((curAddr, bName2addr[target])))
            
            elif inst[0] in conJumps:
                if len(inst) < 3:
                    target = inst[1]
                else:
                    target = inst[2]
                if addr_index + len(block) < len(conFunc['bb_addr_list']):
                    edges.append((curAddr, conFunc['bb_addr_list'][addr_index+len(block)]))
                if bName2addr.get(target) != None:
                    edges.append(((curAddr, bName2addr[target])))

            else:
                if addr_index + len(block) < len(conFunc['bb_addr_list']):
                    edges.append((curAddr, conFunc['bb_addr_list'][addr_index+len(block)]))
            addr_index += len(block)
        
        conFunc['edges'] = edges

        del conFunc['bName2addr']

    return conFuncs
    '''
    conFunc的keys:
    funcname
    offset
    blocks
    bb_addr_list
    call
    called
    edges
    '''
