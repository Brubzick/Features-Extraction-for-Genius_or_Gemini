import re

def ReadWindbg(filePath):
    lines = []
    with open(filePath, 'r', encoding='utf-8') as f:
        for line in f:
            sline = line.split()
            if line[-1] == '\n':
                line = line[:-1]
            if line == '':
                continue
            if (line[0] == ' ' or line[-1] != ':') and len(sline[0]) != 8 and (len(sline[0]) != 17 or ('`' not in sline[0])) and (line[0] != ' ' or (not sline[0].isdigit())):
                continue # 不是指令内容
            
            if line[0] == ' ' and sline[0].isdigit():
                i = line.index(sline[1])
                lines.append(line[i:])
            else:
                lines.append(line)

    return lines

def isFunctionEnd(i, lines):
    line = lines[i]
    prevLine = lines[i-1]

    if line[0] != ' ' and line[-1] == ':':
        return True
    
    sline = line.split()
    if len(sline) > 3:
        if sline[2] == 'nop':
            return True
    
    sprevLine = prevLine.split()
    if len(sprevLine) > 2:
        if sprevLine[2] == 'ret':
            return True
        if len(sprevLine) > 3:
            if sprevLine[2] == 'nop':
                return True

    if sline[1] ==  '90' and sprevLine[1] != '90':
        if i + 4 < len(lines):
            if lines[i+1].split()[1] == '90' and lines[i+2].split()[1] == '90' and lines[i+3].split()[1] == '90' and lines[i+4].split()[1] == '90':
                return True
    
    if sline[1] != '90' and sprevLine[1] == '90':
        if i - 4 >= 0:
            if lines[i-2].split()[1] == '90' and lines[i-3].split()[1] == '90' and lines[i-4].split()[1] == '90':
                return True

    return False

def Split2Functions(lines):
    funcRanges = []
    start = 0
    end = 0
    funcname = ''

    for i in range(1, len(lines)):
        line = lines[i]
        # 如果有基本块的头,则不管
        if line[0] != ' ' and line[-1] == ':':
            sline = line.split()
            name = sline[0]
            if len(name) > len(funcname):
                if name[:len(funcname)] == funcname  and name[len(funcname)] == '+':
                    continue

        if isFunctionEnd(i, lines):
            end = i
            # 如果有函数头，记录函数名，用来判断基本块的头
            if line[0] != ' ' and line[-1] == ':':
                funcname = name

            if end > start:
                startLine = lines[start].split()
                if len(startLine) > 2:
                    if startLine[2] != 'nop' and (not re.compile("^0*$").match(startLine[1])):
                        funcRanges.append((start, end))
            
            start = end

    end = len(lines)
    if end > start:
        startLine = lines[start].split()
        if len(startLine) > 2:
            if startLine[2] != 'nop' and (not re.compile("^0*$").match(startLine[1])):
                funcRanges.append((start, end))

    return funcRanges

def Split2BBlocks(lines, funcRange):
    start = funcRange[0]
    end = funcRange[1]

    # 先记录所有jmp的目标地址
    jmpTar = set()
    for i in range(start, end):
        sline = lines[i].split()
        if len(sline) > 4:
            if sline[2][0] == 'j':
                jmpTar.add(sline[4][1:-1])

    line = lines[start]
    if line[0] != '' and line[-1] == ':':
        sline = line.split()
        funcname = sline[0]

        start += 1
        sline = lines[start].split()
        offset = sline[0]
    else:
        sline = line.split()
        offset = sline[0]
        funcname = 'fcn'+offset

    func = {'funcname': funcname, 'offset': offset}
    blocks = []
    bb_addr_list = []
    block = []

    for i in range(start, end):
        line = lines[i]
        sline = line.split()
        # 基本块的头
        if line[0] != ' ' and line[-1] == ':':
            if len(block) > 0:
                blocks.append(block)
                block = []
        else:
            addr = sline[0]
            if addr in jmpTar: # 跳转的目标
                if len(block) > 0:
                    blocks.append(block)
                    block = []
            opcode = ' '.join(sline[2:])
            bb_addr_list.append(addr)
            block.append(opcode)
             # 基本块的结尾
            if sline[2][0] == 'j' or sline[2] == 'ret':
                blocks.append(block)
                block = []

    if len(block) > 0:
        blocks.append(block)

    func['blocks'] = blocks
    func['bb_addr_list'] = bb_addr_list

    return func

def ConstructFuncs(filePath):
    lines = ReadWindbg(filePath)
    funcRanges = Split2Functions(lines)
    funcs = []

    for fRange in funcRanges:
        func = Split2BBlocks(lines, fRange)
        funcs.append(func)

    jmps = ['jmp']
    conJumps = ['jz','jnz','jc','jnc','jo','jno','js','jns','jp','jnp','je','jne','jcxz','jecxz','jrcxz','ja','jnbe','jae',
                'jnb','jb','jnae','jbe','jna','jg','jnle','jge','jnl','jl','jnge','jle']
    calls = ['call']

    #记录调用和被调用
    addr2called = {}
    for func in funcs:
        call = []
        
        for block in func['blocks']:
            for line in block:
                inst = line.split()
                if inst[0] in calls:
                    if len(inst) > 2:
                        callName = inst[1]
                        callAddr = inst[2][1:-1]
                        call.append(callName)
                        if addr2called.get(callAddr) != None:
                            addr2called[callAddr].append(func['funcname'])
                        else:
                            addr2called[callAddr] = [func['funcname']]
        
        func['call'] = call

    #边和被调用
    for func in funcs:
        # 被调用
        if addr2called.get(func['offset']) != None:
            func['called'] = addr2called[func['offset']]
        else:
            func['called'] = []

        # 边
        edges = []
        addr_index = 0
        for block in func['blocks']:
            bb_addr = func['bb_addr_list'][addr_index]
            addr_index += len(block)

            inst = block[-1].split()

            if inst[0] in jmps:
                target = inst[2][1:-1]
                edges.append((bb_addr, target))
            
            elif inst[0] in conJumps:
                target = inst[2][1:-1]
                edges.append((bb_addr, target))
                if addr_index < len(func['bb_addr_list']):
                    edges.append((bb_addr, func['bb_addr_list'][addr_index]))
            
            else:
                if addr_index < len(func['bb_addr_list']):
                    edges.append((bb_addr, func['bb_addr_list'][addr_index]))
        
        func['edges'] = edges
    
    return funcs
    '''
    keys:
    funcname
    offset
    blocks
    bb_addr_list
    call
    called
    edges
    '''
    