import os

x86_jmp = ['jz','jnz','jc','jnc','jo','jno','js','jns','jp','jnp','je','jne','jcxz','jecxz','jrcxz',
           'ja','jnbe','jae','jnb','jb','jnae','jbe','jna','jg','jnle','jge','jnl','jl','jnge','jle',
           'call','mov']

addrs = []
mnemonics = []
opcodes = []
disasmPath = './disasm/test.txt'
filename = os.path.basename(disasmPath)
with open(disasmPath, 'r') as f:
    for line in f:
        codes = line[0:-1].split()
        addrs.append(codes[0][2:-1])
        mnemonics.append(codes[1])
        if len(codes) > 2:
            opcodes.append(' '.join(codes[2:]))
        else:
            opcodes.append('')

l = len(addrs)
for i in range(l):
    print(addrs[i],mnemonics[i],opcodes[i])

