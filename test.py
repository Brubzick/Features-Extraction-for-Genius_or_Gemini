import angr
from radare2_utils import R2Helper

filePath = './data/example'

r2 = R2Helper(filePath)
res = r2.calc_cfg_info()

p = angr.Project(filePath, auto_load_libs=False)
cfg = p.analyses.CFGFast(normalize=True)
funcs = cfg.functions.values()

angrName = []
for func in funcs:
    if (not func.is_simprocedure):
        if (not func.name.startswith('sub_')):
            angrName.append(func.name)

r2Name = []
for func in res:
    name = func['func_name']
    if name.startswith('sym.'):
        name = name[4:]
        if name.startswith('imp.'):
            name = name[4:]
    r2Name.append(name)

print(r2Name)
print(len(r2Name))
print(angrName)
print(len(angrName))

print('===================================================')

for i in range(len(r2Name)-1,-1,-1):
    if r2Name[i] in angrName:
        angrName.remove(r2Name[i])
        r2Name.remove(r2Name[i])
print(r2Name)
print(angrName)

# for func in res:
#     if func['func_name'] in r2Name:
#         print(func['func_name'])
#         for one in func['pdf']['ops']:
#             print(one['disasm'])