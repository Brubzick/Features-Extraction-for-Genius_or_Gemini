import angr
import sys

p = angr.Project('./data/example', auto_load_libs=False)

cfg = p.analyses.CFGFast(normalize=True)

with open('./disasm/test.txt', 'w') as f:
    original_stdout = sys.stdout
    sys.stdout = f
    for node in sorted(cfg.nodes(), key = lambda n: n.addr):
        if not node.is_simprocedure:
            node.block.capstone.pp()
            print('')
    sys.stdout = original_stdout

# for node in sorted(cfg.nodes(), key = lambda n: n.addr):
#     if not node.is_simprocedure:
#         node.block.pp()
#         print('============')

