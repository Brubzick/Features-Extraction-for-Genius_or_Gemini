"""

radare2替换IDA pro生成被测对象的CFG/CG等信息

pip3 install r2pipe

# radare2命令
## 分析全部  aaa
## 查看函数列表以及函数首地址 afl
## 查看函数调用关系   VV
## 查看函数交叉引用   afx
## 跳转到指定地址  s + 指定地址/函数名
## 导出控制流图  agf my_function_name.dot
## 将dot转化为图片 dot -Tpng my_function_name.dot -o my_function_name.png
## 查看整个函数的汇编码  pdf
## 获取函数基本快  afb

"""
import r2pipe
from contextlib import contextmanager

jump_ops = [
    'jz ', 'jnz ', 'jne ', 'jb ', 'jc ', 'jnb ',
    'jnc ', 'ja ', 'jnbe ', 'jae ', 'jna ', 'jbe ',
    'jng ', 'jle ', 'jg ', 'je '
]


@contextmanager
def make_r2(binary_path):
    r2 = r2pipe.open(binary_path)
    try:
        yield r2
    finally:
        print('r2 quit!')
        r2.quit()

class R2Helper:
    def __init__(self, file_path):
        self.file_path = file_path

    def calc_cfg_info(self):
        """
        计算被测对象的所有函数首地址、各函数中所有指令地址、函数基本块、控制流图的边、以及call信息四部分
        """
        res = []
        with make_r2(self.file_path) as r2:
            r2.cmd("aaa")
            # r2.cmd("e anal.vars=false;e anal.hasnext=true;afr;aac")
            # 记录所有函数首地址
            addr2name = {}
            func_offset_list = []
            for one in r2.cmdj('aflj'):
                func_offset_list.append((one['offset'],one['name']))
                addr2name[one['offset']] = one['name']
            
            # 遍历函数首地址，记录被调用情况
            addr2called = {}
            for offset, func_name in func_offset_list:
                r2.cmd("s 0x{0:x}".format(offset))
                cg = r2.cmdj('afxj')
                for reference in cg:
                    if reference['type'] == 'CALL':
                        called = reference['to']
                        if addr2called.get(called):
                            addr2called[called] += 1
                        else:
                            addr2called[called] = 1

            # 遍历函数首地址，获取指令地址
            for offset, func_name in func_offset_list:
                r2.cmd("s 0x{0:x}".format(offset))
                pdf = r2.cmdj("pdfj")
                cmd_addr_list = [one['offset'] for one in pdf['ops']]
                afb = r2.cmdj("afbj")
                bb_addr_list = []
                # 函数的参数
                callArgs = r2.cmdj('afvj')
                argsNum = len(callArgs['reg'])

                # 函数的调用和被调用
                if addr2called.get(offset):
                    calledNum = addr2called[offset]
                else:
                    calledNum = 0
                cg = r2.cmdj('afxj')
                callNum = 0
                for reference in cg:
                    if reference['type'] == 'CALL':
                        callNum += 1             

                # 切割基本快
                for i, one in enumerate(afb):
                    bb_addr = one['addr']
                    idx = cmd_addr_list.index(bb_addr)
                    if i == len(afb) - 1:
                        bb_addr_list.append((bb_addr, cmd_addr_list[idx:]))
                    else:
                        next_idx = cmd_addr_list.index(afb[i+1]['addr'])
                        bb_addr_list.append((bb_addr, cmd_addr_list[idx:next_idx]))

                # 划分边
                edges = []
                for one in afb:
                    if one['addr'] and one.get('jump'):
                        edges.append((one['addr'], one['jump']))
                    if one['addr'] and one.get('fail'):
                        edges.append((one['addr'], one['fail']))

                res.append({
                    # 'cmd_addr_list': cmd_addr_list,
                    'bb_addr_list': bb_addr_list,
                    'edges': edges,
                    'func_name': func_name,
                    'pdf': pdf,
                    'offset': offset,
                    'argsNum': argsNum,
                    'calledNum': calledNum,
                    'callNum': callNum
                })
        return res


