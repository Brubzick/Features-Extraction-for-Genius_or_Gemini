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
import os.path
import r2pipe
from contextlib import contextmanager
import hashlib


jump_ops = [
    'jz ', 'jnz ', 'jne ', 'jb ', 'jc ', 'jnb ',
    'jnc ', 'ja ', 'jnbe ', 'jae ', 'jna ', 'jbe ',
    'jng ', 'jle ', 'jg ', 'je '
]


@contextmanager
def make_r2(binary_path):
    r2 = r2pipe.open(binary_path)
    try:
        yield r2 # 迭代
    finally:
        print('r2 quit!')
        r2.quit()


class R2Helper:
    def __init__(self, file_path):
        self.file_path = file_path

    def file_md5(self, block_size=2 ** 10):
        """
        md5 file
        """
        md5 = hashlib.md5()
        with open(self.file_path, "rb") as f:
            while True:
                data = f.read(block_size)
                if not data:
                    break
                md5.update(data)
        return md5.hexdigest()

    def calc_cfg_info(self):
        """
        计算被测对象的所有函数首地址、各函数中所有指令地址、函数基本块、控制流图的边、以及call信息四部分
        """
        res = []
        with make_r2(self.file_path) as r2:
            r2.cmd("aaa")
            # r2.cmd("e anal.vars=false;e anal.hasnext=true;afr;aac")
            # 记录所有函数首地址
            func_offset_list = [(one['offset'],one['name']) for one in r2.cmdj("aflj")]
            # 遍历函数首地址，获取指令地址
            for offset, func_name in func_offset_list:
                print("Function entrypoints {0x%x, }:" %offset)
                r2.cmd("s 0x{0:x}".format(offset))
                pdf = r2.cmdj("pdfj")
                cmd_addr_list = [one['offset'] for one in pdf['ops']]
                print(', '.join(["0x%x" %one for one in cmd_addr_list]))
                afb = r2.cmdj("afbj")
                bb_addr_list = []
                # 切割基本快
                for i, one in enumerate(afb):
                    bb_addr = one['addr']
                    idx = cmd_addr_list.index(bb_addr)
                    if i == len(afb) - 1:
                        bb_addr_list.append((bb_addr, cmd_addr_list[idx:]))
                    else:
                        next_idx = cmd_addr_list.index(afb[i+1]['addr'])
                        bb_addr_list.append((bb_addr, cmd_addr_list[idx:next_idx]))
                for bb_addr, addr_list in bb_addr_list:
                    print("[0x%x: (%s)]" % (bb_addr, ', '.join(['0x%x' % one for one in addr_list])))
                # 划分边
                edges = []
                for one in afb:
                    if one['addr'] and one.get('jump'):
                        edges.append((one['addr'], one['jump']))
                    if one['addr'] and one.get('fail'):
                        edges.append((one['addr'], one['fail']))
                for edge in edges:
                    print("0x%x -> 0x%x" % edge)
                # 在上述基本块的基础上再按照call方法切分一次基本块
                call_bb_addr_list = []
                call_edges = []
                for bb_addr, addr_list in bb_addr_list:
                    start = addr_list[0]
                    idx = 0
                    cut_edges = [(beg, end) for beg, end in edges if beg == bb_addr]
                    for one in pdf['ops']:
                        if one['offset'] not in addr_list or one['offset'] < start:
                            continue
                        if one['opcode'].startswith('call'):
                            end_idx = addr_list.index(one['offset'])
                            call_bb_addr_list.append((start, addr_list[idx: end_idx + 1]))
                            # 检查边是否别切割，如果被切割需要确认边属于哪个基本块
                            if cut_edges:
                                ops = [one['opcode'] for one in pdf['ops'] if one['offset'] in addr_list[idx: end_idx + 1]]
                                for op in ops:
                                    if any([op.startswith(jp) for jp in jump_ops]):
                                        jump_addr = int(op.split(' ')[1].strip(), 16)
                                        for i in range(len(cut_edges)):
                                            if jump_addr == cut_edges[i][1]:
                                                call_edges.append((start, jump_addr))
                                                cut_edges.pop(i)
                            if end_idx < len(addr_list) - 1:
                                # 如果切割了，需要加一条边
                                call_edges.append((start, addr_list[end_idx + 1]))
                                start = addr_list[end_idx + 1]
                                idx = end_idx + 1
                            else:
                                start = None
                    if start:
                        call_bb_addr_list.append((start, addr_list[idx:]))
                        if cut_edges:
                            ops = [one['opcode'] for one in pdf['ops'] if one['offset'] in call_bb_addr_list[-1][1]]
                            for op in ops:
                                if any([op.startswith(jp) for jp in jump_ops]):
                                    jump_addr = int(op.split(' ')[1].strip(), 16)
                                    for i in range(len(cut_edges)):
                                        try:
                                            cut_edge = cut_edges[i]
                                            if jump_addr == cut_edge[1]:
                                                call_edges.append((start, jump_addr))
                                                cut_edges.pop(i)
                                        except:
                                            break
                    if cut_edges:
                        call_edges.extend(cut_edges)
                for bb_addr, addr_list in call_bb_addr_list:
                    print("=================[0x%x: (%s)]" % (bb_addr, ', '.join(['0x%x' % one for one in addr_list])))
                for edge in call_edges:
                    print("=====================0x%x -> 0x%x" % edge)
                # 第三部分，构建调用块
                call_res_list = []
                call_list = [one for one in pdf['ops'] if one['opcode'].startswith('call')]
                for call in call_list:
                    try:
                        begin = int(call['opcode'].replace('call ', '').strip(), 16)
                        end = cmd_addr_list[cmd_addr_list.index(call['offset']) + 1]
                    except:
                        continue
                    call_res_list.append((call['offset'], begin, end))
                for call_addr, begin, end in call_res_list:
                    print("0x%x: [0x%x-0x%x]" % (call_addr, begin, end))
                res.append({
                    # 'cmd_addr_list': cmd_addr_list,
                    'bb_addr_list': bb_addr_list,
                    'call_bb_addr_list': call_bb_addr_list,
                    'edges': edges,
                    'call_edges': call_edges,
                    'call_res_list': call_res_list,
                    'func_name': func_name,
                    'pdf': pdf,
                    'offset': offset
                })
        return res

    def save_cfg_file(self):
        out_ida_orig_file = "%s.ida_orig" % self.file_md5()
        out_ida_file = "%s.ida" % self.file_md5()
        r2_res = sorted(self.calc_cfg_info(), key=lambda x: x['offset'])
        with open(out_ida_orig_file, 'w+') as f:
            with open(out_ida_file, 'w+') as fa:
                for tmp in r2_res:
                    # cmd_addr_list = r2_res[offset]['cmd_addr_list']
                    offset = tmp['offset']
                    bb_addr_list = tmp['bb_addr_list']
                    edges = tmp['edges']
                    call_edges = tmp['call_edges']
                    call_res_list = tmp['call_res_list']
                    call_bb_addr_list = tmp['call_bb_addr_list']
                    func_name = tmp['func_name']
                    pdf = tmp['pdf']
                    # 1.write eps and name, {0x80485f0;__libc_csu_init}
                    f.write('-------------------\n')
                    fa.write('-------------------\n')
                    # TODO 此处的函数名为了于IDA pro保持一致，暂时移除sym和dbg等字符
                    f.write('{0x%x;%s}\n' % (offset, func_name.replace('sym.imp.', '').replace('sym.', '').replace('dbg.', '')))
                    fa.write('{0x%x;%s}\n' % (offset, func_name.replace('sym.imp.', '').replace('sym.', '').replace('dbg.', '')))
                    # 2.write blocks
                    for bb_addr, addr_list in bb_addr_list:
                        f.write("[0x%x;(%s);(%s);(%s)]\n" % (
                            bb_addr, ','.join(['0x%x' % one for one in addr_list]),
                            ','.join(["0x%x" % edge[1] for edge in edges if edge[0] == bb_addr]),
                            ','.join(["0x%x-0x%x-0x%x" % (a, b, c) for a, b, c in call_res_list if a in addr_list])
                        ))
                        # 3.write inst, (0x80485f0;push    ebp;55;0x80485f0;__libc_csu_init)
                        for one in pdf['ops']:
                            addr = one['offset']
                            if addr not in addr_list:
                                continue
                            name = pdf['name']
                            opcode = one['opcode']
                            _bytes = one['bytes']
                            f.write('(0x%x;%s;%s;0x%x;%s)\n' % (addr, opcode, _bytes, bb_addr, name))
                        f.write('\n')
                    # write blocks
                    for bb_addr, addr_list in call_bb_addr_list:
                        fa.write("[0x%x;(%s);(%s);(%s)]\n" % (
                            bb_addr, ','.join(['0x%x' % one for one in addr_list]),
                            ','.join(["0x%x" % edge[1] for edge in call_edges if edge[0] == bb_addr]),
                            ','.join(["0x%x-0x%x-0x%x" % (a, b, c) for a, b, c in call_res_list if a in addr_list])
                        ))
                        # 3.write inst, (0x80485f0;push    ebp;55;0x80485f0;__libc_csu_init)
                        for one in pdf['ops']:
                            addr = one['offset']
                            if addr not in addr_list:
                                continue
                            name = pdf['name']
                            opcode = one['opcode']
                            _bytes = one['bytes']
                            fa.write('(0x%x;%s;%s;0x%x;%s)\n' % (addr, opcode, _bytes, bb_addr, name))
                        fa.write('\n')
                    f.write('\n')
                    fa.write('\n')

    def generate_dot_file(self):
        with make_r2(self.file_path) as r2:
            r2.cmd("aaa")
            func_list = [one['offset'] for one in r2.cmdj("aflj")]
            addr_dict = {"0x0%x" %one: i for i, one in enumerate(sorted(func_list))}
            # 初始化 .dot 文件内容
            dot_content = r2.cmd("agCdj")
            # 此处的函数名为了于IDA pro保持一致，暂时移除sym和dbg等字符
            dot_content = dot_content.replace('sym.imp.', '').replace('sym.', '').replace('dbg.', '')
            edge_list = []
            new_dot_content = ''
            for edge in dot_content.split('\n'):
                # print('edge', edge)
                if '->' in edge:
                    edge_list.append(edge)
                else:
                    edge = edge.replace("[label", '[color="#000000", fillcolor="#000000", fontcolor="#ffffff", label')
                    new_dot_content += edge + '\n'
            # for edge in edge_list:
            #     new_dot_content += edge + '\n'
            new_dot_content = new_dot_content.replace('}', '\n'.join(edge_list) + '\n}')
            new_dot_content = new_dot_content.replace('\" URL', '\\l\", URL')
            # # 将radare2 dot数据中的16进制地址信息转化为索引
            for addr, idx in addr_dict.items():
                new_dot_content = new_dot_content.replace('\"%s\"' % addr, '%d' % idx)
            print('new_dot_content', new_dot_content)
            # 将内容写入 .dot 文件
            out_dot_file = "%s.dot" % self.file_md5()
            with open(out_dot_file, 'w') as f:
                f.write(new_dot_content)


if __name__ == "__main__":
    r = R2Helper("dfs_gcc_O0")
    r.save_cfg_file()
    r.generate_dot_file()








