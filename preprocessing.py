#coding:utf-8
from func import get_func_cfgs_c
from func_disasm import get_func_cfgs_disasm
import os
import pickle

if __name__ == '__main__':
	filePath = './data/ftpserver_disassembly.txt' # 输入的二进制/反汇编码的路径
	fileName = os.path.basename(filePath)

	path = "./data/" # 保存ACFG的路径

	inputType = 'disassembly' # 'binary'或'disassembly', 输入为二进制或汇编码文本

	# 二进制，支持x86和arm
	if inputType == 'binary':
		cfgs = get_func_cfgs_c(filePath, fileName)
	
	# 汇编码，采用Binary Ninja的文本排列格式。
	elif inputType == 'disassembly':
		arch = 'arm' # 需要手动设置汇编语言的架构，支持x86和arm
		if arch != 'x86' and arch != 'arm':
			print('Not supported arch!!!')
		else:
			cfgs = get_func_cfgs_disasm(filePath, fileName, arch)

	binary_name = fileName + '.cfg'
	fullpath = os.path.join(path, binary_name)
	print(cfgs)
	print("===================--====================")
	pickle.dump(cfgs, open(fullpath,'wb'))
	print(binary_name)


