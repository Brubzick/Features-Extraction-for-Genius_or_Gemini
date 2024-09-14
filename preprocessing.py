#coding:utf-8
from func import get_func_cfgs_c
from func_disasm import get_func_cfgs_disasm
import os
import pickle
import argparse

if __name__ == '__main__':
	# 输入参数
	parser = argparse.ArgumentParser(description='input parameter')
	parser.add_argument('--input', '-i', type=str, required=True, help='input file path')
	parser.add_argument('--output', '-o', type=str, help='output file path, the same as the input dir by default')
	parser.add_argument('--type', '-t', type=str, required=True, help='input type, \'binary\' or \'disassembly\'')
	parser.add_argument('--arch', '-a', type=str, help='arch of input, \'x86\' or \'arm\', only required if input type is disassembly')
	args = parser.parse_args()

	filePath = args.input # 输入的二进制路径
	fileName = os.path.basename(filePath)

	path = args.output # 保存ACFG的路径
	if path == None:
		path = os.path.dirname(filePath)

	inputType = args.type # 'binary'或'disassembly', 输入为二进制或汇编码文本

	haveOutput = False # 是否成功输出

	# 二进制，支持x86和arm
	if inputType == 'binary':
		cfgs = get_func_cfgs_c(filePath, fileName)
		haveOutput = True
	
	# 汇编码，采用Binary Ninja的文本排列格式。
	elif inputType == 'disassembly':
		arch = args.arch # 支持x86和arm
		if arch == None:
			print('arch is required for disassembly. \'x86\' and \'arm\' are supported.')
		elif arch != 'x86' and arch != 'arm':
			print('Not supported arch!!!')
		else:
			cfgs = get_func_cfgs_disasm(filePath, fileName, arch)
			haveOutput = True
	else:
		print('Wrong type. Use --help to see the parameters.')

	if haveOutput:
		binary_name = fileName + '.cfg'
		fullpath = os.path.join(path, binary_name)
		print(cfgs)
		print("===================--====================")
		pickle.dump(cfgs, open(fullpath,'wb'))
		print(binary_name)


