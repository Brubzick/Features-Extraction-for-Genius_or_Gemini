#coding:utf-8
from func import get_func_cfgs_c
from func_disasm import get_func_cfgs_disasm
from func_asm import get_func_cfgs_asm
import os
import pickle
import argparse
import subprocess

ASM_PARSER_PATH = '../asm-parser/build/bin/asm-parser' # asm-parser的路径
ASM_PARSER_OUT_DIR = ''

if __name__ == '__main__':
	# 输入参数
	parser = argparse.ArgumentParser(description='input parameter')
	parser.add_argument('--input', '-i', type=str, required=True, help='input file path') # 输入的路径
	parser.add_argument('--output', '-o', type=str, help='output file path, the same as the input with a \'.cfg\' postfix by default') # 保存ACFG的路径
	parser.add_argument('--type', '-t', type=str, required=True, help='input type, \'bin\' or \'disasm\' or \'asm\'') # 类型
	parser.add_argument('--arch', '-a', type=str, help='arch of input, \'x86\' or \'arm\', only required if input type is disassembly') # 汇编码的架构

	args = parser.parse_args()

	filePath = args.input # 输入的路径
	fileName = os.path.basename(filePath)

	inputType = args.type # 'bin'或'disasm'或'asm', 输入为二进制或汇编码文本

	haveOutput = False # 是否成功输出

	# 二进制，支持x86和arm
	if inputType == 'bin':
		cfgs = get_func_cfgs_c(filePath, fileName)
		haveOutput = True
	
	# 汇编码，采用Binary Ninja的文本排列格式(即反汇编的结果)。
	elif inputType == 'disasm':
		arch = args.arch # 支持x86和arm
		if arch == None:
			print('The arch[--arch/-a] is required for disassembly. \'x86\' and \'arm\' are supported.')
		elif arch != 'x86' and arch != 'arm':
			print('Not supported arch! Use --help to see the parameters.')
		else:
			cfgs = get_func_cfgs_disasm(filePath, fileName, arch)
			haveOutput = True
	# 汇编码，gcc或clang的汇编结果
	elif inputType == 'asm':
		parser_output = os.path.join(ASM_PARSER_OUT_DIR, fileName+'.txt')
		command = './' + ASM_PARSER_PATH + ' ' + filePath + ' -unused_labels -directives -comment_only  -outputtext > ' + parser_output
		process = subprocess.run(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
		cfgs = get_func_cfgs_asm(parser_output, fileName)
		haveOutput = True

	else:
		print('Wrong type. Use --help to see the parameters.')

	if haveOutput:
		path = args.output # 保存ACFG的路径
		if path == None:
			path = os.path.dirname(filePath)
			binary_name = fileName + '.cfg'
			fullpath = os.path.join(path, binary_name)
		else:
			fullpath = path
		print(cfgs)
		print("===================--====================")
		pickle.dump(cfgs, open(fullpath,'wb'))
		print(binary_name)


