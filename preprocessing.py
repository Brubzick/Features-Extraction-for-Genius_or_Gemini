#coding:utf-8
from func import *
import os
import pickle
print("test if run")



if __name__ == '__main__':
	filePath = 'dfs_gcc_O0'
	fileName = os.path.basename(filePath)

	print("open a new binary")
	path = ""

	cfgs = get_func_cfgs_c(filePath, fileName)

	binary_name = fileName + '.cfg'
	fullpath = os.path.join(path, binary_name)
	print(cfgs)
	print("===================--====================")
	pickle.dump(cfgs, open(fullpath,'wb'))
	print(binary_name)


