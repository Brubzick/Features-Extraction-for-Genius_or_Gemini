#coding:utf-8
from func import *
import os
import pickle

if __name__ == '__main__':
	filePath = './data/example' # 输入的二进制路径
	fileName = os.path.basename(filePath)

	path = "./data/" # 保存ACFG的路径

	cfgs = get_func_cfgs_c(filePath, fileName)

	# binary_name = fileName + '.cfg'
	# fullpath = os.path.join(path, binary_name)
	# print(cfgs)
	# print("===================--====================")
	# pickle.dump(cfgs, open(fullpath,'wb'))
	# print(binary_name)

	# with open('./data/example.cfg', 'rb') as f:
	# 	cfgs2 = pickle.load(f)

	# print(len(cfgs.raw_graph_list))
	# for cfg in cfgs.raw_graph_list:
	# 	print(cfg.funcname)
	# 	print(cfg.discovre_features)
	# 	# for node in cfg.old_g:
	# 	# 	print(cfg.old_g.nodes[node]['label'])
	# print('================================')
	# print(len(cfgs2.raw_graph_list))
	# for cfg in cfgs2.raw_graph_list:
	# 	print(cfg.funcname)
	# 	print(cfg.discovre_features)


