需要安装radare2：https://github.com/radareorg/radare2
在preprocessing.py中设置参数并运行，输出ACFG

目前的一些问题：
1. radare2和Binary Ninja的反汇编结果有些不同，使得提取的特征也会有些许不同，但在主体函数上差距不大。
2. 没有追踪rodata，当字符串较长时，在Binary Ninja的汇编指令文本中不会完整显示，如果想要完整的字符串，需要在.rodata section中追踪对应的数据值。