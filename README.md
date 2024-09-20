需要安装radare2：https://github.com/radareorg/radare2
需要安装asm-parser: https://github.com/compiler-explorer/asm-parser

在preprocessing.py中，将ASM_PARSER_PATH设置为：asm-parser所在目录/build/bin/asm-parser
ASM_PARSER_OUT_DIR为asm-parser的输出目录，可自定义设置，默认为和输入的汇编码文件同一目录。

其余参数都为传参
运行：python preprocessing.py -i 输入的路径 -o 输出的路径 -t 输入的类型 -a 输入的架构

一共有四个传参，可以用 -h/--help 查看具体信息。
-i/--input 为输入文件的路径，是必需的参数。
-t/--type 为输入的文件类型（'bin', 'asm', 'disasm'），是必需的参数。
-o/--output 为输出的文件路径，非必需，默认为输入的文件路径加'.cfg'后缀。
-a 为输入的架构（'x86', 'arm'），仅在输入类型为'disasm'时需要，其它情况下没用，不需要。

对于所有输入类型，都只支持x86和arm架构

输入类型为 'bin'（二进制）时，使用radare2分析并抽取特征。
输入类型为 'disasm'（反汇编）时，使用Binary Ninja的反汇编结果（的排列形式的汇编码文本）作为输入。
输入类型为 'asm' （汇编码）时，使用gcc或clang的汇编结果（的排列形式的汇编码文本）作为输入（gcc -S / clang -S）

在使用'asm'作为输入时，汇编码首先会经过asm-parser处理（使用python的subprocess库在脚本中执行了shell命令），处理后的汇编码会输出到ASM_PARSER_OUT_DIR设置的目录，然后该输出会作为输入继续处理并提取特征。
