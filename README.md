提取特征用于输入基于Genius或Gemini的神经网络模型

Genius: https://www.cs.ucr.edu/~heng/pubs/genius-ccs16.pdf

Gemini: https://arxiv.org/pdf/1708.06525

需要安装radare2：https://github.com/radareorg/radare2

需要安装asm-parser: https://github.com/compiler-explorer/asm-parser

在preprocessing.py中，将ASM_PARSER_PATH设置为：asm-parser所在目录/build/bin/asm-parser
ASM_PARSER_OUT_DIR为asm-parser的输出目录，可自定义设置，默认为和输入的汇编码文件同一目录。

其余参数都为传参
运行：python preprocessing.py -i 输入的路径 -o 输出的路径 -t 输入的类型 -a 输入的架构

一共有三个传参，可以用 -h/--help 查看具体信息。
-i/--input 为输入文件的路径，是必需的参数。
-t/--type 为输入的文件类型（'bin', 'asm', 'ida', 'windbg'），是必需的参数。
-o/--output 为输出的文件路径，非必需，默认为输入的文件路径加'.cfg'后缀。

对于所有输入类型，都只支持x86和arm架构

输入类型为 'bin'（二进制）时，使用radare2分析并抽取特征。
输入类型为 'asm' （汇编码）时，使用gcc或clang的汇编结果（的排列形式的汇编码文本）作为输入（gcc -S / clang -S），最好是O0优化等级的情况（即默认优化等级）。
输入类型为 'ida'时，使用ida的反汇编结果（的排列形式的汇编码文本）作为输入（ida导出为<font color=red>LST文件</font>）。
输入类型为 'windbg'时，使用ida的反汇编结果（的排列形式的汇编码文本）作为输入。

在使用'asm'作为输入时，汇编码首先会经过asm-parser处理（使用python的subprocess库在脚本中执行了shell命令），处理后的汇编码会输出到ASM_PARSER_OUT_DIR设置的目录，然后该输出会作为输入继续处理并提取特征。

Used to extract features from binary or assembly for NN based on Genius or Gemini.

Genius: https://www.cs.ucr.edu/~heng/pubs/genius-ccs16.pdf

Gemini: https://arxiv.org/pdf/1708.06525

radare2: https://github.com/radareorg/radare2

asm-parser: https://github.com/compiler-explorer/asm-parser

In preprocessing.py, set ASM_PARSER_PATH and ASM_PARSER_OUT_DIR.

Run 'python preprocessing.py -i [inputPath] -o [outputPath] -t [inputType]'

Use -h/--help to see details

x86 and arm are supported.

'bin' takes binary as input (x86 or arm).

'ida' takes IDA disassembly form text as input (x86).

'windbg' takes WinDbg disassembly form text as input (x86).

'asm' takes assembly form of gcc or clang (gcc -S / clang -S). O0 (default) optimization is preferred (x86 or arm).