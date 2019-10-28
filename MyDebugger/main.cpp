#include <stdio.h>
#include "Debugger.h"

int main()
{
	//1 创建一个调试器对象
	Debugger debugger;
	// 2 建立调试会话
	debugger.Open("demo2.exe");
	// 3 接收并处理调试信息
	debugger.Run();
	return 0;
}

/*
偏移为1184a，有时会变，偏移+exe 的加载基址便得CMP的
demo2.exe
	main: 
	CMP: 2f184a
	CALL printf: 2f1859

设置条件断点：cbp b31859 4
demo.exe
	mem 778ddc7c 写入断点
	mem 778dda44 读取断点
	mem 7786e9e6 执行断点
*/