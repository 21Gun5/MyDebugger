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
demo2.exe
	main: 
	CMP: 4c184a
	CALL printf: 4c1859
*/