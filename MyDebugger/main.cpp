#include <stdio.h>
#include "Debugger.h"

int main()
{
	//1 创建一个调试器对象
	Debugger debugger;
	// 2 建立调试会话
	debugger.Open("demo.exe");
	// 3接收并处理调试信息
	debugger.Run();
	return 0;
}