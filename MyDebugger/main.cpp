#include <stdio.h>
#include "Debugger.h"
#include "Plugin.h"

int main()
{
	Plugin::LoadPlg();					// 加载插件
	Debugger debugger;					// 创建调试器对象
	debugger.Open("target/demo2.exe");	// 建立调试会话
	debugger.Run();						// 接收并处理调试信息
	Plugin::ReleasePlg();				// 卸载插件
	return 0;
}