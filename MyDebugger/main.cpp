#include <stdio.h>
#include "Debugger.h"

int main()
{
	//1 ����һ������������
	Debugger debugger;
	// 2 �������ԻỰ
	debugger.Open("demo.exe");
	// 3���ղ����������Ϣ
	debugger.Run();
	return 0;
}