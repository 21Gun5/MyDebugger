#include <stdio.h>
#include "Debugger.h"

int main()
{
	//1 ����һ������������
	Debugger debugger;
	// 2 �������ԻỰ
	debugger.Open("demo2.exe");
	// 3 ���ղ����������Ϣ
	debugger.Run();
	return 0;
}

/*
demo2.exe
	main: 
	CMP: 4c184a
	CALL printf: 4c1859
*/