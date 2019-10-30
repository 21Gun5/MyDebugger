#include <stdio.h>
#include "Debugger.h"
#include "Plugin.h"

int main()
{
	Plugin::LoadPlg();			// ���ز��
	Debugger debugger;			// ��������������
	debugger.Open("target/demo2.exe");	// �������ԻỰ
	debugger.Run();				// ���ղ����������Ϣ
	Plugin::ReleasePlg();		// ж�ز��
	return 0;
}

/*
ƫ��Ϊ1184a����ʱ��䣬ƫ��+exe �ļ��ػ�ַ���CMP��
demo2.exe
	main: 
	CMP: 2f184a
	CALL printf: 2f1859

���������ϵ㣺cbp b31859 4
demo.exe
	mem 778ddc7c д��ϵ�
	mem 778dda44 ��ȡ�ϵ�
	mem 7786e9e6 ִ�жϵ�
*/