#include <stdio.h>
#include "Debugger.h"
#include "Plugin.h"

int main()
{
	Plugin::LoadPlg();					// ���ز��
	Debugger debugger;					// ��������������
	debugger.Open("target/demo2.exe");	// �������ԻỰ
	debugger.Run();						// ���ղ����������Ϣ
	Plugin::ReleasePlg();				// ж�ز��
	return 0;
}