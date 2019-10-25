#include "BreakPoint.h"

// �ϵ��б��������еĶϵ���Ϣ
vector<BREAKPOINTINFO> BreakPoint::breakPointList;
// ����/�޸� int3-CC����ϵ�
void BreakPoint::SetCCBreakPoint(HANDLE process_handle, LPVOID addr)
{
	// ����ϵ�: �� CPU ��ִ��ָ���ʱ�������� int 3
	// ָ��ͻ����һ�� 3 ���쳣��eip ָ����� int 3
	// ����һ��ָ�ͨ����Ŀ��ָ������ֽ���д�� int 3 
	// ����ʵ������ϵ�

	// 0. ��������ϵ���Ϣ�Ľṹ��
	BREAKPOINTINFO info = { addr };

	// 1. ��ȡĿ���ַԭ�е�OPCODE�����ڻָ�ִ��
	ReadProcessMemory(process_handle, addr, &info.oldOpcode, 1, NULL);

	// 2. ��Ŀ����̵ĵ�ַд�� \xcc �ֽ�
	WriteProcessMemory(process_handle, addr, "\xCC", 1, NULL);

	// 3. �����õĶϵ���ӵ�������
	breakPointList.push_back(info);
}
void BreakPoint::FixCCBreakPoint(HANDLE process_handle, HANDLE thread_handle, LPVOID addr)
{
	// �޸�����ϵ�: ������ϵ���º�,eip ָ�������һ��
	// ��Ҫ�� eip - 1����Ϊ 0xCC ��һ���ֽڣ�Ȼ��Ϊ�˲�Ӱ
	// ������ִ�����̣���Ҫ��ԭ�е� OPCODE �ָ���

	// �����ϵ��б��ҵ���Ҫ�޸��Ķϵ�
	for (int i = 0; i < breakPointList.size(); ++i)
	{
		// ��ַ��ͬ���޸�����������
		if (breakPointList[i].addr == addr)
		{
			// 1. ��ȡ�Ĵ�����Ϣ���� eip - 1
			CONTEXT context = { CONTEXT_CONTROL };
			GetThreadContext(thread_handle, &context);
			context.Eip -= 1;
			SetThreadContext(thread_handle, &context);

			// 2. ��ԭ�е�����д��ָ����λ��
			WriteProcessMemory(process_handle, addr,
				&breakPointList[i].oldOpcode, 1, NULL);

			// 3. ���öϵ�(��־λ����) / ��ͨ�ϵ�(ֱ��ɾ��)
			breakPointList.erase(breakPointList.begin() + i);
			break;
		}
	}
}
// ����TF�����ϵ�
void BreakPoint::SetTFBreakPoint(HANDLE thread_handle)
{
	// �����ϵ�: ͨ�� CPU �� efalgs �ṩ�� TF ��־λ
	// ��ɵġ���CPU��ִ��ָ��֮�󣬻��鵱ǰ�� TF λ
	// �Ƿ�������������ˣ��ͻᴥ��һ�������쳣������
	// �Ὣ TF ��־λ������ 0��

	// 1. ��ȡ���Ĵ�����Ϣ
	CONTEXT context = { CONTEXT_CONTROL };
	GetThreadContext(thread_handle, &context);
	context.EFlags |= 0x100;		// 0x1[8]0[7654]0[3210]
	SetThreadContext(thread_handle, &context);
}
// ����/�޸� DRXӲ���ϵ�
void BreakPoint::SetDRXBreakPoint(HANDLE thread_handle, LPVOID addr, int type, int len)
{
	// Ӳ����ִ�жϵ�����������쳣,���µ�λ�þ����쳣������λ
	// ��,��д�ϵ������ø��ڴ��ַ��,�����������쳣.[��д�ϵ���
	// ���ø��������ڵ����ݵ�]

	// Ӳ���ϵ�: ���ڵ��ԼĴ���ʵ�ֵĶϵ㣬����Ӳ���ϵ�ʹ�õ���
	// Dr0~Dr3 �Լ� Dr7��Dr0~De3 ���������Ҫ���öϵ��λ�ã�
	// Dr7 ���������ϵ�����ͺͶϵ㸲�ǵķ�Χ����Ϊ�����ַ�ĵ�
	// �ԼĴ���ֻ�� 4 ��������Ӳ���ϵ���� 4 ����

	// �� RW ��ֵ�� 0 ��ʱ�򣬱�ʾ����Ӳ��ִ�жϵ㣬��ʱ��Len
	// λ����Ϊ 0��RW ��ʾ�������ͣ�len ��ʾ��Χ��

	// ��ȡ��Ŀ���̵߳ļĴ���
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thread_handle, &context);

	// ��ȡ�� Dr7 �Ĵ�������������Щ�ϵ㱻ʹ��
	PDr7 Dr7 = (PDr7)&context.Dr7;

	// �ж��Ƿ����ã�û�����þ�����
	if (Dr7->L0 == 0)
	{
		// ���û�����Ϣ
		context.Dr0 = (DWORD)addr;
		Dr7->RW0 = type;
		Dr7->LEN0 = len;
		// ���öϵ�
		Dr7->L0 = 1;
	}
	else if (Dr7->L1 == 0)
	{
		context.Dr1 = (DWORD)addr;
		Dr7->RW1 = type;
		Dr7->LEN1 = len;
		Dr7->L1 = 1;
	}
	else if (Dr7->L2 == 0)
	{
		context.Dr2 = (DWORD)addr;
		Dr7->RW2 = type;
		Dr7->LEN2 = len;
		Dr7->L2 = 1;
	}
	else if (Dr7->L3 == 0)
	{
		context.Dr3 = (DWORD)addr;
		Dr7->RW3 = type;
		Dr7->LEN3 = len;
		Dr7->L3 = 1;
	}
	else
	{
		printf("û�п��е�Ӳ���ϵ�λ��!\n");
	}

	SetThreadContext(thread_handle, &context);
}
void BreakPoint::FixDRXBreakPoint(HANDLE thread_handle, LPVOID addr)
{
	// �޸�Ӳ���ϵ��ԭ��: ��Ӳ���ϵ���º�,Dr6����� 4 λ
	// ���������һ��Ӳ���ϵ������,�ҵ����Ӳ���ϵ��Ӧ��
	// LN,�����λ������Ϊ0�Ϳ�����.

	// ��ȡ��Ŀ���̵߳ļĴ���
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thread_handle, &context);

	// ��ȡ�� Dr7 �Ĵ�������������Щ�ϵ㱻ʹ��
	PDr7 Dr7 = (PDr7)&context.Dr7;

	// �ж�����һ���ϵ㴥����
	switch (context.Dr6 & 0xF)
	{
	case 1:
		Dr7->L0 = 0; break;
	case 2:
		Dr7->L1 = 0; break;
	case 4:
		Dr7->L2 = 0; break;
	case 8: Dr7->L3 = 0; break;
	}

	// �������üĴ�����Ϣ
	SetThreadContext(thread_handle, &context);
}


// �ڴ�ϵ�: ���ڷ�ҳ�������õĶϵ�.��һ����ҳ�����ݲ��ɶ�д
// ʱ,�ᴥ���豸�����쳣. ����һ����ַ����Ϊ���ɷ��ʺ�,������
// ��������ҳ�Ͷ����ɷ�����.��ʱ����ͨ���쳣�ṹ�е� infomation 
// ��ȡ�����µ�ԭ��(0,1,8),�ڶ��������ǲ����쳣�ĵ�ַ,ʹ�����
// ���������õĶϵ�λ�ý��бȽ�,�����ҵ�����ϵ�. �������������
// Ҫ���µĵط�,����Ҫ�ָ��ڴ��������,���ҵ���ִ��һ�κ���������
// �ڴ��������,�ظ��Ľ�����һ������,ֱ������һ��Ӧ������i�����õ�
// �ϵ������Ҳ������ĵ�ַ���������õĵ�ַ��ͬ,�ͳɹ�����,�ڼ����õ�
// ���жϵ�,����Ӧ�ñ��û����.