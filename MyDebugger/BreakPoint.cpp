#include "BreakPoint.h"
#include "Capstone.h"

// ��������
vector<BREAKPOINTINFO> BreakPoint::breakPointList;
 MEMBREAKPOINTINFO BreakPoint::m_memBreakPoint;

// ����TF��������ϵ㣬ϵͳ�Զ��޸�
void BreakPoint::SetTFStepIntoBreakPoint(HANDLE thread_handle)
{
	CONTEXT context = { CONTEXT_CONTROL };
	GetThreadContext(thread_handle, &context);
	context.EFlags |= 0x100;		// 0x1[8]0[7654]0[3210]��TFλ��8
	SetThreadContext(thread_handle, &context);
}
// ���õ��������ϵ�
void BreakPoint::SetStepByBreakPoint(HANDLE process_handle,HANDLE thread_handle)
{
	//76FF57E0        56                      push esi
	//76FF57E1        662188CA0F0000          and word ptr[eax + 0xfca], cx
	//76FF57E8        E81308FEFF              call 0x76fd6000
	//76FF57ED        832518DC0B7700          and dword ptr[0x770bdc18], 0

	// 1 ��ȡ��ǰEIP
	CONTEXT context = { CONTEXT_CONTROL };
	GetThreadContext(thread_handle, &context);
	DWORD callAddr = context.Eip;
	// 2 ��ȡcallָ���
	int callLen =  Capstone::GetCallCodeLen(process_handle, LPVOID(callAddr));// �鿴�������루eip���������쳣������
	// 3 �ж��Ƿ���call�����򲽹�
	if (callLen != -1)
	{
		// 4 ��ǰ��ַ+����=��һ��ָ���ַ���漴��int3�ϵ�
		LPVOID addr = LPVOID(callAddr + callLen);
		BreakPoint::SetCCBreakPoint(process_handle, addr);
	}
	// 5 ����call����������һ������
	else
	{
		BreakPoint::SetTFStepIntoBreakPoint(thread_handle);
	}
}
// ����/�޸� int3-CC����ϵ�
void BreakPoint::SetCCBreakPoint(HANDLE process_handle, LPVOID addr)
{
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
	// 0 Ϊ�����б��û��Լ����õ���ӵ��б�OSһ��ʼ�Զ���������֪ͨ���Ǹ�����ӣ�Ϊ�����ֶ���
	// 1 �����ϵ��б��ҵ���Ҫ�޸��Ķϵ�
	for (int i = 0; i < breakPointList.size(); ++i)
	{
		// 2 ��ַ��ͬ���޸�����������
		if (breakPointList[i].addr == addr)
		{
			// 3 ��Ϊ���������쳣����eip - 1
			CONTEXT context = { CONTEXT_CONTROL };
			GetThreadContext(thread_handle, &context);
			context.Eip -= 1;
			SetThreadContext(thread_handle, &context);
			// 4 ��ԭ�е�����д��ָ����λ��
			WriteProcessMemory(process_handle, addr, &breakPointList[i].oldOpcode, 1, NULL);
			// 5 ���öϵ�(��־λ����) / ��ͨ�ϵ�(ֱ��ɾ��)
			breakPointList.erase(breakPointList.begin() + i);
			break;
		}
	}
}
// ����DRXӲ��ִ��/��д�ϵ㡢�޸���������ͨ��
void BreakPoint::SetDrxExeBreakPoint(HANDLE thread_handle, DWORD addr)
{
	// 1 ��ȡĿ���̵߳ļĴ���
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thread_handle, &context);
	// 2 ��ȡ�� Dr7 �Ĵ�������������Щ�ϵ㱻ʹ��
	PDr7 Dr7 = (PDr7)&context.Dr7;
	// 3 �ж��Ƿ����ã�û�����þ�����
	if (Dr7->L0 == 0)
	{
		context.Dr0 = addr;	// �ϵ��ַ
		Dr7->RW0 = 0;			// ���ͣ�ִ��/��д
		Dr7->LEN0 = 0;			// ����
		Dr7->L0 = 1;				// ���öϵ�
	}
	else if (Dr7->L1 == 0)
	{
		context.Dr1 = addr;
		Dr7->RW1 = 0;
		Dr7->LEN1 = 0;
		Dr7->L1 = 1;
	}
	else if (Dr7->L2 == 0)
	{
		context.Dr2 = addr;
		Dr7->RW2 = 0;
		Dr7->LEN2 = 0;
		Dr7->L2 = 1;
	}
	else if (Dr7->L3 == 0)
	{
		context.Dr3 = addr;
		Dr7->RW3 = 0;
		Dr7->LEN3 = 0;
		Dr7->L3 = 1;
	}
	else
	{
		printf("û�п��е�Ӳ���ϵ�λ��!\n");
	}
	// 4 д���޸ĵļĴ�������
	SetThreadContext(thread_handle, &context);
}
void BreakPoint::SetDrxRwBreakPoint(HANDLE thread_handle, DWORD addr,int len)
{
	// 1 ��ȡĿ���̵߳ļĴ���
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thread_handle, &context);
	// 2 ��ȡ�� Dr7 �Ĵ�������������Щ�ϵ㱻ʹ��
	PDr7 Dr7 = (PDr7)&context.Dr7;
	// 3 �Ե�ַ�ͳ��Ƚ��ж��봦��
	if (len == 1)
		addr = addr - addr % 2;
	else if (len == 3)
		addr = addr - addr % 4;
	else if (len > 3)
		return;
	// 3 �ж��Ƿ����ã�û�����þ�����
	if (Dr7->L0 == 0)
	{
		context.Dr0 = addr;		// �ϵ��ַ
		Dr7->RW0 = 3;			// ���ͣ�ִ��/��д
		Dr7->LEN0 = len;		// ����
		Dr7->L0 = 1;			// ���öϵ�
	}
	else if (Dr7->L1 == 0)
	{
		context.Dr1 = addr;
		Dr7->RW1 = 3;
		Dr7->LEN1 = len;
		Dr7->L1 = 1;
	}
	else if (Dr7->L2 == 0)
	{
		context.Dr2 = addr;
		Dr7->RW2 = 3;
		Dr7->LEN2 = len;
		Dr7->L2 = 1;
	}
	else if (Dr7->L3 == 0)
	{
		context.Dr3 = addr;
		Dr7->RW3 = 3;
		Dr7->LEN3 = len;
		Dr7->L3 = 1;
	}
	else
	{
		printf("û�п��е�Ӳ���ϵ�λ��!\n");
	}
	// 4 д���޸ĵļĴ�������
	SetThreadContext(thread_handle, &context);
}
void BreakPoint::FixDrxBreakPoint(HANDLE thread_handle)
{
	// 1 ��ȡ��Ŀ���̵߳ļĴ���
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thread_handle, &context);
	// 2 ��ȡ�� Dr7 �Ĵ�������������Щ�ϵ㱻ʹ��
	PDr7 Dr7 = (PDr7)&context.Dr7;
	// 3 �ж�����һ���ϵ㴥���ˣ������
	switch (context.Dr6 & 0xF)
	{
	case 1:
		Dr7->L0 = 0; break;
	case 2:
		Dr7->L1 = 0; break;
	case 4:
		Dr7->L2 = 0; break;
	case 8:
		Dr7->L3 = 0; break;
	}
	// 4 �������üĴ�����Ϣ
	SetThreadContext(thread_handle, &context);
}
// �ڴ�ϵ����
void BreakPoint::SetMemExeBreakPoint(HANDLE process_handle, HANDLE thread_handle, LPVOID addr)
{
	//���ø��ڴ�ҳΪ���ɷ���
	DWORD dwTempProtect;
	VirtualProtectEx(process_handle,addr,1, PAGE_NOACCESS, &dwTempProtect);
	// �����ַ���Ա�,�������ָ�
	m_memBreakPoint.addr = addr;
	m_memBreakPoint.oldAttribute = dwTempProtect;
}
bool BreakPoint::WhenMemExeBreakPoint(HANDLE process_handle, HANDLE thread_handle, LPVOID addr)
{
	bool isFind = false;
	// ���˵�ַ���ǵ������õĵ�ַ
	if (addr != m_memBreakPoint.addr)
	{
		// ��ԭ�е����Իָ�
		DWORD dwTempProtect;
		VirtualProtectEx(process_handle, addr, 1, m_memBreakPoint.oldAttribute, &dwTempProtect);
		// ����һ��TF�����ϵ�
		SetTFStepIntoBreakPoint(thread_handle);
		// ����֮������������һ���ڴ�ϵ�
		//VirtualProtectEx(process_handle, addr, 1, PAGE_NOACCESS, &dwTempProtect);
		isFind = false;
	}
	// ����ǰͣ�µĵ�ַ�����ǵ������õĵ�ַ�����޸�
	else
	{
		DWORD dwTempProtect;
		VirtualProtectEx(process_handle, addr, 1, m_memBreakPoint.oldAttribute, &dwTempProtect);
		isFind = true;
	}
	return isFind;

}
// �����ϵ����
void BreakPoint::SetConditionBreakPoint(HANDLE process_handle, HANDLE thread_handle, LPVOID addr, int eax)
{
	SetCCBreakPoint(process_handle, addr);
}
bool BreakPoint::WhenConditionBreakPoint(HANDLE process_handle, HANDLE thread_handle, int eax,LPVOID addr)
{
	bool isFind = false;

	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;// �Ӵ˱�ʶ��ʲô���͵Ļ���
	GetThreadContext(thread_handle, &ct);
	if (ct.Eax != eax)
	{
		BreakPoint::FixCCBreakPoint(process_handle, thread_handle, addr);
		SetTFStepIntoBreakPoint(thread_handle);
		isFind = false;
	}
	else
	{
		BreakPoint::FixCCBreakPoint(process_handle, thread_handle, addr);
		isFind = true;
	}
	return isFind;
}