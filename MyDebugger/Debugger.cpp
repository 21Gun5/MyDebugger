#include <iostream>
#include "Debugger.h"
#include "Capstone.h"
#include "Keystone.h"
#include "BreakPoint.h"
#include "Plugin.h"
#include <stdio.h>
#include <psapi.h>
#include <strsafe.h>
#include <tchar.h>

#include <winternl.h>
#pragma comment(lib,"ntdll.lib")

// �򿪲����쳣�Ľ���/�̵߳ľ��
void Debugger::OpenHandles()
{
	m_threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, m_debugEvent.dwThreadId);
	m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_debugEvent.dwProcessId);
}
// �رղ����쳣�Ľ���/�̵߳ľ��
void Debugger::CloseHandles()
{
	CloseHandle(m_threadHandle);
	CloseHandle(m_processHandle);
}

// �򿪱����Խ���
void Debugger::Open(LPCSTR file_Path)
{
	// ������̴����ɹ������ڽ��ս����̵߳ľ����id
	//PROCESS_INFORMATION processInfo = { 0 };
	STARTUPINFOA startupInfo = { sizeof(STARTUPINFOA) };

	// ���Է�ʽ�������̣��õ������Խ���
	BOOL result = CreateProcessA(file_Path, nullptr, NULL, NULL, FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL, NULL,
		&startupInfo, //ָ�����̵�����������
		&m_processInfo);//�����½��̵���Ϣ

	// DEBUG_PROCESS ��ʾ�Ե��Եķ�ʽ��Ŀ����̣�����
	//	�������Դ����µĽ���ʱ��ͬ�������½��̵ĵ�����Ϣ��
	// DEBUG_ONLY_THIS_PROCESS ֻ����Ŀ����̣�������
	//	Ŀ����̴������µĽ���
	// CREATE_NEW_CONSOLE ��ʾ�´����� CUI �����ʹ��һ
	//	�������Ŀ���̨���У������д�ͺ͵��������ÿ���̨

	//AntiAntiDebug2(m_processInfo.hProcess);


	// ������̴����ɹ��ˣ��͹رն�Ӧ�ľ������ֹ���й¶
	if (result == TRUE)
	{
		CloseHandle(m_processInfo.hThread);
		CloseHandle(m_processInfo.hProcess);
	}

	// ��ʼ����������棬������ʹ�÷����ĺ���ǰ����
	Capstone::Init();
}
// ��������¼�
void Debugger::Run()
{
	// ���ܣ��ȴ������¼�����������¼����ظ�������ϵͳ

	// �ȴ������¼�����ͨ��ѭ�����ϵĴӵ��Զ����л�ȡ��������Ϣ
	while (WaitForDebugEvent(&m_debugEvent, INFINITE))
	{
		// �򿪶�Ӧ�Ľ��̺��̵߳ľ��
		OpenHandles();
		// �������ͣ��ֱ�������¼�
		switch (m_debugEvent.dwDebugEventCode)//dwDebugEventCode ��ʶ�¼�����
		{
			// �쳣�����¼�
		case EXCEPTION_DEBUG_EVENT:
			OnExceptionEvent();
			break;

		}
		// Ϊ�˷�ֹ���й¶��Ӧ�ùر�
		CloseHandles();

		// �������ϵͳ���ص�ǰ�Ĵ�����: �����еĽ��� id  ��
		// �߳� id ������ͨ�� WaitForDebugEvent ��ȡ���� id��
		// ��Ϊ�����ԵĿ����Ƕ�������еĶ���̣߳���Ҫ�������֡�
		// �������Ǵ�����������ɹ��˾�Ӧ�÷��� DBG_CONTINUE��
		// ���账��ʧ�ܣ�����û�д����Ӧ�÷��� DBG_EXCEPTION_NOT_HANDLED   

		// �ظ�������ϵͳ
		ContinueDebugEvent(m_debugEvent.dwProcessId, m_debugEvent.dwThreadId, m_continueStatus);
	}
}
// �����쳣�¼�
void Debugger::OnExceptionEvent()
{
	// 1 ��ȡ�쳣���͡�������ַ
	DWORD exceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
	LPVOID exceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	// 2 ����ͬ���쳣����
	switch (exceptionCode)
	{
		// 1 �����쳣��DRxӲ���ϵ㡢TF�����ϵ㶼����
	case EXCEPTION_SINGLE_STEP:
	{
		switch (m_singleStepType)
		{
		case Debugger::NORMAL:
			printf("\n================================ �쳣��Ϣ ==================================\n");
			printf("����: %08X\n��ַ: %p\n", exceptionCode, exceptionAddr);
			printf("����: �����ϵ㷢��\n");
			break;
		case Debugger::DRXEXE:
			printf("\n================================ �쳣��Ϣ ==================================\n");
			printf("����: %08X\n��ַ: %p\n", exceptionCode, exceptionAddr);
			printf("����: Ӳ��ִ�жϵ㷢��\n");
			BreakPoint::FixDrxBreakPoint(m_threadHandle);
			//return;
			break;
		case Debugger::DRXRW:
			printf("\n================================ �쳣��Ϣ ==================================\n");
			printf("����: %08X\n��ַ: %p\n", exceptionCode, exceptionAddr);
			printf("����: Ӳ����д�ϵ㷢��\n");
			BreakPoint::FixDrxBreakPoint(m_threadHandle);
			break;
		case Debugger::MEM:
			// �������ڴ�ϵ�
			DWORD dwTempProtect;
			VirtualProtectEx(m_processHandle, m_memBreakPointAddr, 1, PAGE_NOACCESS, &dwTempProtect);
			return;
		case Debugger::CONDITION:
			// �����������ϵ㣬��INT3����ϵ�
			BreakPoint::SetConditionBreakPoint(m_processHandle, m_threadHandle, m_ConditionBreakPointAddr, m_eax);
			return;
		case Debugger::CC:
			// �����������ϵ㣬��INT3����ϵ�
			BreakPoint::SetCCBreakPoint(m_processHandle, m_eternalPointAddr);
			return;
		default:
			break;
		}
		break;
	}
	// 2 �ϵ��쳣: int3����ϵ�
	case EXCEPTION_BREAKPOINT:
	{
		// 1 �����ϵ�
		if (m_isConditonSet)
		{
			bool isFind = BreakPoint::WhenConditionBreakPoint(m_processHandle, m_threadHandle, m_eax, LPVOID(exceptionAddr));
			// ���������������ӡ���޸�������ִ��
			if (isFind)
			{
				printf("\n================================ �쳣��Ϣ ==================================\n");
				printf("����: %08X\n��ַ: %p\n", exceptionCode, exceptionAddr);
				printf("����: eax=%d �������ϵ㷢��\n", m_eax);
				m_isConditonSet = false;
				break;
			}
			// �������㣬���˳�������
			else
			{
				return;
			}
		}
		printf("\n================================ �쳣��Ϣ ==================================\n");
		printf("����: %08X\n��ַ: %p\n", exceptionCode, exceptionAddr);
		// 2 ϵͳ�ϵ㷢������Ϊ0��û�������������������
		if (!m_isSysBPHappened)
		{
			printf("����: ��һ���쳣�¼�����ϵͳ�ϵ㷢��\n");
			m_isSysBPHappened = true;
			// ע�⣬��ϵͳ�ϵ㷢��֮�����޸�PEB��ֵ
			// �����Խ�������֮ǰ��ϵͳ�ȼ��PEB��BeingDebugֵ�������������ϵͳ�ϵ�
			// ��֮ǰ���޸ģ�ϵͳ��ⲻ������ͣ������
			AntiAntiDebug(m_processHandle);

			AntiAntiDebug2(m_processHandle);//hookAPI �������ԣ�δ�ɹ�
			BreakPoint::FixCCBreakPoint(m_processHandle, m_threadHandle, exceptionAddr);
			break;
		}
		// 3 ��ͨ����ϵ�
		else
		{
			printf("����: int3����ϵ㷢��\n");
			BreakPoint::FixCCBreakPoint(m_processHandle, m_threadHandle, exceptionAddr);
			// ����һ��TF�����ϵ�
			BreakPoint::SetTFStepIntoBreakPoint(m_threadHandle);
			m_singleStepType = CC;
			break;
		}
	}
	// 3 �����쳣���ڴ���ʶϵ�
	case EXCEPTION_ACCESS_VIOLATION:
	{
		DWORD type = m_debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[0];//��������0/1/8
		DWORD memAccessAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1];//������ַ
		bool isFind = BreakPoint::WhenMemExeBreakPoint(m_processHandle, m_threadHandle, LPVOID(memAccessAddr));
		// ����ҵ���ַ�����ӡ��Ϣ��break
		if (isFind)
		{
			printf("\n================================ �쳣��Ϣ ==================================\n");
			printf("����: %08X\n��ַ: %p\n", exceptionCode, memAccessAddr);
			// ��ӡ��������
			switch (type)
			{
			case 0:
				printf("����: �ڴ��ȡ�ϵ㷢��\n");
				break;
			case 1:
				printf("����: �ڴ�д��ϵ㷢��\n");
				break;
			case 8:
				printf("����: �ڴ�ִ�жϵ㷢��\n");
				break;
			default:
				break;
			}
			break;
		}
		// ���û�ҵ�����return��ȥ������
		else
		{
			return;
		}
	}
	}
	// 3 �鿴��Ϣ
	Capstone::DisAsm(m_processHandle, exceptionAddr, 10);// �鿴�������루eip���������쳣������
	// 4 ��ȡ�û�����
	GetUserCommand();
}
// ��ȡ�û�������
void Debugger::GetUserCommand()
{
	char input[0x100] = { 0 };
	while (true)
	{
		// 1 ��ʾ֧�ֵ�����
		ShowCommandMenu();
		printf(">>> ");
		// 2 ��ȡָ�ָ��Ӧ�������ȿ��Ǻõ�
		scanf_s("%s", input, 0x100);
		// 3 �ֱ�ִ�в�ͬ��ָ��
		if (!strcmp(input, "go"))
		{
			// ����ִ�У�ֱ�����н�����������һ���쳣
			break;
		}
		else if (!strcmp(input, "test"))
		{
			AntiAntiDebug(m_processHandle);
		}
		else if (!strcmp(input, "shmd"))
		{
			// ��ʾģ����Ϣ
			ShowModuleInfo();
		}
		else if (!strcmp(input, "shrg"))
		{
			// ��ʾ�Ĵ���
			ShowRegisterInfo(m_threadHandle);
		}
		else if (!strcmp(input, "shmm"))
		{
			// show memory and stack
			// �鿴�ڴ���Ϣ
			int addr = 0, size = 0;
			scanf_s("%x %d", &addr, &size);
			ShowMemStaInfo(m_processHandle, addr, size);
		}
		else if (!strcmp(input, "shas"))
		{
			// �鿴���ָ��
			int addr = 0, lines = 0;
			scanf_s("%x %d", &addr, &lines);
			Capstone::DisAsm(m_processHandle, (LPVOID)addr, lines);
		}
		else if (!strcmp(input, "mfas"))
		{
			/* ʾ����
			mu 7786e9e3 mov ecx,1; B901000000
			mu push eax; 50
			*/

			// �޸Ļ��ָ��
			LPVOID addr = 0;
			char buff[0x100] = { 0 };
			scanf_s("%x", &addr);
			gets_s(buff);
			//scanf_s("%s", buff,0x10);
			ModifyAssemble(m_processHandle, addr, buff);
		}
		else if (!strcmp(input, "mfmm"))
		{
			// modify memory
			// �޸��ڴ�
			LPVOID addr = 0;
			char buff[100] = { 0 };
			scanf_s("%x", &addr);
			scanf_s("%s", buff, 100);
			ModifyMemory(m_processHandle, addr, buff);
		}
		else if (!strcmp(input, "mfrg"))
		{
			// �޸ļĴ���
			char regis[10] = { 0 };
			LPVOID buff = 0;
			scanf_s("%s", regis, 10);
			scanf_s("%x", &buff);
			ModifyRegister(m_threadHandle, regis, buff);
		}
		else if (!strcmp(input, "sfbp"))
		{
			// ����int3����ϵ�
			LPVOID addr = 0;
			scanf_s("%x", &addr);
			BreakPoint::SetCCBreakPoint(m_processHandle, addr);
			m_eternalPointAddr = addr;
		}
		else if (!strcmp(input, "cdbp"))
		{
			// ��ȡҪ���õĵ�ַ������
			LPVOID addr = 0;
			int eax = 0;
			scanf_s("%x", &addr);
			scanf_s("%d", &eax);
			BreakPoint::SetConditionBreakPoint(m_processHandle, m_threadHandle, addr, eax);
			m_eax = eax;// ��¼�£�����Ҫ���ڶԱ�
			m_isConditonSet = true;
			m_ConditionBreakPointAddr = addr;
			m_singleStepType = CONDITION;
		}
		else if (!strcmp(input, "stin"))
		{
			// ����TF�����ϵ�
			BreakPoint::SetTFStepIntoBreakPoint(m_threadHandle);
			m_singleStepType = NORMAL;
			break;
		}
		else if (!strcmp(input, "ston"))
		{
			// ����TF���������ϵ�
			BreakPoint::SetStepByBreakPoint(m_processHandle, m_threadHandle);
			break;// Ҫbreak���������Σ��Խ�����溯���е�int3�ϵ�
		}
		else if (!strcmp(input, "hdex"))
		{
			// ��ȡҪ���õĵ�ַ
			LPVOID addr = 0;
			scanf_s("%x", &addr);
			BreakPoint::SetDrxExeBreakPoint(m_threadHandle, (DWORD)addr);// ִ�жϵ�ʱ��rw=0��len=0
			m_singleStepType = DRXEXE;
		}
		else if (!strcmp(input, "hdrw"))
		{
			// ��ȡҪ���õĵ�ַ������
			LPVOID addr = 0;
			int len = 0;
			scanf_s("%x", &addr);
			scanf_s("%d", &len);
			BreakPoint::SetDrxRwBreakPoint(m_threadHandle, (DWORD)addr, len - 1);// ��д�ϵ�ʱ��rw=1,len �Զ�
			m_singleStepType = DRXRW;
		}
		else if (!strcmp(input, "mmbp"))
		{
			// ��ȡҪ���õĵ�ַ
			LPVOID addr = 0;
			scanf_s("%x", &addr);
			BreakPoint::SetMemExeBreakPoint(m_processHandle, m_threadHandle, addr);
			m_memBreakPointAddr = addr;// ��¼�´˵�ַ�������쳣ʱ�ٴ�����
			m_singleStepType = MEM;
		}
		else if (!strcmp(input, "clpg"))
		{
			Plugin::CallPlgFun();		// ��������ʱ����
		}
		else
		{
			printf("ָ�����\n");
		}
	}
}
// ��������
void Debugger::AntiAntiDebug(HANDLE process_handle)
{
	PROCESS_BASIC_INFORMATION stcProcInfo;
	NtQueryInformationProcess(process_handle, ProcessBasicInformation, &stcProcInfo, sizeof(stcProcInfo), NULL);
	//printf("%08X\n", stcProcInfo.PebBaseAddress);
	//��ȡPEB�ĵ�ַ
	PPEB pPeb = stcProcInfo.PebBaseAddress;
	//DWORD OldProtect;
	//DWORD TempProtect;
	DWORD dwSize = 0;
	// �޸�����ʹ���д
	//VirtualProtectEx(process_handle, pPeb, sizeof(stcProcInfo), PAGE_READWRITE, &OldProtect);
	// �޸�PEB����ֶ�
	BYTE value1 = 0;
	WriteProcessMemory(process_handle, (BYTE*)pPeb + 0x02, &value1, 1, &dwSize);
	//DWORD value2 = 2;
	//WriteProcessMemory(process_handle, (BYTE*)pPeb + 0x18 + 0x0C, &value2, 4, &dwSize);
	//DWORD value3 = 0;
	//WriteProcessMemory(process_handle, (BYTE*)pPeb + 0x18 + 0x10, &value3, 4, &dwSize);
	//DWORD value4 = 0;
	//WriteProcessMemory(process_handle, (BYTE*)pPeb + 0x68, &value4, 4, &dwSize);
	// �ָ�ԭ������
	//VirtualProtectEx(process_handle, pPeb, sizeof(stcProcInfo), OldProtect, &TempProtect);

	printf("PEB��̬�����Խ��\n");
	m_isSolvePEB = true; // ��־���Ѿ����
	return;
}


//#define DLLPATH L"C:\\Users\\ry1yn\\source\\repos\\15PB\\Debug\\Dll4HookAPI.dll"
#define DLLPATH L"..\\HookAPI\\Dll4HookAPI.dll"
void Debugger::AntiAntiDebug2(HANDLE process_handle)
{
// 2.��Ŀ�����������ռ�
	LPVOID lpPathAddr = VirtualAllocEx(
		process_handle,					// Ŀ����̾��
		0,							// ָ�������ַ
		wcslen(DLLPATH) * 2 + 2,	// ����ռ��С
		MEM_RESERVE | MEM_COMMIT,	// �ڴ��״̬
		PAGE_READWRITE);			// �ڴ�����

	// 3.��Ŀ�������д��Dll·��
	DWORD dwWriteSize = 0;
	WriteProcessMemory(
		process_handle,				// Ŀ����̾��
		lpPathAddr,					// Ŀ����̵�ַ
		DLLPATH,					// д��Ļ�����
		wcslen(DLLPATH) * 2 + 2,	// ��������С
		&dwWriteSize);				// ʵ��д���С

	// 4.��Ŀ������д����߳�
	HANDLE hThread = CreateRemoteThread(
		process_handle,					// Ŀ����̾��
		NULL,						// ��ȫ����
		NULL,						// ջ��С
		(PTHREAD_START_ROUTINE)LoadLibraryW,	// �ص�����
		lpPathAddr,					// �ص���������
		NULL,						// ��־
		NULL						// �߳�ID
	);

	// 5.�ȴ��߳̽���
	//WaitForSingleObject(hThread, -1);

	// 6.������
	//VirtualFreeEx(process_handle, lpPathAddr, 0, MEM_RELEASE);
	//CloseHandle(hThread);
	//CloseHandle(process_handle);
	return;
}

// ��ʾ�Ĵ�����Ϣ
void Debugger::ShowRegisterInfo(HANDLE thread_handle)
{
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;// �Ӵ˱�ʶ��ʲô���͵Ļ���
	GetThreadContext(thread_handle, &ct);
	printf("=============================== �Ĵ�����Ϣ =================================\n");
	printf("���ݼĴ�����       EAX:%08X  EBX:%08X  ECX:%08X  EDX:%08X\n", ct.Eax, ct.Ebx, ct.Ecx, ct.Edx);
	printf("�μĴ�����         ECS:%08X  EDS:%08X  ESS:%08X  EES:%08X\n", ct.SegCs, ct.SegDs, ct.SegEs, ct.SegEs);
	printf("��ַ�Ĵ�����       ESI:%08X  EDI:%08X\n", ct.Esi, ct.Edi);
	printf("��ַ�Ĵ�����       EBP:%08X  ESP:%08X\n", ct.Ebp, ct.Esp);
	printf("ָ��ָ��Ĵ�����   EIP:%08X\n", ct.Eip);
	printf("��־�Ĵ�����       EFLAGS:%08X\n", ct.EFlags);
}
// ��ʾ�ڴ�/ջ��Ϣ
void Debugger::ShowMemStaInfo(HANDLE process_handle, DWORD addr, int size)
{
	// ��ȡջ��Ϣ
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;// �Ӵ˱�ʶ��ʲô���͵Ļ���
	GetThreadContext(m_threadHandle, &ct);
	BYTE buff2[512] = { 0 };//��ȡ esp �б���ĵ�ַ
	DWORD dwRead2 = 0;
	ReadProcessMemory(m_processHandle, (BYTE*)ct.Esp, buff2, 512, &dwRead2);

	// ��ȡ�ڴ���Ϣ
	BYTE buff[512] = { 0 };//��ȡ esp �б���ĵ�ַ
	DWORD dwRead = 0;
	ReadProcessMemory(m_processHandle, LPVOID(addr), buff, 512, &dwRead);
	// ��ӡ
	printf("\n================================= �ڴ�/ջ ===================================\n");
	for (int i = 0; i < size; i++)
	{
		printf("%08X: %08X\tESP+%2d: %08X\n", addr, ((DWORD *)buff)[i], i * 4, ((DWORD *)buff2)[i]);
		addr += 4;
	}
}
// ��ʾ֧�ֵ�����
void Debugger::ShowCommandMenu()
{
	printf("\n================================ ����ָ�� ==================================\n");
	printf("go:   ����ִ��   shmd: �鿴ģ��             sfbp-addr: ��������ϵ�\n");
	printf("stin: ��������   shrg: �鿴�Ĵ���           mmbp-addr: �����ڴ�ϵ�\n");
	printf("ston: ��������   shmm: �鿴�ڴ�/ջ          hdex-addr: ����Ӳ��ִ�жϵ�\n");
	printf("clpg: ���ò��   shas-addr-line: �鿴���   hdrw-addr-len: ����Ӳ����д�ϵ�\n");
	printf("                 mfmm-addr-buff: �޸��ڴ�   cdbp-addr-buff: ���������ϵ�\n");
	printf("                 mfas-addr-buff: �޸Ļ��ָ��\n");
	printf("                 mfrg-regi-buff: �޸ļĴ�������\n");
}
// ��ʾģ����Ϣ
void Debugger::ShowModuleInfo()
{
	std::vector<MODULEENTRY32> moduleList;

	// ��ȡ���վ��������ģ��ʱ��ָ��pid
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_processInfo.dwProcessId);
	// �洢ģ����Ϣ
	MODULEENTRY32 mInfo = { sizeof(MODULEENTRY32) };
	// ����ģ��
	Module32First(hSnap, &mInfo);
	do
	{
		moduleList.push_back(mInfo);
	} while (Module32Next(hSnap, &mInfo));

	printf("��ַ\t\t��С\t\t·��\n");
	for (auto&i : moduleList)
	{
		printf("%08X\t%08X\t%s\n", i.modBaseAddr, i.modBaseSize, i.szExePath);
	}
}

// �޸Ļ�����
void Debugger::ModifyAssemble(HANDLE process_handle, LPVOID addr, char * buff)
{
	Keystone::Asm(process_handle, addr, buff);
}
// �޸ļĴ���
void Debugger::ModifyRegister(HANDLE thread_handle, char * regis, LPVOID buff)
{
	// ��ȡ�Ĵ�������
	CONTEXT context = { CONTEXT_ALL };
	GetThreadContext(thread_handle, &context);
	// �ж��޸ĵ��ĸ��Ĵ���
	if (!strcmp(regis, "eip"))
		printf("����ֱ���޸�EIP\n");
	else if (!strcmp(regis, "eax"))
		context.Eax = (DWORD)buff;
	else if (!strcmp(regis, "ebx"))
		context.Ebx = (DWORD)buff;
	else if (!strcmp(regis, "ecx"))
		context.Ecx = (DWORD)buff;
	else if (!strcmp(regis, "edx"))
		context.Edx = (DWORD)buff;
	else if (!strcmp(regis, "ecs"))
		context.SegCs = (DWORD)buff;
	else if (!strcmp(regis, "eds"))
		context.SegDs = (DWORD)buff;
	else if (!strcmp(regis, "ess"))
		context.SegSs = (DWORD)buff;
	else if (!strcmp(regis, "ees"))
		context.SegEs = (DWORD)buff;
	else if (!strcmp(regis, "ebp"))
		context.Ebp = (DWORD)buff;
	else if (!strcmp(regis, "esp"))
		context.Esp = (DWORD)buff;
	else if (!strcmp(regis, "eflags"))
		context.EFlags = (DWORD)buff;
	else
		printf("�ݲ�֧���޸Ĵ˼Ĵ���\n");
	// �޸ļĴ���
	SetThreadContext(thread_handle, &context);
	// �ٴ���ʾ��֤���޸ĳɹ�
	ShowRegisterInfo(thread_handle);
}
// �޸��ڴ�
void Debugger::ModifyMemory(HANDLE process_handle, LPVOID addr, char * buff)
{
	//ShowMemStaInfo(process_handle, (DWORD)addr, 10);
	WriteProcessMemory(process_handle, addr, buff, strlen(buff), NULL);
	ShowMemStaInfo(process_handle, (DWORD)addr, 10);
}

