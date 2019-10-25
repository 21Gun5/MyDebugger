#include <iostream>
#include "Debugger.h"
#include "Capstone.h"
#include "BreakPoint.h"

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
	PROCESS_INFORMATION processInfo = { 0 };
	STARTUPINFOA startupInfo = { sizeof(STARTUPINFOA) };

	// ���Է�ʽ�������̣��õ������Խ���
	BOOL result = CreateProcessA(file_Path, nullptr, NULL, NULL, FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL, NULL, 
		&startupInfo, //ָ�����̵�����������
		&processInfo);//�����½��̵���Ϣ

	// DEBUG_PROCESS ��ʾ�Ե��Եķ�ʽ��Ŀ����̣�����
	//	�������Դ����µĽ���ʱ��ͬ�������½��̵ĵ�����Ϣ��
	// DEBUG_ONLY_THIS_PROCESS ֻ����Ŀ����̣�������
	//	Ŀ����̴������µĽ���
	// CREATE_NEW_CONSOLE ��ʾ�´����� CUI �����ʹ��һ
	//	�������Ŀ���̨���У������д�ͺ͵��������ÿ���̨

	// ������̴����ɹ��ˣ��͹رն�Ӧ�ľ������ֹ���й¶
	if (result == TRUE)
	{
		CloseHandle(processInfo.hThread);
		CloseHandle(processInfo.hProcess);
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
		case EXCEPTION_DEBUG_EVENT:     // �쳣�����¼�
			OnExceptionEvent();
			break;
		}

		// �ڴ���ģ������¼��ͽ��̴����¼���ʱ�򣬶�Ӧ�Ľṹ��
		// �л��ṩ�����ֶΣ�lpImageName �� fUnicode��������
		// lpImageName ��һ��ָ��Ŀ������ڴ�ռ�ָ�룬��ַ��
		// ������ģ������ƣ�fUnicode���ڱ�ʶ�����Ƿ��ǿ��ַ���
		// ���ǣ�ʵ����������ֵû���κε����塣����ͨ����������
		// ����ͨ���ļ�����ҵ�ģ������(·��)��ȡ��

		// Ϊ�˷�ֹ���й¶��Ӧ�ùر�
		CloseHandles();

		// �������ϵͳ���ص�ǰ�Ĵ�����: �����еĽ��� id  ��
		// �߳� id ������ͨ�� WaitForDebugEvent ��ȡ���� id��
		// ��Ϊ�����ԵĿ����Ƕ�������еĶ���̣߳���Ҫ�������֡�
		// �������Ǵ�����������ɹ��˾�Ӧ�÷��� DBG_CONTINUE��
		// ���账��ʧ�ܣ�����û�д����Ӧ�÷��� DBG_EXCEPTION_NOT_HANDLED   

		// �ظ�������ϵͳ
		ContinueDebugEvent(m_debugEvent.dwProcessId,m_debugEvent.dwThreadId,m_continueStatus);
	}
}
// ��������¼��е��쳣�¼�
void Debugger::OnExceptionEvent()
{
	// ��ȡ�쳣���͡�������ַ
	DWORD exceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
	LPVOID exceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	printf("\n================================ ������Ϣ ==================================\n");
	printf("����: %08X\n��ַ: %p\n", exceptionCode, exceptionAddr);
	
	// ����ͬ���쳣����
	switch (exceptionCode)
	{
	// 1 �����쳣��DRxӲ���ϵ㡢TF�����ϵ�
	case EXCEPTION_SINGLE_STEP:
	{
		printf("����: DRxӲ���ϵ㷢��\n");
		BreakPoint::FixDRXBreakPoint(m_threadHandle, exceptionAddr);
		break;
	}
	// 2 �ϵ��쳣: int3����ϵ�
	case EXCEPTION_BREAKPOINT:
	{
		// ϵͳ�ϵ㷢������Ϊ0��û�������������������
		if (!m_isSysBPHappened)
		{
			printf("����: ��һ���쳣�¼�����ϵͳ�ϵ㷢��\n");
			m_isSysBPHappened = true;
		}
		else
		{
			printf("����: int3����ϵ㷢��\n");
		}
		BreakPoint::FixCCBreakPoint(m_processHandle, m_threadHandle, exceptionAddr);
		break;
	}
	// 3 �����쳣���ڴ���ʶϵ�
	case EXCEPTION_ACCESS_VIOLATION:
		printf("����: �ڴ���ʶϵ㷢��\n");
		break;
	}

	// �鿴�������루eip���������쳣������
	printf("\n=============================== �������� =================================\n");
	Capstone::DisAsm(m_processHandle, exceptionAddr, 10);
	// �鿴�Ĵ�����Ϣ
	CONTEXT ct = { 0 };
	GetThreadContext(m_threadHandle, &ct);
	printf("=============================== �Ĵ�����Ϣ =================================\n");
	printf("���ݼĴ�����       EAX:%08X  EBX:%08X  ECX:%08X  EDX:%08X\n", ct.Eax, ct.Ebx, ct.Ecx, ct.Edx);
	printf("�μĴ�����         ECS:%08X  EDS:%08X  ESS:%08X  EES:%08X\n", ct.SegCs, ct.SegDs, ct.SegEs, ct.SegEs);
	printf("��ַ�Ĵ�����       ESI:%08X  EDI:%08X\n", ct.Esi, ct.Edi);
	printf("��ַ�Ĵ�����       EBP:%08X  ESP:%08X\n", ct.Ebp, ct.Esp);
	printf("ָ��ָ��Ĵ�����   EIP:%08X\n", ct.Eip);
	printf("��־�Ĵ�����       EFLAGS:%08X\n", ct.EFlags);

	// ��ȡ�û�����
	GetUserCommand();
}

// ��ȡ�û�������
void Debugger::GetUserCommand()
{
	char input[0x100] = { 0 };

	while (true)
	{
		// ��ȡָ�ָ��Ӧ�������ȿ��Ǻõ�
		printf("\n================================ ����ָ�� ==================================\n");
		printf("g:      \t����ִ��\n");
		printf("p:      \t���õ����ϵ�\n");
		printf("bp-addr:\t��������ϵ�\n");
		printf("hde-addr:\t����Ӳ���ϵ�\n");
		printf("mem-addr:\t�����ڴ���ʶϵ�\n");
		printf("u-addr-lines:\t�鿴���ָ��\n");
		//printf("g: ����ִ��");
		printf(">>> ");
		scanf_s("%s", input, 0x100);
		// ����ִ�У�ֱ�����н�����������һ���쳣
		if (!strcmp(input, "g"))
		{
			break;
		}
		// �鿴���ָ��
		else if (!strcmp(input, "u"))
		{
			int addr = 0, lines = 0;
			scanf_s("%x %d", &addr, &lines);
			Capstone::DisAsm(m_processHandle, (LPVOID)addr, lines);
		}
		// ����int3����ϵ�
		else if (!strcmp(input, "bp"))
		{
			LPVOID addr = 0;
			scanf_s("%x", &addr);
			BreakPoint::SetCCBreakPoint(m_processHandle, addr);
		}
		// ����TF�����ϵ�
		else if (!strcmp(input, "p"))
		{
			BreakPoint::SetTFBreakPoint(m_threadHandle);
			break;
		}
		else if (!strcmp(input, "hde"))
		{
			// ����Ӳ��ִ�жϵ�
			LPVOID addr = 0;
			scanf_s("%x", &addr);
			BreakPoint::SetDRXBreakPoint(m_threadHandle, addr, 0, 0);
		}
		else
		{
			printf("ָ���������\n");
		}
	}
}
