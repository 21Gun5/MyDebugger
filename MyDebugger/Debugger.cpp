#include <iostream>

#include "Debugger.h"
#include "Capstone.h"
#include "BreakPoint.h"
#include <psapi.h>
#include <strsafe.h>
#include <tchar.h>

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
		// �쳣�����¼�
		case EXCEPTION_DEBUG_EVENT:     
			OnExceptionEvent();
			break;
		// ģ�鵼���¼�
		case LOAD_DLL_DEBUG_EVENT:
			OnLoadDLLEvent();
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
		ContinueDebugEvent(m_debugEvent.dwProcessId,m_debugEvent.dwThreadId,m_continueStatus);
	}
}
// �����쳣�¼�
void Debugger::OnExceptionEvent()
{
	// ��ȡ�쳣���͡�������ַ
	DWORD exceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
	LPVOID exceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	printf("\n================================ �쳣��Ϣ ==================================\n");
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
	Capstone::DisAsm(m_processHandle, exceptionAddr, 10);
	// �鿴�Ĵ�����Ϣ
	ShowRegisterInfo();
	// �鿴ջ�ռ�
	ShowStackInfo();
	// ��ȡ�û�����
	GetUserCommand();
}
// ����ģ�鵼���¼�
void Debugger::OnLoadDLLEvent()
{
	// ��ȡdll�ļ��ľ��
	HANDLE hFile = m_debugEvent.u.LoadDll.hFile;
	// ��ʾ�����ģ�飨ͨ�������ȡ·��
	ShowLoadDLL(hFile);
}

// ��ȡ�û�������
void Debugger::GetUserCommand()
{
	char input[0x100] = { 0 };

	while (true)
	{
		// ��ʾ֧�ֵ�����
		ShowCommandMenu();
		// ��ȡָ�ָ��Ӧ�������ȿ��Ǻõ�
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
		// �޸Ļ��ָ��
		else if (!strcmp(input, "mu"))
		{
			LPVOID addr = 0;
			char buff[0x10] = { 0 };
			scanf_s("%x", &addr);
			scanf_s("%s", buff,0x10);
			ModifyAssemble(m_processHandle, addr, buff);
		}
		// test
		else if (!strcmp(input, "test"))
		{
			ModifyRegister(m_processHandle);
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
// �鿴�Ĵ�����Ϣ
void Debugger::ShowRegisterInfo()
{
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_CONTROL;// �Ӵ˱�ʶ��ʲô���͵Ļ���
	GetThreadContext(m_threadHandle, &ct);
	printf("=============================== �Ĵ�����Ϣ =================================\n");
	printf("���ݼĴ�����       EAX:%08X  EBX:%08X  ECX:%08X  EDX:%08X\n", ct.Eax, ct.Ebx, ct.Ecx, ct.Edx);
	printf("�μĴ�����         ECS:%08X  EDS:%08X  ESS:%08X  EES:%08X\n", ct.SegCs, ct.SegDs, ct.SegEs, ct.SegEs);
	printf("��ַ�Ĵ�����       ESI:%08X  EDI:%08X\n", ct.Esi, ct.Edi);
	printf("��ַ�Ĵ�����       EBP:%08X  ESP:%08X\n", ct.Ebp, ct.Esp);
	printf("ָ��ָ��Ĵ�����   EIP:%08X\n", ct.Eip);
	printf("��־�Ĵ�����       EFLAGS:%08X\n", ct.EFlags);
}
// �鿴ջ�ռ���Ϣ
void Debugger::ShowStackInfo()
{
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_CONTROL;// �Ӵ˱�ʶ��ʲô���͵Ļ���
	GetThreadContext(m_threadHandle, &ct);
	BYTE buff[512] = { 0 };//��ȡ esp �б���ĵ�ַ
	DWORD dwRead = 0;
	ReadProcessMemory(m_processHandle, (BYTE*)ct.Esp, buff, 512, &dwRead);
	printf("\n================================= ջ�ռ� ===================================\n");
	for (int i = 0; i < 10; i++)
	{
		printf("ESP + %2d\t%08X\n", i * 4, ((DWORD *)buff)[i]);
	}
}
// ��ʾ֧�ֵ�����
void Debugger::ShowCommandMenu()
{
	printf("\n================================ ����ָ�� ==================================\n");
	printf("g:      \t����ִ��\n");
	printf("p:      \t���õ����ϵ�\n");
	printf("bp-addr:\t��������ϵ�\n");
	printf("hde-addr:\t����Ӳ���ϵ�\n");
	printf("mem-addr:\t�����ڴ���ʶϵ�\n");
	printf("u-addr-lines:\t�鿴���ָ��\n");
	printf("mu-addr-buff:\t�޸Ļ��ָ��\n");
}
// ��ʾģ����Ϣ��from CV
bool Debugger::ShowLoadDLL(HANDLE hFile)
{
	BOOL bSuccess = FALSE;
	TCHAR pszFilename[MAX_PATH + 1];
	HANDLE hFileMap;
	// Get the file size.
	DWORD dwFileSizeHi = 0;
	DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);
	if (dwFileSizeLo == 0 && dwFileSizeHi == 0)
	{
		_tprintf(TEXT("Cannot map a file with a length of zero.\n"));
		return FALSE;
	}
	// Create a file mapping object.
	hFileMap = CreateFileMapping(hFile,
		NULL,
		PAGE_READONLY,
		0,
		1,
		NULL);
	if (hFileMap)
	{
		// Create a file mapping to get the file name.
		void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);
		if (pMem)
		{
			if (GetMappedFileName(GetCurrentProcess(),
				pMem,
				pszFilename,
				MAX_PATH))
			{
				// Translate path with device name to drive letters.
				TCHAR szTemp[512];
				szTemp[0] = '\0';
				if (GetLogicalDriveStrings(512 - 1, szTemp))
				{
					TCHAR szName[MAX_PATH];
					TCHAR szDrive[3] = TEXT(" :");
					BOOL bFound = FALSE;
					TCHAR* p = szTemp;
					do
					{
						// Copy the drive letter to the template string
						*szDrive = *p;
						// Look up each device name
						if (QueryDosDevice(szDrive, szName, MAX_PATH))
						{
							size_t uNameLen = _tcslen(szName);
							if (uNameLen < MAX_PATH)
							{
								bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0;
								if (bFound && *(pszFilename + uNameLen) == _T('\\'))
								{
									// Reconstruct pszFilename using szTempFile
									// Replace device path with DOS path
									TCHAR szTempFile[MAX_PATH];
									StringCchPrintf(szTempFile,
										MAX_PATH,
										TEXT("%s%s"),
										szDrive,
										pszFilename + uNameLen);
									StringCchCopyN(pszFilename, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
								}
							}
						}
						// Go to the next NULL character.
						while (*p++);
					} while (!bFound && *p); // end of string
				}
			}
			bSuccess = TRUE;
			UnmapViewOfFile(pMem);
		}
		CloseHandle(hFileMap);
	}
	_tprintf(TEXT("ModuleLoaded\t%s\n"), pszFilename);
	return bSuccess;
}

void Debugger::ModifyAssemble(HANDLE process_handle, LPVOID addr, char * buff)
{
	// Ӧ���޸ķ������룬���ǻ���ָ��ݸ���

	// ��Ŀ����̵ĵ�ַд��ָ�����ֽ�
	//strcpy_s(buff,0x10,"\xCC");
	//WriteProcessMemory(process_handle, addr, buff, 1, NULL);
}

void Debugger::ModifyRegister(HANDLE thread_handle)
{
	// Ϊ���޸Ĳ��ɹ����ж���߳�
	CONTEXT context = { CONTEXT_CONTROL };
	GetThreadContext(thread_handle, &context);
	context.Eip = 0x1000;
	SetThreadContext(thread_handle, &context);

	ShowRegisterInfo();
}

void Debugger::ModifyStack()
{
}
