#include <iostream>

#include "Debugger.h"
#include "Capstone.h"
#include "BreakPoint.h"
#include <stdio.h>
#include <psapi.h>
#include <strsafe.h>
#include <tchar.h>

// 打开产生异常的进程/线程的句柄
void Debugger::OpenHandles()
{
	m_threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, m_debugEvent.dwThreadId);
	m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_debugEvent.dwProcessId);
}
// 关闭产生异常的进程/线程的句柄
void Debugger::CloseHandles()
{
	CloseHandle(m_threadHandle);
	CloseHandle(m_processHandle);
}

// 打开被调试进程
void Debugger::Open(LPCSTR file_Path)
{
	// 如果进程创建成功，用于接收进程线程的句柄和id
	PROCESS_INFORMATION processInfo = { 0 };
	STARTUPINFOA startupInfo = { sizeof(STARTUPINFOA) };

	// 调试方式创建进程，得到被调试进程
	BOOL result = CreateProcessA(file_Path, nullptr, NULL, NULL, FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL, NULL, 
		&startupInfo, //指定进程的主窗口特性
		&processInfo);//接收新进程的信息

	// DEBUG_PROCESS 表示以调试的方式打开目标进程，并且
	//	当被调试创建新的进程时，同样接收新进程的调试信息。
	// DEBUG_ONLY_THIS_PROCESS 只调试目标进程，不调试
	//	目标进程创建的新的进程
	// CREATE_NEW_CONSOLE 表示新创建的 CUI 程序会使用一
	//	个独立的控制台运行，如果不写就和调试器共用控制台

	// 如果进程创建成功了，就关闭对应的句柄，防止句柄泄露
	if (result == TRUE)
	{
		CloseHandle(processInfo.hThread);
		CloseHandle(processInfo.hProcess);
	}

	// 初始化反汇编引擎，必须在使用反汇编的函数前调用
	Capstone::Init();
}
// 处理调试事件
void Debugger::Run()
{
	// 功能：等待调试事件、处理调试事件、回复调试子系统

	// 等待调试事件，即通过循环不断的从调试对象中获取到调试信息
	while (WaitForDebugEvent(&m_debugEvent, INFINITE))
	{
		// 打开对应的进程和线程的句柄
		OpenHandles();

		// 根据类型，分别处理调试事件
		switch (m_debugEvent.dwDebugEventCode)//dwDebugEventCode 标识事件类型
		{
		// 异常调试事件
		case EXCEPTION_DEBUG_EVENT:     
			OnExceptionEvent();
			break;
		// 模块导入事件
		case LOAD_DLL_DEBUG_EVENT:
			OnLoadDLLEvent();
			break;
		}
		// 为了防止句柄泄露，应该关闭
		CloseHandles();

		// 向调试子系统返回当前的处理结果: 参数中的进程 id  和
		// 线程 id 必须是通过 WaitForDebugEvent 获取到的 id。
		// 因为被调试的可能是多个进程中的多个线程，需要进行区分。
		// 参数三是处理结果，处理成功了就应该返回 DBG_CONTINUE，
		// 假设处理失败，或者没有处理就应该返回 DBG_EXCEPTION_NOT_HANDLED   

		// 回复调试子系统
		ContinueDebugEvent(m_debugEvent.dwProcessId,m_debugEvent.dwThreadId,m_continueStatus);
	}
}

// 处理异常事件
void Debugger::OnExceptionEvent()
{
	// 1 获取异常类型、发生地址
	DWORD exceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
	LPVOID exceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	printf("\n================================ 异常信息 ==================================\n");
	printf("类型: %08X\n地址: %p\n", exceptionCode, exceptionAddr);
	// 2 处理不同的异常类型
	switch (exceptionCode)
	{
	// 1 单步异常：DRx硬件断点
	case EXCEPTION_SINGLE_STEP:
	{	
		BreakPoint::FixDrxBreakPoint(m_threadHandle);
		break;
	}
	// 2 断点异常: int3软件断点
	case EXCEPTION_BREAKPOINT:
	{
		// 系统断点发生（其为0则没发生，发生后则作标记
		if (!m_isSysBPHappened)
		{
			printf("详情: 第一个异常事件，即系统断点发生\n");
			m_isSysBPHappened = true;
		}
		else
		{
			printf("详情: int3软件断点发生\n");
		}
		BreakPoint::FixCCBreakPoint(m_processHandle, m_threadHandle, exceptionAddr);
		break;
	}
	// 3 访问异常：内存访问断点
	case EXCEPTION_ACCESS_VIOLATION:
		printf("详情: 内存访问断点发生\n");
		break;
	}
	// 3 查看信息
	Capstone::DisAsm(m_processHandle, exceptionAddr, 10);// 查看反汇编代码（eip处，而非异常发生处
	ShowRegisterInfo(m_threadHandle);	// 查看寄存器信息
	//ShowStackInfo();	// 查看栈空间
	// 4 获取用户输入
	GetUserCommand();
}
// 处理模块导入事件
void Debugger::OnLoadDLLEvent()
{
	// 获取dll文件的句柄
	HANDLE hFile = m_debugEvent.u.LoadDll.hFile;
	// 显示导入的模块（通过句柄获取路径
	ShowLoadDLL(hFile);
}

// 获取用户的输入
void Debugger::GetUserCommand()
{
	char input[0x100] = { 0 };
	while (true)
	{
		// 1 显示支持的命令
		ShowCommandMenu();
		printf(">>> ");
		// 2 获取指令，指令应该是事先考虑好的
		scanf_s("%s", input, 0x100);
		// 3 分别执行不同的指令
		if (!strcmp(input, "g"))
		{
			// 继续执行，直到运行结束或遇到下一个异常
			break;
		}
		else if (!strcmp(input, "test"))
		{
			//ModifyRegister(m_threadHandle);
		}
		else if (!strcmp(input, "u"))
		{
			// 查看汇编指令
			int addr = 0, lines = 0;
			scanf_s("%x %d", &addr, &lines);
			Capstone::DisAsm(m_processHandle, (LPVOID)addr, lines);
		}
		else if (!strcmp(input, "mu"))
		{
			// 修改汇编指令
			LPVOID addr = 0;
			char buff[0x10] = { 0 };
			scanf_s("%x", &addr);
			scanf_s("%s", buff,0x10);
			ModifyAssemble(m_processHandle, addr, buff);
		}
		else if (!strcmp(input, "mr"))
		{
			// 修改寄存器
			char regis[10] = { 0 };
			LPVOID buff = 0;
			scanf_s("%s", regis,10);
			scanf_s("%x", &buff);
			ModifyRegister(m_threadHandle,regis,buff);
		}
		else if (!strcmp(input, "bp"))
		{
			// 设置int3软件断点
			LPVOID addr = 0;
			scanf_s("%x", &addr);
			BreakPoint::SetCCBreakPoint(m_processHandle, addr);
		}
		else if (!strcmp(input, "p"))
		{
			// 设置TF单步断点
			BreakPoint::SetTFBreakPoint(m_threadHandle);
			break;
		}
		else if (!strcmp(input, "hde"))
		{
			// 获取要设置的地址、类型
			LPVOID addr = 0;
			scanf_s("%x", &addr);
			BreakPoint::SetDrxExeBreakPoint(m_threadHandle, (DWORD)addr);// 执行断点时，rw=0，len=0
		}
		else if (!strcmp(input, "hdr"))
		{
			// 获取要设置的地址、类型
			LPVOID addr = 0;
			int len = 0;
			scanf_s("%x", &addr);
			scanf_s("%d", &len);
			BreakPoint::SetDrxRwBreakPoint(m_threadHandle, (DWORD)addr, len-1);// 读写断点时，rw=1,len 自定
		}
		else
		{
			printf("指令输入错误\n");
		}		
	}
}

// 显示寄存器信息
void Debugger::ShowRegisterInfo(HANDLE thread_handle)
{
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_CONTROL;// 加此标识（什么类型的环境
	GetThreadContext(thread_handle, &ct);
	printf("=============================== 寄存器信息 =================================\n");
	printf("数据寄存器：       EAX:%08X  EBX:%08X  ECX:%08X  EDX:%08X\n", ct.Eax, ct.Ebx, ct.Ecx, ct.Edx);
	printf("段寄存器：         ECS:%08X  EDS:%08X  ESS:%08X  EES:%08X\n", ct.SegCs, ct.SegDs, ct.SegEs, ct.SegEs);
	printf("变址寄存器：       ESI:%08X  EDI:%08X\n", ct.Esi, ct.Edi);
	printf("地址寄存器：       EBP:%08X  ESP:%08X\n", ct.Ebp, ct.Esp);
	printf("指令指针寄存器：   EIP:%08X\n", ct.Eip);
	printf("标志寄存器：       EFLAGS:%08X\n", ct.EFlags);
}
// 显示栈空间信息
void Debugger::ShowStackInfo()
{
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_CONTROL;// 加此标识（什么类型的环境
	GetThreadContext(m_threadHandle, &ct);
	BYTE buff[512] = { 0 };//获取 esp 中保存的地址
	DWORD dwRead = 0;
	ReadProcessMemory(m_processHandle, (BYTE*)ct.Esp, buff, 512, &dwRead);
	printf("\n================================= 栈空间 ===================================\n");
	for (int i = 0; i < 10; i++)
	{
		printf("ESP + %2d\t%08X\n", i * 4, ((DWORD *)buff)[i]);
	}
}
// 显示支持的命令
void Debugger::ShowCommandMenu()
{
	printf("\n================================ 键入指令 ==================================\n");
	printf("g:      \t继续执行\n");
	printf("p:      \t设置单步断点\n");
	printf("bp-addr:\t设置软件断点\n");
	printf("hde-addr:\t设置硬件执行断点\n");
	printf("hdr-addr-1/2/4:\t设置硬件读写断点\n");
	printf("mem-addr:\t设置内存访问断点\n");
	printf("u-addr-lines:\t查看汇编指令\n");
	printf("mu-addr-buff:\t修改汇编指令\n");
	printf("mr-regi-buff:\t修改寄存器环境\n");
}
// 显示模块信息（from CV
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

// 修改汇编代码
void Debugger::ModifyAssemble(HANDLE process_handle, LPVOID addr, char * buff)
{
	// 应该修改反汇编代码，而非机器指令，暂搁置

	// 向目标进程的地址写入指定的字节
	//strcpy_s(buff,0x10,"\xCC");
	//WriteProcessMemory(process_handle, addr, buff, 1, NULL);
}
// 修改寄存器
void Debugger::ModifyRegister(HANDLE thread_handle,char * regis, LPVOID buff)
{
	// 获取寄存器环境
	CONTEXT context = { CONTEXT_CONTROL };
	GetThreadContext(thread_handle, &context);
	// 判断修改的哪个寄存器
	if (!strcmp(regis, "eip"))
		printf("不能直接修改EIP\n");
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
		printf("暂不支持修改此寄存器\n");
	// 修改寄存器
	SetThreadContext(thread_handle, &context);
	// 再次显示来证明修改成功
	ShowRegisterInfo(thread_handle);
}
// 修改栈内存
void Debugger::ModifyStack()
{
}
