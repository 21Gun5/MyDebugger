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
	//PROCESS_INFORMATION processInfo = { 0 };
	STARTUPINFOA startupInfo = { sizeof(STARTUPINFOA) };

	// 调试方式创建进程，得到被调试进程
	BOOL result = CreateProcessA(file_Path, nullptr, NULL, NULL, FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL, NULL,
		&startupInfo, //指定进程的主窗口特性
		&m_processInfo);//接收新进程的信息

	// DEBUG_PROCESS 表示以调试的方式打开目标进程，并且
	//	当被调试创建新的进程时，同样接收新进程的调试信息。
	// DEBUG_ONLY_THIS_PROCESS 只调试目标进程，不调试
	//	目标进程创建的新的进程
	// CREATE_NEW_CONSOLE 表示新创建的 CUI 程序会使用一
	//	个独立的控制台运行，如果不写就和调试器共用控制台

	//AntiAntiDebug2(m_processInfo.hProcess);


	// 如果进程创建成功了，就关闭对应的句柄，防止句柄泄露
	if (result == TRUE)
	{
		CloseHandle(m_processInfo.hThread);
		CloseHandle(m_processInfo.hProcess);
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

		}
		// 为了防止句柄泄露，应该关闭
		CloseHandles();

		// 向调试子系统返回当前的处理结果: 参数中的进程 id  和
		// 线程 id 必须是通过 WaitForDebugEvent 获取到的 id。
		// 因为被调试的可能是多个进程中的多个线程，需要进行区分。
		// 参数三是处理结果，处理成功了就应该返回 DBG_CONTINUE，
		// 假设处理失败，或者没有处理就应该返回 DBG_EXCEPTION_NOT_HANDLED   

		// 回复调试子系统
		ContinueDebugEvent(m_debugEvent.dwProcessId, m_debugEvent.dwThreadId, m_continueStatus);
	}
}
// 处理异常事件
void Debugger::OnExceptionEvent()
{
	// 1 获取异常类型、发生地址
	DWORD exceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
	LPVOID exceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	// 2 处理不同的异常类型
	switch (exceptionCode)
	{
		// 1 单步异常：DRx硬件断点、TF单步断点都在这
	case EXCEPTION_SINGLE_STEP:
	{
		switch (m_singleStepType)
		{
		case Debugger::NORMAL:
			printf("\n================================ 异常信息 ==================================\n");
			printf("类型: %08X\n地址: %p\n", exceptionCode, exceptionAddr);
			printf("详情: 单步断点发生\n");
			break;
		case Debugger::DRXEXE:
			printf("\n================================ 异常信息 ==================================\n");
			printf("类型: %08X\n地址: %p\n", exceptionCode, exceptionAddr);
			printf("详情: 硬件执行断点发生\n");
			BreakPoint::FixDrxBreakPoint(m_threadHandle);
			//return;
			break;
		case Debugger::DRXRW:
			printf("\n================================ 异常信息 ==================================\n");
			printf("类型: %08X\n地址: %p\n", exceptionCode, exceptionAddr);
			printf("详情: 硬件读写断点发生\n");
			BreakPoint::FixDrxBreakPoint(m_threadHandle);
			break;
		case Debugger::MEM:
			// 再设置内存断点
			DWORD dwTempProtect;
			VirtualProtectEx(m_processHandle, m_memBreakPointAddr, 1, PAGE_NOACCESS, &dwTempProtect);
			return;
		case Debugger::CONDITION:
			// 再设置条件断点，即INT3软件断点
			BreakPoint::SetConditionBreakPoint(m_processHandle, m_threadHandle, m_ConditionBreakPointAddr, m_eax);
			return;
		case Debugger::CC:
			// 再设置条件断点，即INT3软件断点
			BreakPoint::SetCCBreakPoint(m_processHandle, m_eternalPointAddr);
			return;
		default:
			break;
		}
		break;
	}
	// 2 断点异常: int3软件断点
	case EXCEPTION_BREAKPOINT:
	{
		// 1 条件断点
		if (m_isConditonSet)
		{
			bool isFind = BreakPoint::WhenConditionBreakPoint(m_processHandle, m_threadHandle, m_eax, LPVOID(exceptionAddr));
			// 若满足条件，则打印，修复，继续执行
			if (isFind)
			{
				printf("\n================================ 异常信息 ==================================\n");
				printf("类型: %08X\n地址: %p\n", exceptionCode, exceptionAddr);
				printf("详情: eax=%d 的条件断点发生\n", m_eax);
				m_isConditonSet = false;
				break;
			}
			// 若不满足，则退出，继续
			else
			{
				return;
			}
		}
		printf("\n================================ 异常信息 ==================================\n");
		printf("类型: %08X\n地址: %p\n", exceptionCode, exceptionAddr);
		// 2 系统断点发生（其为0则没发生，发生后则作标记
		if (!m_isSysBPHappened)
		{
			printf("详情: 第一个异常事件，即系统断点发生\n");
			m_isSysBPHappened = true;
			// 注意，在系统断点发生之后在修改PEB的值
			// 被调试进程在跑之前，系统先检测PEB的BeingDebug值，根据这个来下系统断点
			// 若之前就修改，系统检测不到，就停不下来
			AntiAntiDebug(m_processHandle);

			AntiAntiDebug2(m_processHandle);//hookAPI 反反调试，未成功
			BreakPoint::FixCCBreakPoint(m_processHandle, m_threadHandle, exceptionAddr);
			break;
		}
		// 3 普通软件断点
		else
		{
			printf("详情: int3软件断点发生\n");
			BreakPoint::FixCCBreakPoint(m_processHandle, m_threadHandle, exceptionAddr);
			// 再下一个TF单步断点
			BreakPoint::SetTFStepIntoBreakPoint(m_threadHandle);
			m_singleStepType = CC;
			break;
		}
	}
	// 3 访问异常：内存访问断点
	case EXCEPTION_ACCESS_VIOLATION:
	{
		DWORD type = m_debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[0];//触发类型0/1/8
		DWORD memAccessAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1];//触发地址
		bool isFind = BreakPoint::WhenMemExeBreakPoint(m_processHandle, m_threadHandle, LPVOID(memAccessAddr));
		// 如果找到地址，则打印信息，break
		if (isFind)
		{
			printf("\n================================ 异常信息 ==================================\n");
			printf("类型: %08X\n地址: %p\n", exceptionCode, memAccessAddr);
			// 打印具体类型
			switch (type)
			{
			case 0:
				printf("详情: 内存读取断点发生\n");
				break;
			case 1:
				printf("详情: 内存写入断点发生\n");
				break;
			case 8:
				printf("详情: 内存执行断点发生\n");
				break;
			default:
				break;
			}
			break;
		}
		// 如果没找到，则return回去继续找
		else
		{
			return;
		}
	}
	}
	// 3 查看信息
	Capstone::DisAsm(m_processHandle, exceptionAddr, 10);// 查看反汇编代码（eip处，而非异常发生处
	// 4 获取用户输入
	GetUserCommand();
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
		if (!strcmp(input, "go"))
		{
			// 继续执行，直到运行结束或遇到下一个异常
			break;
		}
		else if (!strcmp(input, "test"))
		{
			AntiAntiDebug(m_processHandle);
		}
		else if (!strcmp(input, "shmd"))
		{
			// 显示模块信息
			ShowModuleInfo();
		}
		else if (!strcmp(input, "shrg"))
		{
			// 显示寄存器
			ShowRegisterInfo(m_threadHandle);
		}
		else if (!strcmp(input, "shmm"))
		{
			// show memory and stack
			// 查看内存信息
			int addr = 0, size = 0;
			scanf_s("%x %d", &addr, &size);
			ShowMemStaInfo(m_processHandle, addr, size);
		}
		else if (!strcmp(input, "shas"))
		{
			// 查看汇编指令
			int addr = 0, lines = 0;
			scanf_s("%x %d", &addr, &lines);
			Capstone::DisAsm(m_processHandle, (LPVOID)addr, lines);
		}
		else if (!strcmp(input, "mfas"))
		{
			/* 示例：
			mu 7786e9e3 mov ecx,1; B901000000
			mu push eax; 50
			*/

			// 修改汇编指令
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
			// 修改内存
			LPVOID addr = 0;
			char buff[100] = { 0 };
			scanf_s("%x", &addr);
			scanf_s("%s", buff, 100);
			ModifyMemory(m_processHandle, addr, buff);
		}
		else if (!strcmp(input, "mfrg"))
		{
			// 修改寄存器
			char regis[10] = { 0 };
			LPVOID buff = 0;
			scanf_s("%s", regis, 10);
			scanf_s("%x", &buff);
			ModifyRegister(m_threadHandle, regis, buff);
		}
		else if (!strcmp(input, "sfbp"))
		{
			// 设置int3软件断点
			LPVOID addr = 0;
			scanf_s("%x", &addr);
			BreakPoint::SetCCBreakPoint(m_processHandle, addr);
			m_eternalPointAddr = addr;
		}
		else if (!strcmp(input, "cdbp"))
		{
			// 获取要设置的地址、条件
			LPVOID addr = 0;
			int eax = 0;
			scanf_s("%x", &addr);
			scanf_s("%d", &eax);
			BreakPoint::SetConditionBreakPoint(m_processHandle, m_threadHandle, addr, eax);
			m_eax = eax;// 记录下，后续要用于对比
			m_isConditonSet = true;
			m_ConditionBreakPointAddr = addr;
			m_singleStepType = CONDITION;
		}
		else if (!strcmp(input, "stin"))
		{
			// 设置TF单步断点
			BreakPoint::SetTFStepIntoBreakPoint(m_threadHandle);
			m_singleStepType = NORMAL;
			break;
		}
		else if (!strcmp(input, "ston"))
		{
			// 设置TF单步步过断点
			BreakPoint::SetStepByBreakPoint(m_processHandle, m_threadHandle);
			break;// 要break，结束本次，以解除上面函数中的int3断点
		}
		else if (!strcmp(input, "hdex"))
		{
			// 获取要设置的地址
			LPVOID addr = 0;
			scanf_s("%x", &addr);
			BreakPoint::SetDrxExeBreakPoint(m_threadHandle, (DWORD)addr);// 执行断点时，rw=0，len=0
			m_singleStepType = DRXEXE;
		}
		else if (!strcmp(input, "hdrw"))
		{
			// 获取要设置的地址、类型
			LPVOID addr = 0;
			int len = 0;
			scanf_s("%x", &addr);
			scanf_s("%d", &len);
			BreakPoint::SetDrxRwBreakPoint(m_threadHandle, (DWORD)addr, len - 1);// 读写断点时，rw=1,len 自定
			m_singleStepType = DRXRW;
		}
		else if (!strcmp(input, "mmbp"))
		{
			// 获取要设置的地址
			LPVOID addr = 0;
			scanf_s("%x", &addr);
			BreakPoint::SetMemExeBreakPoint(m_processHandle, m_threadHandle, addr);
			m_memBreakPointAddr = addr;// 记录下此地址，单步异常时再次设置
			m_singleStepType = MEM;
		}
		else if (!strcmp(input, "clpg"))
		{
			Plugin::CallPlgFun();		// 正在运行时调用
		}
		else
		{
			printf("指令错误\n");
		}
	}
}
// 反反调试
void Debugger::AntiAntiDebug(HANDLE process_handle)
{
	PROCESS_BASIC_INFORMATION stcProcInfo;
	NtQueryInformationProcess(process_handle, ProcessBasicInformation, &stcProcInfo, sizeof(stcProcInfo), NULL);
	//printf("%08X\n", stcProcInfo.PebBaseAddress);
	//获取PEB的地址
	PPEB pPeb = stcProcInfo.PebBaseAddress;
	//DWORD OldProtect;
	//DWORD TempProtect;
	DWORD dwSize = 0;
	// 修改属性使其可写
	//VirtualProtectEx(process_handle, pPeb, sizeof(stcProcInfo), PAGE_READWRITE, &OldProtect);
	// 修改PEB相关字段
	BYTE value1 = 0;
	WriteProcessMemory(process_handle, (BYTE*)pPeb + 0x02, &value1, 1, &dwSize);
	//DWORD value2 = 2;
	//WriteProcessMemory(process_handle, (BYTE*)pPeb + 0x18 + 0x0C, &value2, 4, &dwSize);
	//DWORD value3 = 0;
	//WriteProcessMemory(process_handle, (BYTE*)pPeb + 0x18 + 0x10, &value3, 4, &dwSize);
	//DWORD value4 = 0;
	//WriteProcessMemory(process_handle, (BYTE*)pPeb + 0x68, &value4, 4, &dwSize);
	// 恢复原有属性
	//VirtualProtectEx(process_handle, pPeb, sizeof(stcProcInfo), OldProtect, &TempProtect);

	printf("PEB静态反调试解决\n");
	m_isSolvePEB = true; // 标志其已经解决
	return;
}


//#define DLLPATH L"C:\\Users\\ry1yn\\source\\repos\\15PB\\Debug\\Dll4HookAPI.dll"
#define DLLPATH L"..\\HookAPI\\Dll4HookAPI.dll"
void Debugger::AntiAntiDebug2(HANDLE process_handle)
{
// 2.在目标进程中申请空间
	LPVOID lpPathAddr = VirtualAllocEx(
		process_handle,					// 目标进程句柄
		0,							// 指定申请地址
		wcslen(DLLPATH) * 2 + 2,	// 申请空间大小
		MEM_RESERVE | MEM_COMMIT,	// 内存的状态
		PAGE_READWRITE);			// 内存属性

	// 3.在目标进程中写入Dll路径
	DWORD dwWriteSize = 0;
	WriteProcessMemory(
		process_handle,				// 目标进程句柄
		lpPathAddr,					// 目标进程地址
		DLLPATH,					// 写入的缓冲区
		wcslen(DLLPATH) * 2 + 2,	// 缓冲区大小
		&dwWriteSize);				// 实际写入大小

	// 4.在目标进程中创建线程
	HANDLE hThread = CreateRemoteThread(
		process_handle,					// 目标进程句柄
		NULL,						// 安全属性
		NULL,						// 栈大小
		(PTHREAD_START_ROUTINE)LoadLibraryW,	// 回调函数
		lpPathAddr,					// 回调函数参数
		NULL,						// 标志
		NULL						// 线程ID
	);

	// 5.等待线程结束
	//WaitForSingleObject(hThread, -1);

	// 6.清理环境
	//VirtualFreeEx(process_handle, lpPathAddr, 0, MEM_RELEASE);
	//CloseHandle(hThread);
	//CloseHandle(process_handle);
	return;
}

// 显示寄存器信息
void Debugger::ShowRegisterInfo(HANDLE thread_handle)
{
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;// 加此标识（什么类型的环境
	GetThreadContext(thread_handle, &ct);
	printf("=============================== 寄存器信息 =================================\n");
	printf("数据寄存器：       EAX:%08X  EBX:%08X  ECX:%08X  EDX:%08X\n", ct.Eax, ct.Ebx, ct.Ecx, ct.Edx);
	printf("段寄存器：         ECS:%08X  EDS:%08X  ESS:%08X  EES:%08X\n", ct.SegCs, ct.SegDs, ct.SegEs, ct.SegEs);
	printf("变址寄存器：       ESI:%08X  EDI:%08X\n", ct.Esi, ct.Edi);
	printf("地址寄存器：       EBP:%08X  ESP:%08X\n", ct.Ebp, ct.Esp);
	printf("指令指针寄存器：   EIP:%08X\n", ct.Eip);
	printf("标志寄存器：       EFLAGS:%08X\n", ct.EFlags);
}
// 显示内存/栈信息
void Debugger::ShowMemStaInfo(HANDLE process_handle, DWORD addr, int size)
{
	// 获取栈信息
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;// 加此标识（什么类型的环境
	GetThreadContext(m_threadHandle, &ct);
	BYTE buff2[512] = { 0 };//获取 esp 中保存的地址
	DWORD dwRead2 = 0;
	ReadProcessMemory(m_processHandle, (BYTE*)ct.Esp, buff2, 512, &dwRead2);

	// 获取内存信息
	BYTE buff[512] = { 0 };//获取 esp 中保存的地址
	DWORD dwRead = 0;
	ReadProcessMemory(m_processHandle, LPVOID(addr), buff, 512, &dwRead);
	// 打印
	printf("\n================================= 内存/栈 ===================================\n");
	for (int i = 0; i < size; i++)
	{
		printf("%08X: %08X\tESP+%2d: %08X\n", addr, ((DWORD *)buff)[i], i * 4, ((DWORD *)buff2)[i]);
		addr += 4;
	}
}
// 显示支持的命令
void Debugger::ShowCommandMenu()
{
	printf("\n================================ 键入指令 ==================================\n");
	printf("go:   继续执行   shmd: 查看模块             sfbp-addr: 设置软件断点\n");
	printf("stin: 单步步入   shrg: 查看寄存器           mmbp-addr: 设置内存断点\n");
	printf("ston: 单步步过   shmm: 查看内存/栈          hdex-addr: 设置硬件执行断点\n");
	printf("clpg: 调用插件   shas-addr-line: 查看汇编   hdrw-addr-len: 设置硬件读写断点\n");
	printf("                 mfmm-addr-buff: 修改内存   cdbp-addr-buff: 设置条件断点\n");
	printf("                 mfas-addr-buff: 修改汇编指令\n");
	printf("                 mfrg-regi-buff: 修改寄存器环境\n");
}
// 显示模块信息
void Debugger::ShowModuleInfo()
{
	std::vector<MODULEENTRY32> moduleList;

	// 获取快照句柄（遍历模块时需指定pid
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_processInfo.dwProcessId);
	// 存储模块信息
	MODULEENTRY32 mInfo = { sizeof(MODULEENTRY32) };
	// 遍历模块
	Module32First(hSnap, &mInfo);
	do
	{
		moduleList.push_back(mInfo);
	} while (Module32Next(hSnap, &mInfo));

	printf("基址\t\t大小\t\t路径\n");
	for (auto&i : moduleList)
	{
		printf("%08X\t%08X\t%s\n", i.modBaseAddr, i.modBaseSize, i.szExePath);
	}
}

// 修改汇编代码
void Debugger::ModifyAssemble(HANDLE process_handle, LPVOID addr, char * buff)
{
	Keystone::Asm(process_handle, addr, buff);
}
// 修改寄存器
void Debugger::ModifyRegister(HANDLE thread_handle, char * regis, LPVOID buff)
{
	// 获取寄存器环境
	CONTEXT context = { CONTEXT_ALL };
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
// 修改内存
void Debugger::ModifyMemory(HANDLE process_handle, LPVOID addr, char * buff)
{
	//ShowMemStaInfo(process_handle, (DWORD)addr, 10);
	WriteProcessMemory(process_handle, addr, buff, strlen(buff), NULL);
	ShowMemStaInfo(process_handle, (DWORD)addr, 10);
}

