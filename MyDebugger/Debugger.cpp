#include <iostream>
#include "Debugger.h"
#include "Capstone.h"
#include "BreakPoint.h"

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
		case EXCEPTION_DEBUG_EVENT:     // 异常调试事件
			OnExceptionEvent();
			break;
		}

		// 在处理模块加载事件和进程创建事件的时候，对应的结构体
		// 中会提供两个字段，lpImageName 和 fUnicode，理论上
		// lpImageName 是一个指向目标进程内存空间指针，地址上
		// 保存了模块的名称，fUnicode用于标识名称是否是宽字符。
		// 但是，实际上这两个值没有任何的意义。可以通过搜索引擎
		// 搜索通过文件句柄找到模块名称(路径)获取。

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
// 处理调试事件中的异常事件
void Debugger::OnExceptionEvent()
{
	// 获取异常类型、发生地址
	DWORD exceptionCode = m_debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
	LPVOID exceptionAddr = m_debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	printf("\n================================ 基本信息 ==================================\n");
	printf("类型: %08X\n地址: %p\n", exceptionCode, exceptionAddr);
	
	// 处理不同的异常类型
	switch (exceptionCode)
	{
	// 1 单步异常：DRx硬件断点、TF单步断点
	case EXCEPTION_SINGLE_STEP:
	{
		printf("详情: DRx硬件断点发生\n");
		BreakPoint::FixDRXBreakPoint(m_threadHandle, exceptionAddr);
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

	// 查看反汇编代码（eip处，而非异常发生处
	printf("\n=============================== 反汇编代码 =================================\n");
	Capstone::DisAsm(m_processHandle, exceptionAddr, 10);
	// 查看寄存器信息
	CONTEXT ct = { 0 };
	GetThreadContext(m_threadHandle, &ct);
	printf("=============================== 寄存器信息 =================================\n");
	printf("数据寄存器：       EAX:%08X  EBX:%08X  ECX:%08X  EDX:%08X\n", ct.Eax, ct.Ebx, ct.Ecx, ct.Edx);
	printf("段寄存器：         ECS:%08X  EDS:%08X  ESS:%08X  EES:%08X\n", ct.SegCs, ct.SegDs, ct.SegEs, ct.SegEs);
	printf("变址寄存器：       ESI:%08X  EDI:%08X\n", ct.Esi, ct.Edi);
	printf("地址寄存器：       EBP:%08X  ESP:%08X\n", ct.Ebp, ct.Esp);
	printf("指令指针寄存器：   EIP:%08X\n", ct.Eip);
	printf("标志寄存器：       EFLAGS:%08X\n", ct.EFlags);

	// 获取用户输入
	GetUserCommand();
}

// 获取用户的输入
void Debugger::GetUserCommand()
{
	char input[0x100] = { 0 };

	while (true)
	{
		// 获取指令，指令应该是事先考虑好的
		printf("\n================================ 键入指令 ==================================\n");
		printf("g:      \t继续执行\n");
		printf("p:      \t设置单步断点\n");
		printf("bp-addr:\t设置软件断点\n");
		printf("hde-addr:\t设置硬件断点\n");
		printf("mem-addr:\t设置内存访问断点\n");
		printf("u-addr-lines:\t查看汇编指令\n");
		//printf("g: 继续执行");
		printf(">>> ");
		scanf_s("%s", input, 0x100);
		// 继续执行，直到运行结束或遇到下一个异常
		if (!strcmp(input, "g"))
		{
			break;
		}
		// 查看汇编指令
		else if (!strcmp(input, "u"))
		{
			int addr = 0, lines = 0;
			scanf_s("%x %d", &addr, &lines);
			Capstone::DisAsm(m_processHandle, (LPVOID)addr, lines);
		}
		// 设置int3软件断点
		else if (!strcmp(input, "bp"))
		{
			LPVOID addr = 0;
			scanf_s("%x", &addr);
			BreakPoint::SetCCBreakPoint(m_processHandle, addr);
		}
		// 设置TF单步断点
		else if (!strcmp(input, "p"))
		{
			BreakPoint::SetTFBreakPoint(m_threadHandle);
			break;
		}
		else if (!strcmp(input, "hde"))
		{
			// 设置硬件执行断点
			LPVOID addr = 0;
			scanf_s("%x", &addr);
			BreakPoint::SetDRXBreakPoint(m_threadHandle, addr, 0, 0);
		}
		else
		{
			printf("指令输入错误\n");
		}
	}
}
