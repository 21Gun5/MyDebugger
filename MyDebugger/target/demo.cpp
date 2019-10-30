// 01_Inject.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <Windows.h>

//  (inject)  注入程序
//  (testdll) dll文件
//  (target)  目标程序


// CreateThread() 线程的回调函数 参数刚好1个
// LoadLibray()  函数的参数刚好也是1
// 让线程的回调函数指向LoadLibray，参数刚好是dll路径

// 要注入的dll 
//#define DLLPATH L"C:\\Users\\ry1yn\\source\\repos\\window原理006day\\Debug\\01_testdll.dll"

#define DLLPATH L"C:\\Users\\ry1yn\\source\\repos\\window原理006day\\Debug\\03_inlineHook.dll"
int main()
{
	DWORD dwPid = 0;
	printf("PID: ");
	scanf_s("%d", &dwPid);

	// 1.打开目标进程
	HANDLE hProcess = OpenProcess(
					PROCESS_ALL_ACCESS,		// 打开权限
					FALSE,					// 是否继承
					dwPid);					// 进程PID
				
	// 2.在目标进程中申请空间
	LPVOID lpPathAddr = VirtualAllocEx(
		hProcess,					// 目标进程句柄
		0,							// 指定申请地址
		wcslen(DLLPATH) * 2 + 2,	// 申请空间大小
		MEM_RESERVE | MEM_COMMIT,	// 内存的状态
		PAGE_READWRITE);			// 内存属性


	// 3.在目标进程中写入Dll路径
	DWORD dwWriteSize = 0;
	WriteProcessMemory(
		hProcess,					// 目标进程句柄
		lpPathAddr,					// 目标进程地址
		DLLPATH,					// 写入的缓冲区
		wcslen(DLLPATH) * 2 + 2,	// 缓冲区大小
		&dwWriteSize);				// 实际写入大小

	// 4.在目标进程中创建线程
	HANDLE hThread = CreateRemoteThread(
		hProcess,					// 目标进程句柄
		NULL,						// 安全属性
		NULL,						// 栈大小
		(PTHREAD_START_ROUTINE)LoadLibrary,	// 回调函数
		lpPathAddr,					// 回调函数参数
		NULL,						// 标志
		NULL						// 线程ID
	);

	// 5.等待线程结束
	WaitForSingleObject(hThread, -1);

	// 6.清理环境
	VirtualFreeEx(hProcess, lpPathAddr, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);



    std::cout << "Hello World!\n"; 
}

// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

// hook   MessageBoxW

void OnInlineHook();
void UnInlineHook();

// 保存hook地址前5个字节
BYTE g_oldcode[5] = {};

// 保存hook的5个指令  jmp 0xxxxxxxx
BYTE g_newcode[5] = {0xE9};

// hook后的新代码
int WINAPI  MyMessageBoxW(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCWSTR lpText,
	_In_opt_ LPCWSTR lpCaption,
	_In_ UINT uType)
{
	// 卸载钩子
	UnInlineHook();

	//调用函数
	int Ret = MessageBoxW(hWnd,L"你被hook了", lpCaption, uType);

	//设置钩子
	OnInlineHook();
	
	return Ret;
}


// 开启InlineHook
void OnInlineHook()
{
	// 1.获取函数地址
	HMODULE hModule = LoadLibraryA("user32.dll");
	LPVOID lpMsgAddr = GetProcAddress(hModule, "MessageBoxW");

	// 2. 保存原始指令5个字节
	memcpy(g_oldcode, lpMsgAddr, 5);

	// 3. 计算跳转偏移，构建跳转 newcode[5]
	// 跳转偏移  = 目标地址 - 指令所在- 指令长度
	DWORD dwOffset = (DWORD)MyMessageBoxW - (DWORD)lpMsgAddr - 5;
	*(DWORD*)(g_newcode + 1) = dwOffset;

	// 4. 写入跳转偏移
	// 修改目标页属性
	DWORD dwOldProtect;
	VirtualProtect(lpMsgAddr, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	// 修改MessageBoxW指令前5个字节
	memcpy(lpMsgAddr, g_newcode, 5);
	// 恢复页属性
	VirtualProtect(lpMsgAddr, 5, dwOldProtect, &dwOldProtect);
}

// 关闭InlineHook
void UnInlineHook()
{
	// 还原MessageBoxW前5个字节
		// 1.获取函数地址
	HMODULE hModule = LoadLibraryA("user32.dll");
	LPVOID lpMsgAddr = GetProcAddress(hModule, "MessageBoxW");

	// 2.还原指令前5字节
	// 修改目标页属性
	DWORD dwOldProtect;
	VirtualProtect(lpMsgAddr, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	// 修改MessageBoxW指令前5个字节
	memcpy(lpMsgAddr, g_oldcode, 5);
	// 恢复页属性
	VirtualProtect(lpMsgAddr, 5, dwOldProtect, &dwOldProtect);



}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		OnInlineHook();
		break;
	}
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
		UnInlineHook();
        break;
    }
	//  dllmain 必须返回true,才可以加载
    return TRUE;
}



