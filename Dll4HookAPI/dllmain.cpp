// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

#include <Windows.h>
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")

void OnInlineHook();
void UnInlineHook();

BYTE g_oldcode[5] = {};// 保存hook地址前5个字节
BYTE g_newcode[5] = { 0xE9 };// 保存hook的5个指令  jmp 0xxxxxxxx

// 自己函数
int NTAPI MyNtQueryInformationProcess(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
)
{
	UnInlineHook();

	// 1 调用原始函数
	int status = NtQueryInformationProcess(
		ProcessHandle,
		ProcessInformationClass,
		ProcessInformation,
		ProcessInformationLength,
		ReturnLength);
	// 2 若返回为0，且查询类型为调试端口（返回为0推测为运行成功
	if (status == 0x00000000 && ProcessInformationClass == ProcessDebugPort)
	{
		// 3 将获取的信息置为0，即所查询的调试端口
		*((PDWORD_PTR)ProcessInformation) = 0;
	}
	MessageBoxW(0, L"你被hook了", 0, 0);
	OnInlineHook();
	return status;
}

// 开启Hook
void OnInlineHook()
{
	// 1 获取函数地址
	HMODULE hModule = LoadLibrary(TEXT("ntdll.dll"));
	LPVOID lpMsgAddr = GetProcAddress(hModule, "NtQueryInformationProcess");
	// 2 保存原始指令5个字节
	memcpy(g_oldcode, lpMsgAddr, 5);
	// 3 计算跳转偏移，构建跳转 jmp xxx
	DWORD dwOffset = (DWORD)MyNtQueryInformationProcess - (DWORD)lpMsgAddr - 5;
	*(DWORD*)(g_newcode + 1) = dwOffset;
	// 4 写入跳转偏移
	DWORD dwOldProtect;
	VirtualProtect(lpMsgAddr, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);// 修改目标页属性
	memcpy(lpMsgAddr, g_newcode, 5);// 修改MessageBoxW指令前5个字节
	VirtualProtect(lpMsgAddr, 5, dwOldProtect, &dwOldProtect);// 恢复页属性
	//return 0;
}

// 关闭InlineHook
void UnInlineHook()
{
	// 还原MessageBoxW前5个字节
	// 1 获取函数地址
	HMODULE hModule = LoadLibrary(TEXT("ntdll.dll"));
	LPVOID lpMsgAddr = GetProcAddress(hModule, "NtQueryInformationProcess");
	// 2 还原指令前5字节
	DWORD dwOldProtect;
	VirtualProtect(lpMsgAddr, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);// 修改目标页属性
	memcpy(lpMsgAddr, g_oldcode, 5);// 修改MessageBoxW指令前5个字节
	VirtualProtect(lpMsgAddr, 5, dwOldProtect, &dwOldProtect);// 恢复页属性
}



// 当进程注入时，开启hook
BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		OnInlineHook();
		break;
	case DLL_PROCESS_DETACH:
		UnInlineHook();
		break;
	}
	return TRUE;
}
