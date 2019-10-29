// demo.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")

// 请把随机基址关闭    属性->链接器->所有选项->随机基址


// 2.查看内存，修改内存
char buff[100] = "hello world";

int g_number=0xFF;

int g_number2 = 0x33;

bool CheckProcessDebugPort()
{
	int nDebugPort = 0;
	NtQueryInformationProcess(
		GetCurrentProcess(),   // 目标进程句柄
		ProcessDebugPort,      // 查询信息类型
		&nDebugPort,           // 输出查询信息
		sizeof(nDebugPort),    // 查询类型大小
		NULL);                 // 实际返回数据大小

	return nDebugPort == 0xFFFFFFFF ? true : false;
}

void fun()
{
	return;
}

int main()
{
	// 1 main函数 设置断点 0x00411A30

	// 2 查看修改汇编指令  
	_asm mov eax, 10;

	// 2 查看/修寄存器
	_asm push eax

	// 3查看模块

	// 4 单步
	_asm pop eax
	
	// 5 步过
	fun();

	// 6 条件断点   0x00411A70 设置eax = 3
	for (int i = 0; i < 5; i++)
		printf("[i:[%d]\n", i);

	// 7 硬件执行断点  0x00411A90 
	_asm push eax
	_asm pop eax

	// 8 硬件访问断点  设置 0x041A064
	if (g_number == 0xFF)
		printf("number == FF\n");

	// 9 内存执行断点
	_asm push eax
	_asm pop eax

	// 10 内存访问断点 设置0x041A068h
	if (g_number2 == 33)
		printf("number2 == 33\n");

	// 11 Messagebox  API断点
	MessageBoxW(NULL, NULL, NULL, NULL);

	// 12 反调试
	int dbg = 0;
	_asm {
		mov eax, dword ptr FS : [0x30];
		movzx eax, byte ptr[eax + 0x02];
		mov dword ptr ds : [dbg], eax;
	}
	if (dbg) {
		printf("BeginDebug:当前处于[调试]\n");
	}
	else {
		printf("BeginDebug:当前处于[正常]\n");
	}
	
	dbg = CheckProcessDebugPort();
	if (dbg) {
		printf("DebugPort: 当前处于[调试]\n");
	}
	else {
		printf("DebugPort: 当前处于[正常]\n");
	}

	//13  源码调试
	//14  导入导出表
	//15  dump文件


}
