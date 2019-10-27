#pragma once
#include <windows.h>
#include <vector>
using namespace std;

// 断点信息结构体
typedef struct _BREAKPOINTINFO
{
	LPVOID addr = 0;		// 地址
	BYTE oldOpcode = 0;		// 原机器指令，用于恢复
} BREAKPOINTINFO, *PBREAKPOINTINFO;
// DR7 寄存器结构体
typedef struct _DBG_REG7
{
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;
	unsigned : 6;// 保留的无效空间
	unsigned RW0 : 2; unsigned LEN0 : 2;
	unsigned RW1 : 2; unsigned LEN1 : 2;
	unsigned RW2 : 2; unsigned LEN2 : 2;
	unsigned RW3 : 2; unsigned LEN3 : 2;
} Dr7, *PDr7;

// 断点类：工具类，设置/删除/修复断点
class BreakPoint
{
private:
	// 断点列表，保存所有的int3软件断点
	static vector<BREAKPOINTINFO> breakPointList;
public:
	// 设置TF单步步入/单步步过断点
	static void SetTFStepIntoBreakPoint(HANDLE thread_handle);
	static void SetStepByBreakPoint(HANDLE process_handle, HANDLE thread_handle);
	// 设置/修复 int3-CC软件断点
	static void SetCCBreakPoint(HANDLE process_handle, LPVOID addr);
	static void FixCCBreakPoint(HANDLE process_handle, HANDLE thread_handle, LPVOID addr);
	// 设置/修复 DRX硬件执行断点
	static void SetDrxExeBreakPoint(HANDLE thread_handle, DWORD addr);
	static void FixDrxBreakPoint(HANDLE thread_handle);
	// 设置/修复 DRX硬件读写断点
	static void SetDrxRwBreakPoint(HANDLE thread_handle, DWORD addr, int len);
};

