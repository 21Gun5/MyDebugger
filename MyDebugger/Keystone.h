#pragma once
#include <windows.h>
#include "keystone/include/keystone.h"// 包含头文件
#pragma comment (lib,"keystone/lib/keystone_x86.lib")// 包含静态库

class Keystone
{
public:
	static void printOpcode(const unsigned char* pOpcode, int nSize);// 打印opcode
	static int Asm(HANDLE process_handle, LPVOID Addr, char asmCode[]);
};