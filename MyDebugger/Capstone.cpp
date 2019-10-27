#include "Capstone.h"

csh Capstone::Handle = { 0 };
cs_opt_mem Capstone::OptMem = { 0 };

// 初始化反汇编引擎
void Capstone::Init()
{
	// 配置堆空间的回调函数
	OptMem.free = free;
	OptMem.calloc = calloc;
	OptMem.malloc = malloc;
	OptMem.realloc = realloc;
	OptMem.vsnprintf = (cs_vsnprintf_t)vsprintf_s;

	// 注册堆空间管理组函数
	cs_option(NULL, CS_OPT_MEM, (size_t)& OptMem);

	// 打开一个句柄
	cs_open(CS_ARCH_X86, CS_MODE_32, &Capstone::Handle);
}

// 反汇编指定条数的语句
void Capstone::DisAsm(HANDLE Handle, LPVOID Addr, DWORD Count)
{
	// 用来读取指令位置内存的缓冲区信息
	cs_insn* ins = nullptr;
	PCHAR buff = new CHAR[Count * 16]{ 0 };

	// 读取指定长度的内存空间
	DWORD dwWrite = 0;
	ReadProcessMemory(Handle, (LPVOID)Addr, buff, Count * 16, &dwWrite);
	int count = cs_disasm(Capstone::Handle, (uint8_t*)buff, Count * 16, (uint64_t)Addr, 0, &ins);

	// for 条件在少数情况下会产生问题，可能需要修改条件
	//	- 某些时候，设置断点之后会生成无效指令
	printf("\n=============================== 反汇编代码 =================================\n");
	for (DWORD i = 0; i < Count && i < count; ++i)
	{
		printf("%08X\t", (UINT)ins[i].address);// 地址
		for (uint16_t j = 0; j < 16; ++j)
		{
			if (j < ins[i].size)
				printf("%02X", ins[i].bytes[j]);// 机器指令
			else
				printf(" ");
		}
		printf("\t%s %s\n", ins[i].mnemonic, ins[i].op_str);// 汇编代码
	}
	printf("\n");
	// 释放动态分配的空间
	delete[] buff;
	cs_free(ins, count);
}

int Capstone::GetCallCodeLen(HANDLE Handle, LPVOID Addr)
{
	// 用来读取指令位置内存的缓冲区信息
	cs_insn* ins = nullptr;
	PCHAR buff = new CHAR[16]{ 0 };
	// 读取指定长度的内存空间
	DWORD dwWrite = 0;
	ReadProcessMemory(Handle, (LPVOID)Addr, buff, 16, &dwWrite);
	int count = cs_disasm(Capstone::Handle, (uint8_t*)buff, 16, (uint64_t)Addr, 0, &ins);
	// 判断是否是call指令,不是则长度为-1
	int callLen = -1;
	if(!strcmp(ins[0].mnemonic,"call"))
	{
		// 获取call指令的长度，首地址+长度即下一条指令地址
		callLen = ins[0].size;
	}
	// 释放动态分配的空间
	delete[] buff;
	cs_free(ins, count);
	// 返回
	return callLen;
}
