#include "BreakPoint.h"
#include "Capstone.h"

// 事先声明
vector<BREAKPOINTINFO> BreakPoint::breakPointList;
 MEMBREAKPOINTINFO BreakPoint::m_memBreakPoint;

// 设置TF单步步入断点，系统自动修复
void BreakPoint::SetTFStepIntoBreakPoint(HANDLE thread_handle)
{
	CONTEXT context = { CONTEXT_CONTROL };
	GetThreadContext(thread_handle, &context);
	context.EFlags |= 0x100;		// 0x1[8]0[7654]0[3210]，TF位于8
	SetThreadContext(thread_handle, &context);
}
// 设置单步步过断点
void BreakPoint::SetStepByBreakPoint(HANDLE process_handle,HANDLE thread_handle)
{
	//76FF57E0        56                      push esi
	//76FF57E1        662188CA0F0000          and word ptr[eax + 0xfca], cx
	//76FF57E8        E81308FEFF              call 0x76fd6000
	//76FF57ED        832518DC0B7700          and dword ptr[0x770bdc18], 0

	// 1 获取当前EIP
	CONTEXT context = { CONTEXT_CONTROL };
	GetThreadContext(thread_handle, &context);
	DWORD callAddr = context.Eip;
	// 2 获取call指令长度
	int callLen =  Capstone::GetCallCodeLen(process_handle, LPVOID(callAddr));// 查看反汇编代码（eip处，而非异常发生处
	// 3 判断是否是call，是则步过
	if (callLen != -1)
	{
		// 4 当前地址+长度=下一条指令地址，随即下int3断点
		LPVOID addr = LPVOID(callAddr + callLen);
		BreakPoint::SetCCBreakPoint(process_handle, addr);
	}
	// 5 不是call，则正常的一步步走
	else
	{
		BreakPoint::SetTFStepIntoBreakPoint(thread_handle);
	}
}
// 设置/修复 int3-CC软件断点
void BreakPoint::SetCCBreakPoint(HANDLE process_handle, LPVOID addr)
{
	// 0. 创建保存断点信息的结构体
	BREAKPOINTINFO info = { addr };
	// 1. 读取目标地址原有的OPCODE，用于恢复执行
	ReadProcessMemory(process_handle, addr, &info.oldOpcode, 1, NULL);
	// 2. 向目标进程的地址写入 \xcc 字节
	WriteProcessMemory(process_handle, addr, "\xCC", 1, NULL);
	// 3. 将设置的断点添加到链表中
	breakPointList.push_back(info);
}
void BreakPoint::FixCCBreakPoint(HANDLE process_handle, HANDLE thread_handle, LPVOID addr)
{
	// 0 为何用列表，用户自己设置的添加到列表，OS一开始自动设置用于通知的那个不添加（为了区分二者
	// 1 遍历断点列表，找到需要修复的断点
	for (int i = 0; i < breakPointList.size(); ++i)
	{
		// 2 地址相同才修复，否则会出错
		if (breakPointList[i].addr == addr)
		{
			// 3 因为是陷阱类异常，故eip - 1
			CONTEXT context = { CONTEXT_CONTROL };
			GetThreadContext(thread_handle, &context);
			context.Eip -= 1;
			SetThreadContext(thread_handle, &context);
			// 4 将原有的数据写回指定的位置
			WriteProcessMemory(process_handle, addr, &breakPointList[i].oldOpcode, 1, NULL);
			// 5 永久断点(标志位设置) / 普通断点(直接删掉)
			breakPointList.erase(breakPointList.begin() + i);
			break;
		}
	}
}
// 设置DRX硬件执行/读写断点、修复方法二者通用
void BreakPoint::SetDrxExeBreakPoint(HANDLE thread_handle, DWORD addr)
{
	// 1 获取目标线程的寄存器
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thread_handle, &context);
	// 2 获取到 Dr7 寄存器（保存了哪些断点被使用
	PDr7 Dr7 = (PDr7)&context.Dr7;
	// 3 判断是否启用，没有启用就设置
	if (Dr7->L0 == 0)
	{
		context.Dr0 = addr;	// 断点地址
		Dr7->RW0 = 0;			// 类型，执行/读写
		Dr7->LEN0 = 0;			// 长度
		Dr7->L0 = 1;				// 启用断点
	}
	else if (Dr7->L1 == 0)
	{
		context.Dr1 = addr;
		Dr7->RW1 = 0;
		Dr7->LEN1 = 0;
		Dr7->L1 = 1;
	}
	else if (Dr7->L2 == 0)
	{
		context.Dr2 = addr;
		Dr7->RW2 = 0;
		Dr7->LEN2 = 0;
		Dr7->L2 = 1;
	}
	else if (Dr7->L3 == 0)
	{
		context.Dr3 = addr;
		Dr7->RW3 = 0;
		Dr7->LEN3 = 0;
		Dr7->L3 = 1;
	}
	else
	{
		printf("没有空闲的硬件断点位置!\n");
	}
	// 4 写入修改的寄存器环境
	SetThreadContext(thread_handle, &context);
}
void BreakPoint::SetDrxRwBreakPoint(HANDLE thread_handle, DWORD addr,int len)
{
	// 1 获取目标线程的寄存器
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thread_handle, &context);
	// 2 获取到 Dr7 寄存器（保存了哪些断点被使用
	PDr7 Dr7 = (PDr7)&context.Dr7;
	// 3 对地址和长度进行对齐处理
	if (len == 1)
		addr = addr - addr % 2;
	else if (len == 3)
		addr = addr - addr % 4;
	else if (len > 3)
		return;
	// 3 判断是否启用，没有启用就设置
	if (Dr7->L0 == 0)
	{
		context.Dr0 = addr;		// 断点地址
		Dr7->RW0 = 3;			// 类型，执行/读写
		Dr7->LEN0 = len;		// 长度
		Dr7->L0 = 1;			// 启用断点
	}
	else if (Dr7->L1 == 0)
	{
		context.Dr1 = addr;
		Dr7->RW1 = 3;
		Dr7->LEN1 = len;
		Dr7->L1 = 1;
	}
	else if (Dr7->L2 == 0)
	{
		context.Dr2 = addr;
		Dr7->RW2 = 3;
		Dr7->LEN2 = len;
		Dr7->L2 = 1;
	}
	else if (Dr7->L3 == 0)
	{
		context.Dr3 = addr;
		Dr7->RW3 = 3;
		Dr7->LEN3 = len;
		Dr7->L3 = 1;
	}
	else
	{
		printf("没有空闲的硬件断点位置!\n");
	}
	// 4 写入修改的寄存器环境
	SetThreadContext(thread_handle, &context);
}
void BreakPoint::FixDrxBreakPoint(HANDLE thread_handle)
{
	// 1 获取到目标线程的寄存器
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thread_handle, &context);
	// 2 获取到 Dr7 寄存器，保存了哪些断点被使用
	PDr7 Dr7 = (PDr7)&context.Dr7;
	// 3 判断是哪一个断点触发了，并解除
	switch (context.Dr6 & 0xF)
	{
	case 1:
		Dr7->L0 = 0; break;
	case 2:
		Dr7->L1 = 0; break;
	case 4:
		Dr7->L2 = 0; break;
	case 8:
		Dr7->L3 = 0; break;
	}
	// 4 重新设置寄存器信息
	SetThreadContext(thread_handle, &context);
}
// 内存断点相关
void BreakPoint::SetMemExeBreakPoint(HANDLE process_handle, HANDLE thread_handle, LPVOID addr)
{
	//设置该内存页为不可访问
	DWORD dwTempProtect;
	VirtualProtectEx(process_handle,addr,1, PAGE_NOACCESS, &dwTempProtect);
	// 保存地址作对比,属性作恢复
	m_memBreakPoint.addr = addr;
	m_memBreakPoint.oldAttribute = dwTempProtect;
}
bool BreakPoint::WhenMemExeBreakPoint(HANDLE process_handle, HANDLE thread_handle, LPVOID addr)
{
	bool isFind = false;
	// 若此地址不是当初设置的地址
	if (addr != m_memBreakPoint.addr)
	{
		// 将原有的属性恢复
		DWORD dwTempProtect;
		VirtualProtectEx(process_handle, addr, 1, m_memBreakPoint.oldAttribute, &dwTempProtect);
		// 再下一个TF单步断点
		SetTFStepIntoBreakPoint(thread_handle);
		// 单步之后，再重新设置一次内存断点
		//VirtualProtectEx(process_handle, addr, 1, PAGE_NOACCESS, &dwTempProtect);
		isFind = false;
	}
	// 若当前停下的地址，就是当初设置的地址，则修复
	else
	{
		DWORD dwTempProtect;
		VirtualProtectEx(process_handle, addr, 1, m_memBreakPoint.oldAttribute, &dwTempProtect);
		isFind = true;
	}
	return isFind;

}
// 条件断点相关
void BreakPoint::SetConditionBreakPoint(HANDLE process_handle, HANDLE thread_handle, LPVOID addr, int eax)
{
	SetCCBreakPoint(process_handle, addr);
}
bool BreakPoint::WhenConditionBreakPoint(HANDLE process_handle, HANDLE thread_handle, int eax,LPVOID addr)
{
	bool isFind = false;

	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;// 加此标识（什么类型的环境
	GetThreadContext(thread_handle, &ct);
	if (ct.Eax != eax)
	{
		BreakPoint::FixCCBreakPoint(process_handle, thread_handle, addr);
		SetTFStepIntoBreakPoint(thread_handle);
		isFind = false;
	}
	else
	{
		BreakPoint::FixCCBreakPoint(process_handle, thread_handle, addr);
		isFind = true;
	}
	return isFind;
}