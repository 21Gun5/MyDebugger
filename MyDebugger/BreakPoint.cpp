#include "BreakPoint.h"

// 断点列表，保存所有的断点信息
vector<BREAKPOINTINFO> BreakPoint::breakPointList;
// 设置TF单步断点，系统自动修复
void BreakPoint::SetTFBreakPoint(HANDLE thread_handle)
{
	CONTEXT context = { CONTEXT_CONTROL };
	GetThreadContext(thread_handle, &context);
	context.EFlags |= 0x100;		// 0x1[8]0[7654]0[3210]，TF位于8
	SetThreadContext(thread_handle, &context);
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


// 内存断点: 基于分页属性设置的断点.当一个分页的数据不可读写
// 时,会触发设备访问异常. 当将一个地址设置为不可访问后,他所在
// 的整个分页就都不可访问了.此时可以通过异常结构中的 infomation 
// 获取到断下的原因(0,1,8),第二个参数是产生异常的地址,使用这个
// 参数和设置的断点位置进行比较,可以找到这个断点. 如果不是我们需
// 要断下的地方,就需要恢复内存访问属性,并且单步执行一次后重新设置
// 内存访问属性,重复的进行这一个操作,直到参数一对应的是我i们设置的
// 断点类型且参数二的地址和我们设置的地址相同,就成功断下,期间设置的
// 所有断点,都不应该被用户察觉.