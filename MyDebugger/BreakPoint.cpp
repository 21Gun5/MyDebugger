#include "BreakPoint.h"

// 断点列表，保存所有的断点信息
vector<BREAKPOINTINFO> BreakPoint::breakPointList;
// 设置/修复 int3-CC软件断点
void BreakPoint::SetCCBreakPoint(HANDLE process_handle, LPVOID addr)
{
	// 软件断点: 当 CPU 在执行指令的时候，遇到了 int 3
	// 指令，就会产生一个 3 号异常，eip 指向的是 int 3
	// 的下一条指令，通过向目标指令的首字节中写入 int 3 
	// 可以实现软件断点

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
	// 修复软件断点: 当软件断点断下后,eip 指向的是下一条
	// 需要将 eip - 1，因为 0xCC 是一个字节，然后为了不影
	// 响代码的执行流程，需要将原有的 OPCODE 恢复。

	// 遍历断点列表，找到需要修复的断点
	for (int i = 0; i < breakPointList.size(); ++i)
	{
		// 地址相同才修复，否则会出错
		if (breakPointList[i].addr == addr)
		{
			// 1. 获取寄存器信息，将 eip - 1
			CONTEXT context = { CONTEXT_CONTROL };
			GetThreadContext(thread_handle, &context);
			context.Eip -= 1;
			SetThreadContext(thread_handle, &context);

			// 2. 将原有的数据写回指定的位置
			WriteProcessMemory(process_handle, addr,
				&breakPointList[i].oldOpcode, 1, NULL);

			// 3. 永久断点(标志位设置) / 普通断点(直接删掉)
			breakPointList.erase(breakPointList.begin() + i);
			break;
		}
	}
}
// 设置TF单步断点
void BreakPoint::SetTFBreakPoint(HANDLE thread_handle)
{
	// 单步断点: 通过 CPU 中 efalgs 提供的 TF 标志位
	// 完成的。当CPU在执行指令之后，会检查当前的 TF 位
	// 是否开启，如果开启了，就会触发一个单步异常，并且
	// 会将 TF 标志位重新置 0。

	// 1. 获取到寄存器信息
	CONTEXT context = { CONTEXT_CONTROL };
	GetThreadContext(thread_handle, &context);
	context.EFlags |= 0x100;		// 0x1[8]0[7654]0[3210]
	SetThreadContext(thread_handle, &context);
}
// 设置/修复 DRX硬件断点
void BreakPoint::SetDRXBreakPoint(HANDLE thread_handle, LPVOID addr, int type, int len)
{
	// 硬件的执行断点术语错误类异常,断下的位置就是异常发生的位
	// 置,读写断点是设置给内存地址的,属于陷阱类异常.[读写断点是
	// 设置给中括号内的内容的]

	// 硬件断点: 基于调试寄存器实现的断点，设置硬件断点使用到了
	// Dr0~Dr3 以及 Dr7，Dr0~De3 保存的是想要设置断点的位置，
	// Dr7 用于描述断点的类型和断点覆盖的范围。因为保存地址的调
	// 试寄存器只有 4 个，所以硬件断点最多 4 个。

	// 当 RW 的值是 0 的时候，表示设置硬件执行断点，此时，Len
	// 位必须为 0，RW 表示的是类型，len 表示范围。

	// 获取到目标线程的寄存器
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thread_handle, &context);

	// 获取到 Dr7 寄存器，保存了哪些断点被使用
	PDr7 Dr7 = (PDr7)&context.Dr7;

	// 判断是否启用，没有启用就设置
	if (Dr7->L0 == 0)
	{
		// 设置基本信息
		context.Dr0 = (DWORD)addr;
		Dr7->RW0 = type;
		Dr7->LEN0 = len;
		// 启用断点
		Dr7->L0 = 1;
	}
	else if (Dr7->L1 == 0)
	{
		context.Dr1 = (DWORD)addr;
		Dr7->RW1 = type;
		Dr7->LEN1 = len;
		Dr7->L1 = 1;
	}
	else if (Dr7->L2 == 0)
	{
		context.Dr2 = (DWORD)addr;
		Dr7->RW2 = type;
		Dr7->LEN2 = len;
		Dr7->L2 = 1;
	}
	else if (Dr7->L3 == 0)
	{
		context.Dr3 = (DWORD)addr;
		Dr7->RW3 = type;
		Dr7->LEN3 = len;
		Dr7->L3 = 1;
	}
	else
	{
		printf("没有空闲的硬件断点位置!\n");
	}

	SetThreadContext(thread_handle, &context);
}
void BreakPoint::FixDRXBreakPoint(HANDLE thread_handle, LPVOID addr)
{
	// 修复硬件断点的原理: 当硬件断点断下后,Dr6的最低 4 位
	// 标记了是哪一个硬件断点断下了,找到这个硬件断点对应的
	// LN,将这个位置设置为0就可以了.

	// 获取到目标线程的寄存器
	CONTEXT context = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thread_handle, &context);

	// 获取到 Dr7 寄存器，保存了哪些断点被使用
	PDr7 Dr7 = (PDr7)&context.Dr7;

	// 判断是哪一个断点触发了
	switch (context.Dr6 & 0xF)
	{
	case 1:
		Dr7->L0 = 0; break;
	case 2:
		Dr7->L1 = 0; break;
	case 4:
		Dr7->L2 = 0; break;
	case 8: Dr7->L3 = 0; break;
	}

	// 重新设置寄存器信息
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