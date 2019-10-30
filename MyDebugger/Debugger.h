#include <windows.h>
#include <vector>
#include <TlHelp32.h>
using namespace std;

// 调试器类: 建立调试会话、接收/处理/反馈调试信息、获取用户输入
class Debugger
{
private:
	DEBUG_EVENT m_debugEvent = { 0 };		// 调试事件的结构体
	DWORD m_continueStatus = DBG_CONTINUE;	// 处理的结果
	HANDLE m_threadHandle = NULL;			// 异常产生的线程的句柄
	HANDLE m_processHandle = NULL;			// 异常产生的进程的句柄
	bool m_isSysBPHappened = false;			// 第一个异常事件，即系统断点是否触发
	bool m_isConditonSet = false;			// 是否开启了条件断点
	bool m_isSolvePEB = false;				// 是否解决了PEB反调试
	LPVOID m_memBreakPointAddr = 0;			// 设置内存断点的位置，因为要多次设置，故保存下来
	LPVOID m_eternalPointAddr = 0;			//永久断点的地址
	LPVOID m_ConditionBreakPointAddr = 0;	// 设置条件断点的位置，因为要多次设置，故保存下来
	int m_eax = 0;							// 设置条件断点的条件，用用于对比
	PROCESS_INFORMATION m_processInfo = { 0 };							// 被调试进程信息
	enum Type { NORMAL,DRXEXE, DRXRW, MEM,CONDITION,CC}m_singleStepType;// 多个事件可触发单步异常
public:
	void Open(LPCSTR filePath);		// 打开被调试进程
	void Run();						// 处理调试事件
private:
	void OpenHandles();				// 打开进程句柄
	void CloseHandles();			// 关闭进程句柄
	void OnExceptionEvent();		// 处理异常事件
	void GetUserCommand();			// 获取输入命令
	void ShowCommandMenu();			// 显示支持命令
	void ShowModuleInfo();			// 显示模块信息
	void DebugSetPEB(HANDLE process_handle);		// 反反调试-SetPEB
	void DebugHookAPI(HANDLE process_handle);		// 反反调试-HookAPI
	void ShowRegisterInfo(HANDLE thread_handle);							// 显示寄存器信息
	void ShowMemStaInfo(HANDLE thread_handle, DWORD addr, int size);		// 显示内存/栈信息
	void ModifyAssemble(HANDLE process_handle, LPVOID addr, char * buff);	// 修改汇编指令
	void ModifyRegister(HANDLE thread_handle, char * regis, LPVOID  buff);	// 修改寄存器
	void ModifyMemory(HANDLE process_handle, LPVOID addr, char * buff);		// 修改内存
};