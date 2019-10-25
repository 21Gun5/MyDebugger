#include <windows.h>

// 调试器类: 建立调试会话、接收/处理/反馈调试信息、获取用户输入
class Debugger
{
private:
	DEBUG_EVENT m_debugEvent = { 0 };// 调试事件的结构体
	DWORD m_continueStatus = DBG_CONTINUE;// 处理的结果
	HANDLE m_threadHandle = NULL;	// 异常产生的线程的句柄
	HANDLE m_processHandle = NULL;// 异常产生的进程的句柄
	bool m_isSysBPHappened = false;	// 第一个异常事件，即系统断点是否触发
public:
	void Open(LPCSTR filePath);	// 打开被调试进程
	void Run();					// 处理调试事件
private:
	void OpenHandles();			// 打开目标进程句柄
	void CloseHandles();		// 关闭目标进程句柄
	void OnExceptionEvent();	// 处理调试事件中的异常事件
	void GetUserCommand();		// 获取用户输入的命令
};

