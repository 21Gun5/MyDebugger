#include <windows.h>
#include <vector>
#include <TlHelp32.h>
using namespace std;

//// 模块信息结构体
//typedef struct _MYMODULEINFO
//{
//	LOAD_DLL_DEBUG_INFO dllInfo;	// 原来的dll信息
//	TCHAR  filename[250];				// 加上名字
//} MYMODULEINFO, *PMYMODULEINFO;



// 调试器类: 建立调试会话、接收/处理/反馈调试信息、获取用户输入
class Debugger
{
private:
	DEBUG_EVENT m_debugEvent = { 0 };		// 调试事件的结构体
	DWORD m_continueStatus = DBG_CONTINUE;	// 处理的结果
	HANDLE m_threadHandle = NULL;			// 异常产生的线程的句柄
	HANDLE m_processHandle = NULL;			// 异常产生的进程的句柄
	bool m_isSysBPHappened = false;			// 第一个异常事件，即系统断点是否触发

	PROCESS_INFORMATION m_processInfo = { 0 };// 被调试进程信息

	//vector<MYMODULEINFO> m_moduleInfoList;// 导入的模块列表

	LPVOID m_memBreakPointAddr = 0;// 设置内存断点的位置，因为要多次设置，故保存下来
	enum Type { NORMAL, DRXEXE, DRXRW, MEM }m_singleStepType;// 多个事件可触发单步异常，普通的、硬件执行/读写、软件执行/读/写
public:
	void Open(LPCSTR filePath);		// 打开被调试进程
	void Run();						// 处理调试事件
private:
	void OpenHandles();				// 打开目标进程句柄
	void CloseHandles();			// 关闭目标进程句柄

	void OnExceptionEvent();		// 处理异常事件
	//void OnLoadDLLEvent();			// 处理模块导入事件

	void GetUserCommand();			// 获取用户输入的命令

	void ShowRegisterInfo(HANDLE thread_handle);		// 显示寄存器信息
	void ShowStackInfo();			// 显示栈空间信息
	void ShowCommandMenu();			// 显示支持的命令
	//void GetProcessAllModule(DWORD dwPid, std::vector<MODULEENTRY32>* moduleList);// 获取进程所有模块
	//bool GetNameFromHandle(LOAD_DLL_DEBUG_INFO dllInfo);	
	void ShowModuleInfo();// 显示模块信息

	void ModifyAssemble(HANDLE process_handle, LPVOID addr, char * buff);			// 修改汇编指令
	void ModifyRegister(HANDLE thread_handle, char * regis, LPVOID  buff);			// 修改寄存器
	void ModifyStack();				// 修改栈



};

