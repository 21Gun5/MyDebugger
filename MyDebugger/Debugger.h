#include <windows.h>
#include <vector>
#include <TlHelp32.h>
using namespace std;

// ��������: �������ԻỰ������/����/����������Ϣ����ȡ�û�����
class Debugger
{
private:
	DEBUG_EVENT m_debugEvent = { 0 };		// �����¼��Ľṹ��
	DWORD m_continueStatus = DBG_CONTINUE;	// ����Ľ��
	HANDLE m_threadHandle = NULL;			// �쳣�������̵߳ľ��
	HANDLE m_processHandle = NULL;			// �쳣�����Ľ��̵ľ��
	bool m_isSysBPHappened = false;			// ��һ���쳣�¼�����ϵͳ�ϵ��Ƿ񴥷�
	bool m_isConditonSet = false;			// �Ƿ����������ϵ�
	bool m_isSolvePEB = false;				// �Ƿ�����PEB������
	LPVOID m_memBreakPointAddr = 0;			// �����ڴ�ϵ��λ�ã���ΪҪ������ã��ʱ�������
	LPVOID m_eternalPointAddr = 0;			//���öϵ�ĵ�ַ
	LPVOID m_ConditionBreakPointAddr = 0;	// ���������ϵ��λ�ã���ΪҪ������ã��ʱ�������
	int m_eax = 0;							// ���������ϵ�������������ڶԱ�
	PROCESS_INFORMATION m_processInfo = { 0 };							// �����Խ�����Ϣ
	enum Type { NORMAL,DRXEXE, DRXRW, MEM,CONDITION,CC}m_singleStepType;// ����¼��ɴ��������쳣
public:
	void Open(LPCSTR filePath);		// �򿪱����Խ���
	void Run();						// ��������¼�
private:
	void OpenHandles();				// �򿪽��̾��
	void CloseHandles();			// �رս��̾��
	void OnExceptionEvent();		// �����쳣�¼�
	void GetUserCommand();			// ��ȡ��������
	void ShowCommandMenu();			// ��ʾ֧������
	void ShowModuleInfo();			// ��ʾģ����Ϣ
	void DebugSetPEB(HANDLE process_handle);		// ��������-SetPEB
	void DebugHookAPI(HANDLE process_handle);		// ��������-HookAPI
	void ShowRegisterInfo(HANDLE thread_handle);							// ��ʾ�Ĵ�����Ϣ
	void ShowMemStaInfo(HANDLE thread_handle, DWORD addr, int size);		// ��ʾ�ڴ�/ջ��Ϣ
	void ModifyAssemble(HANDLE process_handle, LPVOID addr, char * buff);	// �޸Ļ��ָ��
	void ModifyRegister(HANDLE thread_handle, char * regis, LPVOID  buff);	// �޸ļĴ���
	void ModifyMemory(HANDLE process_handle, LPVOID addr, char * buff);		// �޸��ڴ�
};