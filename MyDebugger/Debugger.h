#include <windows.h>
#include <vector>
#include <TlHelp32.h>
using namespace std;

//// ģ����Ϣ�ṹ��
//typedef struct _MYMODULEINFO
//{
//	LOAD_DLL_DEBUG_INFO dllInfo;	// ԭ����dll��Ϣ
//	TCHAR  filename[250];				// ��������
//} MYMODULEINFO, *PMYMODULEINFO;



// ��������: �������ԻỰ������/����/����������Ϣ����ȡ�û�����
class Debugger
{
private:
	DEBUG_EVENT m_debugEvent = { 0 };		// �����¼��Ľṹ��
	DWORD m_continueStatus = DBG_CONTINUE;	// ����Ľ��
	HANDLE m_threadHandle = NULL;			// �쳣�������̵߳ľ��
	HANDLE m_processHandle = NULL;			// �쳣�����Ľ��̵ľ��
	bool m_isSysBPHappened = false;			// ��һ���쳣�¼�����ϵͳ�ϵ��Ƿ񴥷�

	PROCESS_INFORMATION m_processInfo = { 0 };// �����Խ�����Ϣ

	//vector<MYMODULEINFO> m_moduleInfoList;// �����ģ���б�

	LPVOID m_memBreakPointAddr = 0;// �����ڴ�ϵ��λ�ã���ΪҪ������ã��ʱ�������
	enum Type { NORMAL, DRXEXE, DRXRW, MEM }m_singleStepType;// ����¼��ɴ��������쳣����ͨ�ġ�Ӳ��ִ��/��д�����ִ��/��/д
public:
	void Open(LPCSTR filePath);		// �򿪱����Խ���
	void Run();						// ��������¼�
private:
	void OpenHandles();				// ��Ŀ����̾��
	void CloseHandles();			// �ر�Ŀ����̾��

	void OnExceptionEvent();		// �����쳣�¼�
	//void OnLoadDLLEvent();			// ����ģ�鵼���¼�

	void GetUserCommand();			// ��ȡ�û����������

	void ShowRegisterInfo(HANDLE thread_handle);		// ��ʾ�Ĵ�����Ϣ
	void ShowStackInfo();			// ��ʾջ�ռ���Ϣ
	void ShowCommandMenu();			// ��ʾ֧�ֵ�����
	//void GetProcessAllModule(DWORD dwPid, std::vector<MODULEENTRY32>* moduleList);// ��ȡ��������ģ��
	//bool GetNameFromHandle(LOAD_DLL_DEBUG_INFO dllInfo);	
	void ShowModuleInfo();// ��ʾģ����Ϣ

	void ModifyAssemble(HANDLE process_handle, LPVOID addr, char * buff);			// �޸Ļ��ָ��
	void ModifyRegister(HANDLE thread_handle, char * regis, LPVOID  buff);			// �޸ļĴ���
	void ModifyStack();				// �޸�ջ



};

