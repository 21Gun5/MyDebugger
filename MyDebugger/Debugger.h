#include <windows.h>

// ��������: �������ԻỰ������/����/����������Ϣ����ȡ�û�����
class Debugger
{
private:
	DEBUG_EVENT m_debugEvent = { 0 };// �����¼��Ľṹ��
	DWORD m_continueStatus = DBG_CONTINUE;// ����Ľ��
	HANDLE m_threadHandle = NULL;	// �쳣�������̵߳ľ��
	HANDLE m_processHandle = NULL;// �쳣�����Ľ��̵ľ��
	bool m_isSysBPHappened = false;	// ��һ���쳣�¼�����ϵͳ�ϵ��Ƿ񴥷�
public:
	void Open(LPCSTR filePath);	// �򿪱����Խ���
	void Run();					// ��������¼�
private:
	void OpenHandles();			// ��Ŀ����̾��
	void CloseHandles();		// �ر�Ŀ����̾��
	void OnExceptionEvent();	// ��������¼��е��쳣�¼�
	void GetUserCommand();		// ��ȡ�û����������
};

