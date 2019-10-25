#pragma once
#include <windows.h>
#include <vector>
using namespace std;

// �ϵ���Ϣ�ṹ��
typedef struct _BREAKPOINTINFO
{
	LPVOID addr = 0;		// ��ַ
	BYTE oldOpcode = 0;		// ԭ����ָ����ڻָ�
} BREAKPOINTINFO, *PBREAKPOINTINFO;
// DR7 �Ĵ����ṹ��
typedef struct _DBG_REG7
{
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;
	unsigned : 6;// ��������Ч�ռ�
	unsigned RW0 : 2; unsigned LEN0 : 2;
	unsigned RW1 : 2; unsigned LEN1 : 2;
	unsigned RW2 : 2; unsigned LEN2 : 2;
	unsigned RW3 : 2; unsigned LEN3 : 2;
} Dr7, *PDr7;

// �ϵ��ࣺ�����࣬����/ɾ��/�޸��ϵ�
class BreakPoint
{
private:
	// �ϵ��б��������еĶϵ���Ϣ
	static vector<BREAKPOINTINFO> breakPointList;
public:
	// ����TF�����ϵ�
	static void SetTFBreakPoint(HANDLE thread_handle);
	// ����/�޸� int3-CC����ϵ�
	static void SetCCBreakPoint(HANDLE process_handle, LPVOID addr);
	static void FixCCBreakPoint(HANDLE process_handle, HANDLE thread_handle, LPVOID addr);
	// ����/�޸� DRXӲ���ϵ�
	static void SetDRXBreakPoint(HANDLE thread_handle, LPVOID addr, int type, int len);
	static void FixDRXBreakPoint(HANDLE thread_handle, LPVOID addr);
};

