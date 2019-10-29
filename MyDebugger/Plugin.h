#pragma once
#include <iostream>
#include <windows.h>
#include <locale.h>
#include <vector>
#include <string>
using namespace std;

// 用于保存所有的插件信息
typedef struct _PLGINFO
{
	HMODULE Base = 0;			// 加载基址
	char name[32] = { 0 };		// 插件的名称
} PLGINFO, *PPLGINFO;
// 函数指针
using PFUNC1 = void(*)(char*);
using PFUNC2 = void(*)();
// 插件类
class Plugin
{
private:
	static vector<PLGINFO> m_plugins;
public:
	// 加载插件
	static void LoadPlg();
	// 调用插件函数
	static void CallPlgFun();
	// 插件卸载
	static void ReleasePlg();
};

