#include "Plugin.h"

vector<PLGINFO> Plugin::m_plugins;

// 加载插件
void Plugin::LoadPlg()
{
	string PluginPath = "./plugin/";
	string PFindluginPath = "./plugin/*.myplg";

	// 保存遍历到的文件信息
	WIN32_FIND_DATAA FileInfo = { 0 };

	// 遍历插件的路径，可以设置后缀名
	HANDLE FindHandle = FindFirstFileA(PFindluginPath.c_str(), &FileInfo);

	// 一个一个遍历
	do {

		string FilePath = PluginPath + FileInfo.cFileName;
		// 加载 DLL 文件，并且保存到一个容器
		HMODULE Handle = LoadLibraryA(FilePath.c_str());

		// 如果模块加载成功，需要插件提供自己的信息，形式就是导出一个特定的函数
		if (Handle)
		{
			PLGINFO info = { Handle };
			PFUNC1 func = (PFUNC1)GetProcAddress(Handle, "init");

			// 如果函数获取成功
			if (func)
			{
				func(info.name);
				m_plugins.push_back(info);
				printf("插件信息: %s 已被加载\n", info.name);
			}
		}

	} while (FindNextFileA(FindHandle, &FileInfo));
}
// 调用插件函数
void Plugin::CallPlgFun()
{
	// 遍历插件，调用对应的函数
	for (auto& plugin : m_plugins)
	{
		PFUNC2 func = (PFUNC2)GetProcAddress(plugin.Base, "run");
		if (func) func();
	}
}
// 插件卸载
void Plugin::ReleasePlg()
{
	// 和上面的写法类似
	for (auto& plugin : m_plugins)
	{
		FreeLibrary(plugin.Base);
	}
}

