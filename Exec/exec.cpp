#include<Windows.h>

extern "C" __declspec(dllexport) void __cdecl Exec(LPVOID lppath)
{
	ShellExecuteA(0, "open", (LPSTR)lppath, 0, 0, 5);
	_asm
	{
		mov eax, Exec                       //这里填入旧的入口点指令
		jmp  eax   
	}
}

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}