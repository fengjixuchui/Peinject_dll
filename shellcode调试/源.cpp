#include<windows.h>
#define  path  "Peinject_dll.bin"


void main()
{
	HANDLE hFile = CreateFileA(path, FILE_GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		return;
	}
	int filesize = GetFileSize(hFile, NULL);
	char* lpMemory = new char[filesize];
	DWORD RSize=0;
	ReadFile(hFile, lpMemory,filesize,&RSize, NULL);
	__asm {
		nop
		nop
		nop
		nop
		lea eax, lpMemory
		push eax
		ret; 
	}
}