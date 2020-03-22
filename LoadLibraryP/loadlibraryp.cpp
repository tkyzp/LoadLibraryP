/****************************
Description:load dll file
Date:2019/3/22
Version:1.0.0
Author:tkyzp,PPPPPotato,Jin
*****************************/
//#define DEBUG
#ifdef DEBUG
#define _CRT_SECURE_NO_WARNINGS
#endif // DEBUG

#include<stdio.h>
#include<stdlib.h>
#include<Windows.h>
#include<winnt.h>



int isPEfile(HANDLE hfile);
int isDLLfile(HANDLE hfile);
FARPROC getProcAddress(DWORD image_base, DWORD export_table_rva, LPCSTR function_name);
typedef void (*getFileSystemName)(LPCWSTR path);
wchar_t* c2w(const char* str);//char转wchar_t
typedef BOOL(WINAPI* DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);


int main(int argc, char* argv[]) {
	//打开文件句柄
	HANDLE fhandle = CreateFile(L"dDisk.dll",
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED,
		NULL);
	if (fhandle == INVALID_HANDLE_VALUE) {
		printf("open file error:%d", GetLastError());
		return 1;
	}

	//检查是否dll
	//判断是否PE文件
	if (!isPEfile(fhandle)) {
		CloseHandle(fhandle);
		return 2;
	}
	//读取PE文件头
	OVERLAPPED over = { 0 };
	DWORD readsize = 0;
	DWORD peaddr = 0;
	IMAGE_NT_HEADERS ntheader;
	over.Offset = 0x3c;
	ReadFile(fhandle, &peaddr, 4, &readsize, &over);
	over.Offset = peaddr;
	ReadFile(fhandle, &ntheader, sizeof(IMAGE_NT_HEADERS), &readsize, &over);
	if (!(ntheader.FileHeader.Characteristics & IMAGE_FILE_DLL)) {
		CloseHandle(fhandle);
		return 2;
	}
	//开始工作
	//分配内存
	void* image_base = VirtualAlloc((void*)ntheader.OptionalHeader.ImageBase,
		ntheader.OptionalHeader.SizeOfImage,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);
	if (image_base == NULL) {
		printf("分配内存失败:%d", GetLastError());
		CloseHandle(fhandle);
		return 3;
	}
	//将内存置0
	RtlZeroMemory(image_base, ntheader.OptionalHeader.SizeOfImage);
	int RElocation = 0;//是否需要重定位

	if ((DWORD)image_base != ntheader.OptionalHeader.ImageBase) RElocation = 1;

	//复制节及重定位（tkyzp）
	//读取节表
	IMAGE_SECTION_HEADER* section_header = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER) * ntheader.FileHeader.NumberOfSections);
	if (section_header == NULL) {
		printf("分配内存失败:%d", GetLastError());
		CloseHandle(fhandle);
		return 3;
	}
	DWORD section_header_ptr = peaddr + 0x18 + ntheader.FileHeader.SizeOfOptionalHeader;
	over.Offset = section_header_ptr;
	ReadFile(fhandle, section_header, ntheader.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), &readsize, &over);
	//遍历节表，复制节
	unsigned char* buffer = NULL;
	void* dest = NULL;
	DWORD VA = 0;
	DWORD access = 0;
	for (int i = 0; i < ntheader.FileHeader.NumberOfSections; i++) {

		//分配缓冲区
		buffer = (unsigned char*)malloc(section_header[i].SizeOfRawData);
		if (buffer == NULL) {
			printf("分配内存失败:%d", GetLastError());
			CloseHandle(fhandle);
			return 3;
		}
		//从文件中读取节

		over.Offset = section_header[i].PointerToRawData;
		ReadFile(fhandle, buffer, section_header[i].SizeOfRawData, &readsize, &over);
		//复制节
		//计算虚拟地址
		VA = (DWORD)image_base + section_header[i].VirtualAddress;
		//复制内容到虚拟地址
		RtlCopyMemory((void*)VA, buffer, section_header[i].SizeOfRawData);
		//提交更改
		dest = VirtualAlloc((void*)VA,
			section_header[i].SizeOfRawData,
			MEM_COMMIT,
			PAGE_READWRITE);
		if (dest == NULL) return 4;
		free(buffer);
	}
	//重定位
	if (RElocation) {
		//读取重定位表
		DWORD reloc_va = (DWORD)image_base + ntheader.OptionalHeader.DataDirectory[5].VirtualAddress;//重定位表虚拟地址
		DWORD reloc_size = ntheader.OptionalHeader.DataDirectory[5].Size;//重定位表大小
		DWORD reloc_offset = 0;//重定位块在重定位节中偏移
		IMAGE_BASE_RELOCATION cur_reloc_tab = { 0 };
		WORD* TypeOffset = NULL;
		while (reloc_offset < reloc_size)
		{
			cur_reloc_tab = *(IMAGE_BASE_RELOCATION*)(reloc_va + reloc_offset);//当前重定位块头
			TypeOffset = (WORD*)(reloc_va + reloc_offset + 0x8);//重定位项数组
			//需要修改重定位处
			for (int i = 0; i < cur_reloc_tab.SizeOfBlock / 2 - 4; i++) {
				if ((TypeOffset[i] & 0xf000) == 0x3000) {
					*(DWORD*)((DWORD)image_base + cur_reloc_tab.VirtualAddress + (TypeOffset[i] & 0xfff)) += (DWORD)image_base - ntheader.OptionalHeader.ImageBase;
				}
			}
			reloc_offset += cur_reloc_tab.SizeOfBlock;
		}
	}






	//解决导入表
	//TODO:
	printf("导入部分开始\n");
	IMAGE_IMPORT_DESCRIPTOR importDesc = { 0 };//引入描述符

	DWORD IDT_va = (DWORD)image_base + ntheader.OptionalHeader.DataDirectory[1].VirtualAddress;//引入目录表虚拟地址
	DWORD IDT_size = ntheader.OptionalHeader.DataDirectory[1].Size;//引入目录表大小
	DWORD IDT_offset = 0;//引入描述符在引入目录表中偏移

	while (IDT_offset < IDT_size - 0x14)//最后一个引入描述符为全零，不做处理
	{
		importDesc = *(IMAGE_IMPORT_DESCRIPTOR*)(IDT_va + IDT_offset);
		DWORD* nameRef = (DWORD*)((DWORD)image_base + importDesc.OriginalFirstThunk);//INT表
		DWORD* symbolRef = (DWORD*)((DWORD)image_base + importDesc.FirstThunk);//IAT表
		CHAR* dllname = (CHAR*)((DWORD)image_base + importDesc.Name);//dll名字
		WCHAR* w_dllname = c2w(dllname);

		HINSTANCE handle = LoadLibrary(w_dllname);//加载dll
		for (; *nameRef; nameRef++, symbolRef++)
		{
			PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)((DWORD)image_base + *nameRef);//读取函数名	
			*symbolRef = (DWORD)GetProcAddress(handle, (LPCSTR)&thunkData->Name);//写IAT表
			if (*symbolRef == 0)
			{
				return 5;
			}
		}
		IDT_offset += 0x14;//下一个引入描述符偏移
	}
	printf("导入部分结束\n");


	//解决导出表
	getFileSystemName GetFileSystemName = (getFileSystemName)getProcAddress((DWORD)image_base, ntheader.OptionalHeader.DataDirectory[0].VirtualAddress, "GetFileSystemName");


	//内存保护，设置内存权限
	for (int i = 0; i < ntheader.FileHeader.NumberOfSections; i++) {
		//获取节权限
		switch (section_header[i].Characteristics & 0xa0000000) {
		case IMAGE_SCN_MEM_EXECUTE:
			access = PAGE_EXECUTE_READ;
			break;
		case IMAGE_SCN_MEM_WRITE:
			access = PAGE_READWRITE;
			break;
		case IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE:
			access = PAGE_EXECUTE_READWRITE;
			break;
		default:
			access = PAGE_READONLY;
		}
		//计算虚拟地址
		VA = (DWORD)image_base + section_header[i].VirtualAddress;
		dest = VirtualAlloc((void*)VA,
			section_header[i].SizeOfRawData,
			MEM_COMMIT,
			access);
	}
	//调用dll入口


	//导出函数测试

	//VirtualFree(memory, ntheader.OptionalHeader.SizeOfImage,);

	CloseHandle(fhandle);
	//调用DLL入口点（由AddressOfEntryPoint定义），并因此通知库有关附加到进程的信息。
	DllEntryProc entry = (DllEntryProc)((DWORD)image_base + ntheader.OptionalHeader.AddressOfEntryPoint);
	(*entry)((HINSTANCE)image_base, DLL_PROCESS_ATTACH, 0);


	WCHAR path[4];
	swprintf(path, 4, L"%S", "F:\\123.txt");
	GetFileSystemName(path);

	/*
	unsigned char *p = (unsigned char *)GetFileSystemName;
	for (int i = 0; i < 16 * 16; i++) {
		printf("%02x  ", p[i]);
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	*/
	system("pause");
	return 0;
}
//判断是否PE文件
int isPEfile(HANDLE hfile)
{
	OVERLAPPED over = { 0 };
	DWORD readsize = 0;
	//检查MZ头
	char mz[2] = { 0 };
	ReadFile(hfile, mz, 2, &readsize, &over);
	if (mz[0] != 'M' || mz[1] != 'Z') return 0;
	//检查PE头
	DWORD peaddr = 0;
	char pe[4] = { 0 };
	over.Offset = 0x3c;
	ReadFile(hfile, &peaddr, 4, &readsize, &over);
	over.Offset = peaddr;
	ReadFile(hfile, pe, 4, &readsize, &over);
	if (pe[0] == 'P' && pe[1] == 'E' && pe[2] == '\0' && pe[3] == '\0') return 1;
	return 0;
}

//判断是否DLL文件
int isDLLfile(HANDLE hfile)
{
	//判断是否PE文件
	if (!isPEfile(hfile)) return 0;
	//读取PE文件头
	OVERLAPPED over = { 0 };
	DWORD readsize = 0;
	DWORD peaddr = 0;
	IMAGE_NT_HEADERS ntheader;
	over.Offset = 0x3c;
	ReadFile(hfile, &peaddr, 4, &readsize, &over);
	over.Offset = peaddr;
	ReadFile(hfile, &ntheader, sizeof(IMAGE_NT_HEADERS), &readsize, &over);
	if (ntheader.FileHeader.Characteristics & IMAGE_FILE_DLL) return 1;
	return 0;
}

FARPROC getProcAddress(DWORD image_base, DWORD export_table_rva, LPCSTR function_name) {
	DWORD export_table_address = (DWORD)image_base + export_table_rva;
	IMAGE_EXPORT_DIRECTORY* export_directory = (IMAGE_EXPORT_DIRECTORY*)export_table_address;
	//首先将三个数组的地址获得
	DWORD* name_point_table = (DWORD*)(image_base + export_directory->AddressOfNames);
	WORD* ordinal_table = (WORD*)(image_base + export_directory->AddressOfNameOrdinals);
	DWORD* address_table = (DWORD*)(image_base + export_directory->AddressOfFunctions);
	WORD ordinal = 0;
	DWORD* function_address = NULL;
	//访问第一个数组对应函数的下标
	bool find_function = false;//设置是否找到函数的标志。
	int index = 0;//函数找到的下标
	for (; index < export_directory->NumberOfNames; index++) {
		char* str = (char*)image_base + name_point_table[index];//指向函数名字的指针
		if (0 == strcmp(str, function_name)) {
			find_function = true;
			break;
		}
	}
	if (find_function) {
		//从DLL的引出序号表中读出序号，是两个字节的字，然后在EAT中找到函数的地址。
		ordinal = ordinal_table[index];
		if (ordinal >= export_directory->NumberOfFunctions) {
			printf("序号超过导出函数最大序号！！");
		}
		else {
			function_address = (DWORD*)(image_base + address_table[ordinal]);
		}
	}
	else {
		printf("dll中不存在此函数");
	}
	return (FARPROC)function_address;
}

wchar_t* c2w(const char* str)
{
	int length = strlen(str) + 1;
	wchar_t* t = (wchar_t*)malloc(sizeof(wchar_t) * length);
	memset(t, 0, length * sizeof(wchar_t));
	MultiByteToWideChar(CP_ACP, 0, str, strlen(str), t, length);
	return t;
}