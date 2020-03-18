/****************************
description:load dll file
date:2019/3/17
version:0.0.0
--tkyzp
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
int main(int argc, char* argv[]) {
	//打开文件句柄
	HANDLE fhandle = CreateFile(L"D:\\Assignment\\SoftwareSecurity\\第四次作业\\dDisk.dll",
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
		MEM_RESERVE|MEM_COMMIT,
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
	ReadFile(fhandle, section_header,ntheader.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER),&readsize,&over);
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
		/*
		//获取节权限
		switch (section_header[i].Characteristics & 0xa0000000) {
		case IMAGE_SCN_MEM_EXECUTE:
			access = PAGE_EXECUTE_READ;
			break;
		case IMAGE_SCN_MEM_WRITE:
			access = PAGE_READWRITE;
			break;
		case IMAGE_SCN_MEM_EXECUTE| IMAGE_SCN_MEM_WRITE:
			access = PAGE_EXECUTE_READWRITE;
			break;
		default:
			access = PAGE_READONLY;
		}
		*/
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






	//解决导入表（李易）
	//TODO:

	//解决导出表（刘进）
	//TODO:

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