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
	if (!isDLLfile(fhandle)) {
		printf("不是有效的dll文件");
		return 2;
	}
	//开始工作
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
