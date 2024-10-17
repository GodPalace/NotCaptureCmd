#include <Windows.h>
#include <cstdio>
#include <iostream>
#include <conio.h>
using namespace std;

typedef BOOL (*PSetWindowDisplayAffinity) (HWND, DWORD);
typedef FARPROC (WINAPI *PGetProcAddress) (HMODULE, LPCSTR);
typedef HMODULE (WINAPI *PLoadLibraryA) (LPCSTR);

typedef struct _PARAM {
	FARPROC pFunc[2];	// LoadLibraryA(), GetProcAddress()
	char str[2][128];	// User32.dll, SetWindowDisplayAffinity

	HWND hWnd;
	DWORD dw;
} PARAM, *PPARAM;

DWORD WINAPI ThreadProc(LPVOID lParam) {
	PPARAM p = (PPARAM) lParam;

	HMODULE hModule = ((PLoadLibraryA) p -> pFunc[0]) (p -> str[0]);
	FARPROC pFunc = (FARPROC) ((PGetProcAddress) p -> pFunc[1]) (hModule, p -> str[1]);

	((PSetWindowDisplayAffinity) pFunc) (p -> hWnd, p -> dw);

	return 0;
}
void ThreadProcEnd() {}

void COLOR_PRINT(const char* s, int color) {
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | color);
	printf(s);
	SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | 7);
}


int main(int argc, char* argv[]) {
	if (argc != 2) {
		printf("Use: NotCaptureCmd.exe <Window Name>\n");
		return 0;
	}

	printf("===========================================\n");
	printf("= Welcome to this program                 =\n");
	printf("= By: PVPkin, GodPalace                   =\n");
	printf("===========================================\n");

	bool isHide = true;
	COLOR_PRINT("Run Mode: [h/s]\n", 14);

	char c = '.';
	while (c != 'h' && c != 's') {
		c = _getch();
	}
	isHide = (c == 'h' ? true : false);

	HWND hWnd = FindWindowA(NULL, argv[1]);
	if (hWnd == NULL) {
		COLOR_PRINT("[-] Find window fail!\n", 4);
		return 0;
	}
	else {
		COLOR_PRINT("[+] Find window successful!\n", 9);
	}

	DWORD pid, status = GetWindowThreadProcessId(hWnd, &pid);
	if (status == 0) {
		COLOR_PRINT("[-] Get window handle fail!\n", 4);
		return 0;
	}
	else {
		COLOR_PRINT("[+] Get window handle successful!\n", 9);
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		COLOR_PRINT("[-] Get handle fail!\n", 4);
		return 0;
	}
	else {
		COLOR_PRINT("[+] Get handle successful!\n", 9);
	}

	DWORD funcSize = (DWORD) ThreadProcEnd - (DWORD) ThreadProc;
	LPVOID pFunc = VirtualAllocEx(hProcess, NULL, funcSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pFunc == NULL) {
		COLOR_PRINT("[-] Create function virtual memory fail!\n", 4);
		return 0;
	}
	else {
		COLOR_PRINT("[+] Create function virtual memory successful!\n", 9);
	}

	if (WriteProcessMemory(hProcess, pFunc, (LPCVOID) ThreadProc, funcSize, NULL) == 0) {
		COLOR_PRINT("[-] Write function virtual memory fail!\n", 4);
		return 0;
	}
	else {
		COLOR_PRINT("[+] Write function virtual memory successful!\n", 9);
	}

	HMODULE kernel32 = GetModuleHandleA("Kernel32.dll");
	if (kernel32 == NULL) {
		COLOR_PRINT("[-] Get Kernel32.dll handle fail!", 4);
		return 0;
	}

	PARAM p;
	p.pFunc[0] = GetProcAddress(kernel32, "LoadLibraryA");
	p.pFunc[1] = GetProcAddress(kernel32, "GetProcAddress");
	p.hWnd = hWnd;
	p.dw = (isHide ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE);
	strcpy_s(p.str[0], "User32.dll");
	strcpy_s(p.str[1], "SetWindowDisplayAffinity");

	DWORD paramSize = sizeof(PARAM);
	LPVOID pParam = VirtualAllocEx(hProcess, NULL, paramSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pParam == NULL) {
		COLOR_PRINT("[-] Create param virtual memory fail!\n", 4);
		return 0;
	}
	else {
		COLOR_PRINT("[+] Create param virtual memory successful!\n", 9);
	}

	if (WriteProcessMemory(hProcess, pParam, (LPCVOID) &p, paramSize, NULL) == 0) {
		COLOR_PRINT("[-] Write param virtual memory fail!\n", 4);
		return 0;
	}
	else {
		COLOR_PRINT("[+] Write param virtual memory successful!\n", 9);
	}

	HANDLE hRemote = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) pFunc, pParam, 0, NULL);
	if (hRemote == NULL) {
		COLOR_PRINT("[-] Execute function fail!\n", 4);
		return 0;
	}
	else {
		COLOR_PRINT("[+] Execute function successful!\n", 9);
	}

	CloseHandle(hRemote);
	CloseHandle(hProcess);

	COLOR_PRINT("=======Successful!=======\n", 10);

	return 0;
}
