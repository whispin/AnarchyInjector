#include <Windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <cwchar>
#include <fstream>
#include <filesystem>


HANDLE hCSGO;

HANDLE GetProcessByName(const std::string& processName) {
	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "CreateToolhelp32Snapshot failed: " << GetLastError() << std::endl;
		return NULL;
	}

	if (Process32FirstW(snapshot, &entry)) {
		do {
			std::wstring wProcessName(processName.begin(), processName.end());
			if (_wcsicmp(entry.szExeFile, wProcessName.c_str()) == 0) {
				DWORD processId = entry.th32ProcessID;
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
				if (hProcess != NULL) {
					CloseHandle(snapshot);
					return hProcess;
				}
				else {
					std::cerr << "OpenProcess failed: " << GetLastError() << std::endl;
				}
			}
		} while (Process32NextW(snapshot, &entry));
	}

	CloseHandle(snapshot);
	return NULL;
}

std::string GetFileNameFromPath(const std::string& path) {
	return std::filesystem::path(path).filename().string();
}

void OpenCSGO() {
	hCSGO = GetProcessByName("csgo.exe");
	if (!hCSGO) {
		std::cerr << "Error: Can not find game! Please launch CS:GO." << std::endl;
	}
}

bool InjectDll(const std::string& path) {
	std::ifstream file(path);
	if (!file.good()) {
		std::cerr << "Error: DLL file not found: " << path << std::endl;
		return false;
	}
	file.close();

	LPVOID allocatedMem = VirtualAllocEx(hCSGO, NULL, path.size() + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!allocatedMem) {
		std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
		return false;
	}

	SIZE_T bytesWritten;
	if (!WriteProcessMemory(hCSGO, allocatedMem, path.c_str(), path.size() + 1, &bytesWritten)) {
		std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
		VirtualFreeEx(hCSGO, allocatedMem, 0, MEM_RELEASE);
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hCSGO, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocatedMem, 0, 0);
	if (!hThread) {
		std::cerr << "CreateRemoteThread failed: " << GetLastError() << std::endl;
		VirtualFreeEx(hCSGO, allocatedMem, 0, MEM_RELEASE);
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	DWORD exitCode;
	GetExitCodeThread(hThread, &exitCode);
	
	std::cout << "DLL " << GetFileNameFromPath(path) << " injected successfully\nReturn code: " << exitCode << std::endl;

	VirtualFreeEx(hCSGO, allocatedMem, 0, MEM_RELEASE);
	CloseHandle(hThread);
	return true;
}

void pause() {
	std::cout << "Press Enter to exit...";
	std::cin.get();
}

int main(int argc, char* argv[]) {
	SetConsoleTitleA("CS:GO Injector");

	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " <dll_path>" << std::endl;
		pause();
		return 1;
	}

	std::string dllpath = argv[1];

	OpenCSGO();
	if (!hCSGO) {
		pause();
		return 1;
	}

	if (!InjectDll(dllpath)) {
		std::cerr << "Failed to InjectDll" << std::endl;
		pause();
		return 1;
	}

	CloseHandle(hCSGO);

	return 0;
}