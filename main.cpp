#include <Windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <cwchar>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <stdexcept>

#define FOREGROUND_YELLOW (FOREGROUND_RED | FOREGROUND_GREEN)
#define FOREGROUND_WHITE (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

HANDLE hProcess;

const std::string VERSION = "1.0";

void SetConsoleColor(int color) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, color);
}

void PrintBanner() {
	SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
	std::cout << "AnarchyInjector v" << VERSION << std::endl << std::endl;
	SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	std::cout << "ManualMap DLL injector for CS2 and CS:GO" << std::endl;
	std::cout << "By: dest4590" << std::endl << std::endl;
	SetConsoleColor(FOREGROUND_WHITE);
}

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

HANDLE GetProcessById(DWORD processId) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (hProcess == NULL) {
		std::cerr << "OpenProcess failed: " << GetLastError() << std::endl;
	}
	return hProcess;
}


bool IsDigits(const std::string& str) {
	return std::all_of(str.begin(), str.end(), ::isdigit);
}

std::string GetFileNameFromPath(const std::string& path) {
	return std::filesystem::path(path).filename().string();
}

bool InjectDll(const std::string& path) {
	std::ifstream file(path);
	if (!file.good()) {
		std::cerr << "DLL file not found: " << path << std::endl;
		return false;
	}
	file.close();

	LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, path.size() + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!allocatedMem) {
		std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
		return false;
	}

	SIZE_T bytesWritten;
	if (!WriteProcessMemory(hProcess, allocatedMem, path.c_str(), path.size() + 1, &bytesWritten)) {
		std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocatedMem, 0, 0);
	if (!hThread) {
		std::cerr << "CreateRemoteThread failed: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	DWORD exitCode;
	GetExitCodeThread(hThread, &exitCode);

	std::cout << "DLL ";
	SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	std::cout << GetFileNameFromPath(path);
	SetConsoleColor(FOREGROUND_WHITE);
	std::cout << " injected successfully\nReturn code: ";
	SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	std::cout << exitCode << std::endl;
	SetConsoleColor(FOREGROUND_WHITE);

	VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
	CloseHandle(hThread);
	return true;
}


void pause() {
	std::cerr << std::endl;
	system("pause");
}

int main(int argc, char* argv[]) {
	SetConsoleTitleA("AnarchyInjector");
	PrintBanner();

	std::string dllPath;
	std::string processNameOrId;

	std::string exeName = std::filesystem::path(argv[0]).filename().string();

	if (argc == 2) {
		dllPath = argv[1];
		hProcess = GetProcessByName("cs2.exe");
		if (!hProcess) {
			hProcess = GetProcessByName("csgo.exe");
			if (!hProcess) {
				std::cerr << "Could not find cs2.exe or csgo.exe.  Please launch one of the games." << std::endl;
				pause();
				return 1;
			}
			else {
				processNameOrId = "csgo.exe";
			}
		}
		else {
			processNameOrId = "cs2.exe";
		}
	}
	else if (argc == 3) {
		processNameOrId = argv[1];
		dllPath = argv[2];

		if (IsDigits(processNameOrId)) {
			try {
				DWORD processId = std::stoi(processNameOrId);
				hProcess = GetProcessById(processId);
			}
            catch (const std::invalid_argument&) {
				std::cerr << "Invalid process ID: " << processNameOrId << std::endl;
				pause();
				return 1;
            }
            catch (const std::out_of_range&) {
				std::cerr << "Process ID out of range: " << processNameOrId << std::endl;
				pause();
				return 1;
            }
		}
		else {
			hProcess = GetProcessByName(processNameOrId);
		}
		if (!hProcess) {
			std::cerr << "Can not find process: " << processNameOrId << std::endl;
			pause();
			return 1;
		}
	}
	else {
		std::cerr << "Usage: " << exeName << " <dll_path> (injector automatically finds cs2.exe or csgo.exe)\nOR: " << exeName << " <process_name_or_PID> <dll_path>" << std::endl;
		pause();
		return 1;
	}

	std::cout << "Injecting into: ";
	SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
	std::cout << processNameOrId << std::endl;
	SetConsoleColor(FOREGROUND_WHITE);

	if (!InjectDll(dllPath)) {
		SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
		std::cerr << "Failed to InjectDll" << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);
		pause();
		return 1;
	}

	CloseHandle(hProcess);

	return 0;
}