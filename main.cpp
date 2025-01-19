#include <Windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <cwchar>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <stdexcept>
#include <sddl.h>
#include <thread>
#include <chrono>

#define FOREGROUND_YELLOW (FOREGROUND_RED | FOREGROUND_GREEN)
#define FOREGROUND_WHITE (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

HANDLE hProcess;
std::string targetProcessName;

const std::string VERSION = "1.1";

void SetConsoleColor(int color) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, color);
}

void PrintBanner() {
	SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
	std::cout << "AnarchyInjector v" << VERSION << std::endl << std::endl;
	SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	std::cout << "ManualMap DLL injector for CS2, CS:GO and other games." << std::endl;
	std::cout << "By: dest4590" << std::endl;
	SetConsoleColor(FOREGROUND_WHITE);
}

bool IsElevated() {
	BOOL fIsElevated = FALSE;
	HANDLE hToken = NULL;
	TOKEN_ELEVATION tokenElevation;
	DWORD dwSize;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
		std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);
		return FALSE;
	}

	if (GetTokenInformation(hToken, TokenElevation, &tokenElevation, sizeof(tokenElevation), &dwSize)) {
		fIsElevated = tokenElevation.TokenIsElevated;
	}
	else {
		SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
		std::cerr << "GetTokenInformation failed: " << GetLastError() << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);
	}

	if (hToken) {
		CloseHandle(hToken);
	}
	return fIsElevated;
}

HANDLE GetProcessByName(const std::string& processName) {
	DWORD desiredAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
	if (IsElevated()) {
		desiredAccess = PROCESS_ALL_ACCESS;
	}

	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snapshot == INVALID_HANDLE_VALUE) {
		SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
		std::cerr << "CreateToolhelp32Snapshot failed: " << GetLastError() << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);
		return NULL;
	}

	if (Process32FirstW(snapshot, &entry)) {
		do {
			std::wstring wProcessName(processName.begin(), processName.end());
			if (_wcsicmp(entry.szExeFile, wProcessName.c_str()) == 0) {
				DWORD processId = entry.th32ProcessID;
				HANDLE hProcess = OpenProcess(desiredAccess, FALSE, processId);
				if (hProcess != NULL) {
					CloseHandle(snapshot);
					targetProcessName = processName;
					return hProcess;
				}
				else {
					SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
					std::cerr << "OpenProcess failed for process '" << processName << "' (PID: " << processId << "): " << GetLastError() << std::endl;
					SetConsoleColor(FOREGROUND_WHITE);
				}
			}
		} while (Process32NextW(snapshot, &entry));
	}

	CloseHandle(snapshot);
	return NULL;
}

HANDLE GetProcessById(DWORD processId) {
	DWORD desiredAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
	if (IsElevated()) {
		desiredAccess = PROCESS_ALL_ACCESS;
	}
	HANDLE hProcess = OpenProcess(desiredAccess, FALSE, processId);
	if (hProcess == NULL) {
		SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
		std::cerr << "OpenProcess failed for PID " << processId << ": " << GetLastError() << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);
	}
	else {
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (snapshot != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32W entry;
			entry.dwSize = sizeof(PROCESSENTRY32W);
			if (Process32FirstW(snapshot, &entry)) {
				do {
					if (entry.th32ProcessID == processId) {
						int count = WideCharToMultiByte(CP_UTF8, 0, entry.szExeFile, -1, NULL, 0, NULL, NULL);
						if (count > 0) {
							targetProcessName.resize(count);
							WideCharToMultiByte(CP_UTF8, 0, entry.szExeFile, -1, &targetProcessName[0], count, NULL, NULL);
							targetProcessName.pop_back();
						}
						else {
							SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
							std::cerr << "Warning: Could not convert process name for PID " << processId << std::endl;
							SetConsoleColor(FOREGROUND_WHITE);
							targetProcessName = std::to_string(processId);
						}
						break;
					}
				} while (Process32NextW(snapshot, &entry));
			}
			CloseHandle(snapshot);
		}
		else {
			SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
			std::cerr << "Warning: Could not retrieve process name for PID " << processId << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			targetProcessName = std::to_string(processId);
		}
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
	std::filesystem::path dllPath = std::filesystem::absolute(path);
	std::string absoluteDllPath = dllPath.string();
	std::string dllFileName = GetFileNameFromPath(absoluteDllPath);

	SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
	std::cout << "Attempting to inject DLL: " << dllFileName << " into process: " << targetProcessName << std::endl;
	SetConsoleColor(FOREGROUND_WHITE);

	std::ifstream file(absoluteDllPath);
	if (!file.good()) {
		SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
		std::cerr << "Error: DLL file not found: " << absoluteDllPath << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);
		return false;
	}
	file.close();
	std::cout << "[+] DLL file found." << std::endl;

	if (dllFileName == "skeet.dll") {
		SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
		std::cout << "Performing skeet-specific injection..." << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);

		VirtualAllocEx(hProcess, (LPVOID)0x43310000, 0x2FC000u, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // for skeet
		VirtualAllocEx(hProcess, 0, 0x1000u, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // for skeet

		LPVOID lpPathAddress = VirtualAllocEx(hProcess, nullptr, absoluteDllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (lpPathAddress == nullptr) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: VirtualAllocEx failed (skeet path alloc): " << GetLastError() << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			return false;
		}
		SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		std::cout << "Memory allocated for path at address: " << lpPathAddress << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);

		if (!WriteProcessMemory(hProcess, lpPathAddress, absoluteDllPath.c_str(), absoluteDllPath.size() + 1, nullptr)) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: WriteProcessMemory failed (skeet path write): " << GetLastError() << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			VirtualFreeEx(hProcess, lpPathAddress, 0, MEM_RELEASE);
			return false;
		}
		std::cout << "[+] DLL path written successfully." << std::endl;

		HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
		if (!hKernel32) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: GetModuleHandleA failed for kernel32.dll" << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			VirtualFreeEx(hProcess, lpPathAddress, 0, MEM_RELEASE);
			return false;
		}

		FARPROC lpLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
		if (!lpLoadLibraryA) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: GetProcAddress failed for LoadLibraryA" << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			VirtualFreeEx(hProcess, lpPathAddress, 0, MEM_RELEASE);
			return false;
		}
		std::cout << "[+] LoadLibraryA address found." << std::endl;

		HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)lpLoadLibraryA, lpPathAddress, 0, nullptr);
		if (!hThread) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: CreateRemoteThread failed (skeet injection): " << GetLastError() << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			VirtualFreeEx(hProcess, lpPathAddress, 0, MEM_RELEASE);
			return false;
		}
		SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		std::cout << "Remote thread created with handle: " << hThread << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);

		WaitForSingleObject(hThread, INFINITE);
		DWORD exitCode;
		GetExitCodeThread(hThread, &exitCode);

		std::cout << "DLL ";
		SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		std::cout << dllFileName;
		SetConsoleColor(FOREGROUND_WHITE);
		std::cout << " injected successfully into ";
		SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
		std::cout << targetProcessName;
		SetConsoleColor(FOREGROUND_WHITE);
		std::cout << ", Return code: ";
		SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
		std::cout << exitCode << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);

		CloseHandle(hThread);
		std::cout << "[+] Injection completed (skeet)." << std::endl;
		return true;
	}
	else {
		SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
		std::cout << "Allocating memory in target process..." << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);
		LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, absoluteDllPath.size() + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!allocatedMem) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: VirtualAllocEx failed: " << GetLastError() << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			return false;
		}
		SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		std::cout << "Memory allocated at address: " << allocatedMem << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);

		SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
		std::cout << "Writing DLL path to target process..." << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);
		SIZE_T bytesWritten;
		if (!WriteProcessMemory(hProcess, allocatedMem, absoluteDllPath.c_str(), absoluteDllPath.size() + 1, &bytesWritten)) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: WriteProcessMemory failed: " << GetLastError() << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
			return false;
		}
		SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		std::cout << "Successfully wrote " << bytesWritten << " bytes to target process." << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);

		SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
		std::cout << "Creating remote thread in target process..." << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);
		HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocatedMem, 0, 0);
		if (!hThread) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: CreateRemoteThread failed: " << GetLastError() << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
			return false;
		}
		SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		std::cout << "Remote thread created with handle: " << hThread << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);

		WaitForSingleObject(hThread, INFINITE);
		DWORD exitCode;
		GetExitCodeThread(hThread, &exitCode);

		std::cout << "DLL ";
		SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		std::cout << dllFileName;
		SetConsoleColor(FOREGROUND_WHITE);
		std::cout << " injected successfully into ";
		SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
		std::cout << targetProcessName;
		SetConsoleColor(FOREGROUND_WHITE);
		std::cout << ", Return code: ";
		SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
		std::cout << exitCode << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);

		VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
		CloseHandle(hThread);
		std::cout << "[+] Injection completed." << std::endl;
		return true;
	}
}

namespace HookBypass {
	void LoadLib() {
		if (!GetModuleHandleW(L"kernel32")) LoadLibraryW(L"kernel32");
		if (!GetModuleHandleW(L"ntdll")) LoadLibraryW(L"ntdll");
		if (!GetModuleHandleW(L"KernelBase")) LoadLibraryW(L"KernelBase");
	}

	BOOL UnhookMethod(const char* methodName, const wchar_t* dllName, PBYTE save_origin_bytes) {
		HMODULE hModule = GetModuleHandleW(dllName);
		if (!hModule) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: GetModuleHandleW failed for " << dllName << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			return FALSE;
		}
		LPVOID oriMethodAddr = GetProcAddress(hModule, methodName);
		if (!oriMethodAddr) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: GetProcAddress failed for " << methodName << " in " << dllName << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			return FALSE;
		}
		PBYTE originalGameBytes[6];
		if (!ReadProcessMemory(hProcess, oriMethodAddr, originalGameBytes, sizeof(char) * 6, NULL)) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: ReadProcessMemory failed for " << methodName << " in " << dllName << ": " << GetLastError() << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			return FALSE;
		}
		memcpy_s(save_origin_bytes, sizeof(char) * 6, originalGameBytes, sizeof(char) * 6);
		PBYTE originalDllBytes[6];
		memcpy_s(originalDllBytes, sizeof(char) * 6, oriMethodAddr, sizeof(char) * 6);
		if (!WriteProcessMemory(hProcess, oriMethodAddr, originalDllBytes, sizeof(char) * 6, NULL)) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: WriteProcessMemory failed for " << methodName << " in " << dllName << ": " << GetLastError() << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			return FALSE;
		}
		return TRUE;
	}

	BOOL RestoreOriginalHook(const char* methodName, const wchar_t* dllName, PBYTE save_origin_bytes) {
		HMODULE hModule = GetModuleHandleW(dllName);
		if (!hModule) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: GetModuleHandleW failed for " << dllName << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			return FALSE;
		}
		LPVOID oriMethodAddr = GetProcAddress(hModule, methodName);
		if (!oriMethodAddr) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: GetProcAddress failed for " << methodName << " in " << dllName << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			return FALSE;
		}
		if (!WriteProcessMemory(hProcess, oriMethodAddr, save_origin_bytes, sizeof(char) * 6, NULL)) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Error: WriteProcessMemory failed for " << methodName << " in " << dllName << ": " << GetLastError() << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			return FALSE;
		}
		return TRUE;
	}

	enum MethodNum {
		LOADLIBEXW = 1,
		VIRALLOC = 2,
		FREELIB = 3,
		LOADLIBEXA = 4,
		LOADLIBW = 5,
		LOADLIBA = 6,
		VIRALLOCEX = 7,
		LDRLOADDLL = 10,
		NTOPENFILE = 11,
		VIRPROT = 12,
		CREATPROW = 13,
		CREATPROA = 14,
		VIRPROTEX = 15,
		FREELIB_ = 16,
		LOADLIBEXA_ = 17,
		LOADLIBEXW_ = 18,
		RESUMETHREAD = 19,
	};
	BYTE originalGameBytess[30][6];
	BOOL BypassCSGO_hook() {
		BOOL res = TRUE;
		res &= UnhookMethod("LoadLibraryExW", L"kernel32", originalGameBytess[LOADLIBEXW]);
		res &= UnhookMethod("VirtualAlloc", L"kernel32", originalGameBytess[VIRALLOC]);
		res &= UnhookMethod("FreeLibrary", L"kernel32", originalGameBytess[FREELIB]);
		res &= UnhookMethod("LoadLibraryExA", L"kernel32", originalGameBytess[LOADLIBEXA]);
		res &= UnhookMethod("LoadLibraryW", L"kernel32", originalGameBytess[LOADLIBW]);
		res &= UnhookMethod("LoadLibraryA", L"kernel32", originalGameBytess[LOADLIBA]);
		res &= UnhookMethod("VirtualAllocEx", L"kernel32", originalGameBytess[VIRALLOCEX]);
		res &= UnhookMethod("LdrLoadDll", L"ntdll", originalGameBytess[LDRLOADDLL]);
		res &= UnhookMethod("NtOpenFile", L"ntdll", originalGameBytess[NTOPENFILE]);
		res &= UnhookMethod("VirtualProtect", L"kernel32", originalGameBytess[VIRPROT]);
		res &= UnhookMethod("CreateProcessW", L"kernel32", originalGameBytess[CREATPROW]);
		res &= UnhookMethod("CreateProcessA", L"kernel32", originalGameBytess[CREATPROA]);
		res &= UnhookMethod("VirtualProtectEx", L"kernel32", originalGameBytess[VIRPROTEX]);
		res &= UnhookMethod("FreeLibrary", L"KernelBase", originalGameBytess[FREELIB_]);
		res &= UnhookMethod("LoadLibraryExA", L"KernelBase", originalGameBytess[LOADLIBEXA_]);
		res &= UnhookMethod("LoadLibraryExW", L"KernelBase", originalGameBytess[LOADLIBEXW_]);
		res &= UnhookMethod("ResumeThread", L"KernelBase", originalGameBytess[RESUMETHREAD]);
		return res;
	}
	BOOL RestoreCSGO_hook() {
		BOOL res = TRUE;
		res &= RestoreOriginalHook("LoadLibraryExW", L"kernel32", originalGameBytess[LOADLIBEXW]);
		res &= RestoreOriginalHook("VirtualAlloc", L"kernel32", originalGameBytess[VIRALLOC]);
		res &= RestoreOriginalHook("FreeLibrary", L"kernel32", originalGameBytess[FREELIB]);
		res &= RestoreOriginalHook("LoadLibraryExA", L"kernel32", originalGameBytess[LOADLIBEXA]);
		res &= RestoreOriginalHook("LoadLibraryW", L"kernel32", originalGameBytess[LOADLIBW]);
		res &= RestoreOriginalHook("LoadLibraryA", L"kernel32", originalGameBytess[LOADLIBA]);
		res &= RestoreOriginalHook("VirtualAllocEx", L"kernel32", originalGameBytess[VIRALLOCEX]);
		res &= RestoreOriginalHook("LdrLoadDll", L"ntdll", originalGameBytess[LDRLOADDLL]);
		res &= RestoreOriginalHook("NtOpenFile", L"ntdll", originalGameBytess[NTOPENFILE]);
		res &= RestoreOriginalHook("VirtualProtect", L"kernel32", originalGameBytess[VIRPROT]);
		res &= RestoreOriginalHook("CreateProcessW", L"kernel32", originalGameBytess[CREATPROW]);
		res &= RestoreOriginalHook("CreateProcessA", L"kernel32", originalGameBytess[CREATPROA]);
		res &= RestoreOriginalHook("VirtualProtectEx", L"kernel32", originalGameBytess[VIRPROTEX]);
		res &= RestoreOriginalHook("FreeLibrary", L"KernelBase", originalGameBytess[FREELIB_]);
		res &= RestoreOriginalHook("LoadLibraryExA", L"KernelBase", originalGameBytess[LOADLIBEXA_]);
		res &= RestoreOriginalHook("LoadLibraryExW", L"KernelBase", originalGameBytess[LOADLIBEXW_]);
		res &= RestoreOriginalHook("ResumeThread", L"KernelBase", originalGameBytess[RESUMETHREAD]);
		return res;
	}
}

int main(int argc, char* argv[]) {
	SetConsoleTitleA("AnarchyInjector");

	if (argc == 1) {
		PrintBanner();
	}

	if (IsElevated()) {
		SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		std::cout << "[+] Injector is running with administrator privileges." << std::endl;
	}

	SetConsoleColor(FOREGROUND_WHITE);
	std::cout << std::endl;

	std::string dllPath;
	std::string processNameOrId;

	std::string exeName = std::filesystem::path(argv[0]).filename().string();

	if (argc == 2) {
		dllPath = argv[1];
		hProcess = GetProcessByName("cs2.exe");
		if (!hProcess) {
			hProcess = GetProcessByName("csgo.exe");
			if (!hProcess) {
				hProcess = GetProcessByName("RustClient.exe");
				if (!hProcess) {
					SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
					std::cerr << "Could not find cs2.exe, csgo.exe, or RustClient.exe. Please launch one of the games." << std::endl;
					SetConsoleColor(FOREGROUND_WHITE);
					return 1;
				}
				else {
					processNameOrId = "RustClient.exe";
				}
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
				std::wstring targetNameString;
				hProcess = GetProcessById(processId);
			}
			catch (const std::invalid_argument&) {
				SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
				std::cerr << "Invalid process ID: " << processNameOrId << std::endl;
				SetConsoleColor(FOREGROUND_WHITE);

				return 1;
			}
			catch (const std::out_of_range&) {
				SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
				std::cerr << "Process ID out of range: " << processNameOrId << std::endl;
				SetConsoleColor(FOREGROUND_WHITE);

				return 1;
			}
		}
		else {
			hProcess = GetProcessByName(processNameOrId);
		}
		if (!hProcess) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Can not find process: " << processNameOrId << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);

			return 1;
		}
	}
	else {
		SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
		std::cerr << "Usage: " << exeName << " <dll_path> (injector automatically finds cs2.exe, csgo.exe or RustClient.exe)\nOR: " << exeName << " <process_name_or_PID> <dll_path>" << std::endl << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);

		system("pause");

		return 1;
	}

	std::cout << "Injecting into: ";
	SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
	std::cout << targetProcessName << std::endl;
	SetConsoleColor(FOREGROUND_WHITE);

	HookBypass::LoadLib();
	if (targetProcessName == "cs2.exe" || targetProcessName == "csgo.exe") {
		if (!HookBypass::BypassCSGO_hook()) {
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
			std::cerr << "Failed to bypass VAC hooks!" << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
			return 1;
		}
		std::cout << "[+] VAC hooks bypassed." << std::endl;
	}
	else {
		SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
		std::cout << "[!] VAC bypass not applied as the target process is not CS2 or CS:GO." << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);
	}

	if (!InjectDll(dllPath)) {
		SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
		std::cerr << "Failed to InjectDll" << std::endl;
		SetConsoleColor(FOREGROUND_WHITE);
		if (targetProcessName == "cs2.exe" || targetProcessName == "csgo.exe") {
			if (!HookBypass::RestoreCSGO_hook()) {
				SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
				std::cerr << "Failed to restore VAC hooks. This might lead to a ban." << std::endl;
				SetConsoleColor(FOREGROUND_WHITE);
			}
		}
		return 1;
	}

	if (targetProcessName == "cs2.exe" || targetProcessName == "csgo.exe") {
		if (!HookBypass::RestoreCSGO_hook()) {
			SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
			std::cerr << "Warning: Failed to restore VAC hooks! This may result in a VAC ban." << std::endl;
			SetConsoleColor(FOREGROUND_WHITE);
		}
		else {
			std::cout << "[+] VAC hooks restored." << std::endl;
		}
	}

	CloseHandle(hProcess);

	return 0;
}