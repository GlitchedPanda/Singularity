#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <TlHelp32.h>

#include "mapper.hpp"
#include "utils.hpp"
#include "dxe_driver.hpp"

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
		log(L"[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << L" by 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl);
	else
		log(L"[!!] Crash" << std::endl);

	return EXCEPTION_EXECUTE_HANDLER;
}

int param_exists(const int argc, wchar_t** argv, const wchar_t* param) {
	size_t plen = wcslen(param);
	for (int i = 1; i < argc; i++) {
		if (wcslen(argv[i]) == plen + 1ull && _wcsicmp(&argv[i][1], param) == 0 && argv[i][0] == '/') { // with slash
			return i;
		}
		else if (wcslen(argv[i]) == plen + 2ull && _wcsicmp(&argv[i][2], param) == 0 && argv[i][0] == '-' && argv[i][1] == '-') { // with double dash
			return i;
		}
	}
	return -1;
}

bool callback_example(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize) {
	UNREFERENCED_PARAMETER(param1);
	UNREFERENCED_PARAMETER(param2);
	UNREFERENCED_PARAMETER(allocationPtr);
	UNREFERENCED_PARAMETER(allocationSize);
	log("[+] Callback example called" << std::endl);

	/*
	This callback occurs before call driver entry and
	can be useful to pass more customized params in
	the last step of the mapping procedure since you
	know now the mapping address and other things
	*/
	return true;
}

DWORD get_parent_process()
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0, pid = GetCurrentProcessId();

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	__try {
		if (hSnapshot == INVALID_HANDLE_VALUE || hSnapshot == 0) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid) {
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));

	}
	__finally {
		if (hSnapshot != INVALID_HANDLE_VALUE && hSnapshot != 0) CloseHandle(hSnapshot);
	}
	return ppid;
}

//Help people that don't understand how to open a console
void pause_if_parent_is_explorer() {
	DWORD explorerPid = 0;
	GetWindowThreadProcessId(GetShellWindow(), &explorerPid);
	DWORD parentPid = get_parent_process();
	if (parentPid == explorerPid) {
		log(L"[+] Pausing to allow for debugging" << std::endl);
		log(L"[+] Press enter to close" << std::endl);
		std::cin.get();
	}
}

void help() {
	log(L"\r\n\r\n[!] Incorrect Usage!" << std::endl);
	log(L"[+] Usage: mapper.exe [--free][--indPages][--PassAllocationPtr][--copy-header]");

	log(L" driver" << std::endl);

	pause_if_parent_is_explorer();
}

int wmain(const int argc, wchar_t** argv) {
	SetUnhandledExceptionFilter(SimplestCrashHandler);

	bool free = param_exists(argc, argv, L"free") > 0;
	bool indPagesMode = param_exists(argc, argv, L"indPages") > 0;
	bool passAllocationPtr = param_exists(argc, argv, L"PassAllocationPtr") > 0;
	bool copyHeader = param_exists(argc, argv, L"copy-header") > 0;

	if (free) {
		log(L"[+] Free memory after driver execution enabled" << std::endl);
	}

	if (indPagesMode) {
		log(L"[-] Allocate Independent Pages mode is unsupported. Ignoring..." << std::endl);
	}

	if (passAllocationPtr) {
		log(L"[+] Pass Allocation Ptr as first param enabled" << std::endl);
	}

	if (copyHeader) {
		log(L"[+] Copying driver header enabled" << std::endl);
	}

	int drvIndex = -1;
	for (int i = 1; i < argc; i++) {
		if (std::filesystem::path(argv[i]).extension().string().compare(".sys") == 0) {
			drvIndex = i;
			break;
		}
	}

	if (drvIndex <= 0) {
		help();
		return -1;
	}

	const std::wstring driver_path = argv[drvIndex];

	if (!std::filesystem::exists(driver_path)) {
		log(L"[-] File " << driver_path << L" doesn't exist" << std::endl);
		pause_if_parent_is_explorer();
		return -1;
	}

	bool status = dxe_driver::Init();
	if (!status)
	{
		std::cout << "[-] Failed to init driver" << std::endl;
		return -1;
	}

	std::vector<uint8_t> raw_image = { 0 };
	if (!utils::read_file_to_memory(driver_path, &raw_image)) {
		log(L"[-] Failed to read image to memory" << std::endl);
		pause_if_parent_is_explorer();
		return -1;
	}

	mapper::AllocationMode mode = mapper::AllocationMode::AllocatePool;

	NTSTATUS exitCode = 0;
	if (!mapper::map_driver(raw_image.data(), 0, 0, free, !copyHeader, mode, passAllocationPtr, callback_example, &exitCode)) {
		log(L"[-] Failed to map " << driver_path << std::endl);
		pause_if_parent_is_explorer();
		return -1;
	}

	log(L"[+] success" << std::endl);

}