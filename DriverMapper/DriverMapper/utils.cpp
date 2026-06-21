#include "utils.hpp"
#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>

std::wstring utils::get_full_temp_path() {
	wchar_t temp_directory[MAX_PATH + 1] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);

	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
		log(L"[-] Failed to get temp path" << std::endl);
		return L"";
	}

	if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
		temp_directory[wcslen(temp_directory) - 1] = 0x0;

	return std::wstring(temp_directory);
}

bool utils::read_file_to_memory(const std::wstring& file_path, std::vector<BYTE>* out_buffer) {
	std::ifstream file_ifstream(file_path, std::ios::binary);

	if (!file_ifstream)
		return false;

	out_buffer->assign(
		std::istreambuf_iterator<char>(file_ifstream),
		std::istreambuf_iterator<char>());

	file_ifstream.close();

	return true;
}

bool utils::create_file_from_memory(
	const std::wstring& desired_file_path,
	const char* address,
	size_t size) {

	std::ofstream file_ofstream(
		desired_file_path.c_str(),
		std::ios_base::out | std::ios_base::binary);

	if (!file_ofstream.write(address, size)) {
		file_ofstream.close();
		return false;
	}

	file_ofstream.close();
	return true;
}

uint64_t utils::get_kernel_module_address(const std::string& module_name) {
	void* buffer = nullptr;
	DWORD buffer_size = 0;

	NTSTATUS status = NtQuerySystemInformation(
		static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation),
		buffer,
		buffer_size,
		&buffer_size);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(
			nullptr,
			buffer_size,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		status = NtQuerySystemInformation(
			static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation),
			buffer,
			buffer_size,
			&buffer_size);
	}

	if (!NT_SUCCESS(status)) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);

		return 0;
	}

	const auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);

	if (!modules)
		return 0;

	for (auto i = 0u; i < modules->NumberOfModules; ++i) {
		const std::string current_module_name =
			std::string(
				reinterpret_cast<char*>(modules->Modules[i].FullPathName) +
				modules->Modules[i].OffsetToFileName);

		if (!_stricmp(current_module_name.c_str(), module_name.c_str())) {
			const uint64_t result =
				reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);

			VirtualFree(buffer, 0, MEM_RELEASE);
			return result;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}

BOOLEAN utils::b_data_compare(
	const BYTE* p_data,
	const BYTE* b_mask,
	const char* sz_mask) {

	for (; *sz_mask; ++sz_mask, ++p_data, ++b_mask) {
		if (*sz_mask == 'x' && *p_data != *b_mask)
			return 0;
	}

	return (*sz_mask) == 0;
}

uintptr_t utils::find_pattern(
	uintptr_t dw_address,
	uintptr_t dw_len,
	BYTE* b_mask,
	const char* sz_mask) {

	size_t max_len = dw_len - strlen(sz_mask);

	for (uintptr_t i = 0; i < max_len; i++) {
		if (b_data_compare(
			reinterpret_cast<BYTE*>(dw_address + i),
			b_mask,
			sz_mask)) {

			return static_cast<uintptr_t>(dw_address + i);
		}
	}

	return 0;
}

PVOID utils::find_section(
	const char* section_name,
	uintptr_t module_ptr,
	PULONG size) {

	size_t name_length = strlen(section_name);

	PIMAGE_NT_HEADERS headers =
		reinterpret_cast<PIMAGE_NT_HEADERS>(
			module_ptr +
			reinterpret_cast<PIMAGE_DOS_HEADER>(module_ptr)->e_lfanew);

	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];

		if (memcmp(section->Name, section_name, name_length) == 0 &&
			name_length == strlen(reinterpret_cast<char*>(section->Name))) {

			if (!section->VirtualAddress)
				return 0;

			if (size)
				*size = section->Misc.VirtualSize;

			return reinterpret_cast<PVOID>(
				module_ptr + section->VirtualAddress);
		}
	}

	return 0;
}

std::wstring utils::get_current_app_folder() {
	wchar_t buffer[1024];

	GetModuleFileNameW(nullptr, buffer, 1024);

	std::wstring::size_type pos =
		std::wstring(buffer).find_last_of(L"\\/");

	return std::wstring(buffer).substr(0, pos);
}