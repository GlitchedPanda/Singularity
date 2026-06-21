#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <iostream>

#include "nt.hpp"

#if defined(DISABLE_OUTPUT)
#define log(content)
#else
#define log(content) std::wcout << content
#endif

namespace utils
{
	std::wstring get_full_temp_path();
	bool read_file_to_memory(const std::wstring& file_path, std::vector<BYTE>* out_buffer);
	bool create_file_from_memory(const std::wstring& desired_file_path, const char* address, size_t size);
	uint64_t get_kernel_module_address(const std::string& module_name);
	BOOLEAN b_data_compare(const BYTE* p_data, const BYTE* b_mask, const char* sz_mask);
	uintptr_t find_pattern(uintptr_t dw_address, uintptr_t dw_len, BYTE* b_mask, const char* sz_mask);
	PVOID find_section(const char* section_name, uintptr_t module_ptr, PULONG size);
	std::wstring get_current_app_folder();
}