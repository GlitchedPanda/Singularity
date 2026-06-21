#pragma once

#include <Windows.h>
#include <vector>
#include <string>

namespace portable_executable
{
	struct RelocInfo
	{
		ULONG64 address;
		USHORT* item;
		ULONG32 count;
	};

	struct ImportFunctionInfo
	{
		std::string name;
		ULONG64* address;
	};

	struct ImportInfo
	{
		std::string module_name;
		std::vector<ImportFunctionInfo> function_datas;
	};

	using vec_sections = std::vector<IMAGE_SECTION_HEADER>;
	using vec_relocs = std::vector<RelocInfo>;
	using vec_imports = std::vector<ImportInfo>;

	PIMAGE_NT_HEADERS64 get_nt_headers(void* image_base);
	vec_relocs get_relocs(void* image_base);
	vec_imports get_imports(void* image_base);
}