#include "mapper.hpp"

#include <Windows.h>
#include <iostream>

#include "utils.hpp"
#include "dxe_driver.hpp"
#include "nt.hpp"
#include "portable_executable.hpp"

void RelocateImageByDelta(portable_executable::vec_relocs relocs, const ULONG64 delta) {
	for (const auto& current_reloc : relocs) {
		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<ULONG64*>(current_reloc.address + offset) += delta;
		}
	}
}

// Fix cookie by @Jerem584
bool FixSecurityCookie(void* local_image, ULONG64 kernel_image_base)
{
	auto headers = portable_executable::get_nt_headers(local_image);
	if (!headers)
		return false;

	auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	if (!load_config_directory)
	{
		log(L"[+] Load config directory wasn't found, probably StackCookie not defined, fix cookie skipped" << std::endl);
		return true;
	}

	auto load_config_struct = (PIMAGE_LOAD_CONFIG_DIRECTORY)((uintptr_t)local_image + load_config_directory);
	auto stack_cookie = load_config_struct->SecurityCookie;
	if (!stack_cookie)
	{
		log(L"[+] StackCookie not defined, fix cookie skipped" << std::endl);
		return true; // as I said, it is not an error and we should allow that behavior
	}

	stack_cookie = stack_cookie - (uintptr_t)kernel_image_base + (uintptr_t)local_image; //since our local image is already relocated the base returned will be kernel address

	if (*(uintptr_t*)(stack_cookie) != 0x2B992DDFA232) {
		log(L"[-] StackCookie already fixed!? this probably wrong" << std::endl);
		return false;
	}

	log(L"[+] Fixing stack cookie" << std::endl);

	auto new_cookie = 0x2B992DDFA232 ^ GetCurrentProcessId() ^ GetCurrentThreadId(); // here we don't really care about the value of stack cookie, it will still works and produce nice result
	if (new_cookie == 0x2B992DDFA232)
		new_cookie = 0x2B992DDFA233;

	*(uintptr_t*)(stack_cookie) = new_cookie; // the _security_cookie_complement will be init by the driver itself if they use crt
	return true;
}

bool resolve_imports(portable_executable::vec_imports imports) {
	for (const auto& current_import : imports) {
		ULONG64 Module = utils::get_kernel_module_address(current_import.module_name);
		if (!Module) {
#if !defined(DISABLE_OUTPUT)
			std::cout << "[-] Dependency " << current_import.module_name << " wasn't found" << std::endl;
#endif
			return false;
		}

		for (auto& current_function_data : current_import.function_datas) {
			ULONG64 function_address = dxe_driver::GetKernelModuleExport(Module, current_function_data.name);

			if (!function_address) {
				// Fallback to ntoskrnl
				uint64_t ntos = utils::get_kernel_module_address("ntoskrnl.exe");
				if (ntos)
					function_address = dxe_driver::GetKernelModuleExport(ntos, current_function_data.name);
				if (!function_address) {
#if !defined(DISABLE_OUTPUT)
					std::cout << "[-] Failed to resolve import " << current_function_data.name << " (" << current_import.module_name << ")" << std::endl;
#endif
					return false;
				}
			}
			*current_function_data.address = function_address;
		}
	}
	return true;
}

ULONG64 mapper::map_driver(BYTE* data, ULONG64 param1, ULONG64 param2, bool free, bool destroyHeader, AllocationMode mode, bool PassAllocationAddressAsFirstParam, mapCallback callback, NTSTATUS* exitCode) {

	const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::get_nt_headers(data);

	if (!nt_headers) {
		log(L"[-] Invalid format of PE image" << std::endl);
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		log(L"[-] Image is not 64 bit" << std::endl);
		return 0;
	}

	ULONG32 image_size = nt_headers->OptionalHeader.SizeOfImage;

	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!local_image_base)
		return 0;

	DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
	image_size = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);

	ULONG64 kernel_image_base = 0;
	kernel_image_base = dxe_driver::AllocatePool(nt::POOL_TYPE::NonPagedPool, image_size);

	if (!kernel_image_base) {
		log(L"[-] Failed to allocate remote image in kernel" << std::endl);

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	do {
		log(L"[+] Image base has been allocated at 0x" << reinterpret_cast<void*>(kernel_image_base) << std::endl);

		// Copy image headers

		memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);

		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
			if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
				continue;
			auto local_section = reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image_base) + current_image_section[i].VirtualAddress);
			memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<ULONG64>(data) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
		}

		ULONG64 realBase = kernel_image_base;
		if (destroyHeader) {
			kernel_image_base -= TotalVirtualHeaderSize;
			log(L"[+] Skipped 0x" << std::hex << TotalVirtualHeaderSize << L" bytes of PE Header" << std::endl);
		}

		// Resolve relocs and imports

		RelocateImageByDelta(portable_executable::get_relocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		if (!FixSecurityCookie(local_image_base, kernel_image_base))
		{
			log(L"[-] Failed to fix cookie" << std::endl);
			return 0;
		}

		if (!resolve_imports(portable_executable::get_imports(local_image_base))) {
			log(L"[-] Failed to resolve imports" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		// Write fixed image to kernel

		if (!dxe_driver::WriteMemory(realBase, (PVOID)((uintptr_t)local_image_base + (destroyHeader ? TotalVirtualHeaderSize : 0)), image_size)) {
			log(L"[-] Failed to write local image to remote image" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		// Call driver entry point

		const ULONG64 address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		log(L"[<] Calling DriverEntry 0x" << reinterpret_cast<void*>(address_of_entry_point) << std::endl);

		if (callback) {
			if (!callback(&param1, &param2, realBase, image_size)) {
				log(L"[-] Callback returns false, failed!" << std::endl);
				kernel_image_base = realBase;
				break;
			}
		}

		NTSTATUS status = 0;
		if (!dxe_driver::CallKernelFunction(&status, address_of_entry_point, (PassAllocationAddressAsFirstParam ? realBase : param1), param2)) {
			log(L"[-] Failed to call driver entry" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		if (exitCode)
			*exitCode = status;

		log(L"[+] DriverEntry returned 0x" << std::hex << status << std::endl);

		// Free memory
		if (free) {
			log(L"[+] Freeing memory" << std::endl);
			bool free_status = dxe_driver::FreePool(realBase);

			if (free_status) {
				log(L"[+] Memory has been released" << std::endl);
			}
			else {
				log(L"[-] WARNING: Failed to free memory!" << std::endl);
			}
		}



		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return realBase;

	} while (false);


	VirtualFree(local_image_base, 0, MEM_RELEASE);

	log(L"[+] Freeing memory" << std::endl);
	bool free_status = dxe_driver::FreePool(kernel_image_base);

	if (free_status) {
		log(L"[+] Memory has been released" << std::endl);
	}
	else {
		log(L"[-] WARNING: Failed to free memory!" << std::endl);
	}

	return 0;
}

