#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <thread>

#pragma warning(disable : 4996)

#include "driver.h"

BYTE remote_call_dll_main[92] = {
	0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24,
	0x20, 0x83, 0x38, 0x00, 0x75, 0x39, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48,
	0x8B, 0x40, 0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B,
	0x48, 0x10, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
}; DWORD shell_data_offset = 0x6;

typedef struct _main_struct {
	INT status;
	uintptr_t dll_main;
	HINSTANCE dll_base;
} main_struct, * pmain_struct;

auto get_process_id(std::string name) -> DWORD
{
	const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 entry{ };
	entry.dwSize = sizeof(PROCESSENTRY32);

	Process32First(snapshot, &entry);
	do
	{
		if (!name.compare(entry.szExeFile))
		{
			return entry.th32ProcessID;
		}

	} while (Process32Next(snapshot, &entry));

	return 0;
}

auto get_nt_headers(uintptr_t raw_data) -> IMAGE_NT_HEADERS*
{
	IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(raw_data);

	return reinterpret_cast<IMAGE_NT_HEADERS*>(raw_data + dos_header->e_lfanew);
}

auto rva_va(uintptr_t rva, IMAGE_NT_HEADERS* nt_header, uint8_t* raw_data) -> void*
{
	PIMAGE_SECTION_HEADER first_section = IMAGE_FIRST_SECTION(nt_header);

	for (PIMAGE_SECTION_HEADER section = first_section; section < first_section + nt_header->FileHeader.NumberOfSections; section++)
	{
		if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize)
		{
			return (unsigned char*)raw_data + section->PointerToRawData + (rva - section->VirtualAddress);
		}
	}

	return 0;
}

auto resolve_function_address(LPCSTR module_name, LPCSTR function_name) -> uintptr_t
{
	HMODULE handle = LoadLibraryExA(module_name, nullptr, DONT_RESOLVE_DLL_REFERENCES);

	uintptr_t offset = (uintptr_t)GetProcAddress(handle, function_name) - (uintptr_t)handle;

	FreeLibrary(handle);

	return offset;
}

auto erase_discardable_section(DWORD process_id, PVOID base, IMAGE_NT_HEADERS* nt_header) -> void
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);

	for (WORD count = 0; count < nt_header->FileHeader.NumberOfSections; count++, section++)
	{
		if (section->SizeOfRawData == 0)
			continue;

		if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
			LPVOID zero_memory = VirtualAlloc(0, section->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

			comm->write(process_id, (uintptr_t)((uintptr_t)base + section->VirtualAddress), (void*)zero_memory, section->SizeOfRawData);

			VirtualFree(zero_memory, 0, MEM_RELEASE);
		}
	}
}

auto map_pe_sections(DWORD process_id, PVOID base, uint8_t* raw_data, IMAGE_NT_HEADERS* nt_header) -> void
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);

	for (WORD count = 0; count < nt_header->FileHeader.NumberOfSections; count++, section++) {
		comm->write(process_id, (uintptr_t)((uintptr_t)base + section->VirtualAddress), (void*)((uintptr_t)raw_data + section->PointerToRawData), section->SizeOfRawData);
	}
}

auto resolve_import(uint8_t* raw_data, IMAGE_NT_HEADERS* nt_header) -> bool
{
	IMAGE_IMPORT_DESCRIPTOR* import_description = (IMAGE_IMPORT_DESCRIPTOR*)rva_va(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, nt_header, raw_data);

	if (!nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || !nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		return true;

	LPSTR module_name = NULL;

	while (module_name = (LPSTR)rva_va(import_description->Name, nt_header, raw_data))
	{
		uintptr_t base_image = (uintptr_t)LoadLibraryA(module_name);

		if (!base_image)
			return false;

		IMAGE_THUNK_DATA* import_header_data = (IMAGE_THUNK_DATA*)rva_va(import_description->FirstThunk, nt_header, raw_data);

		while (import_header_data->u1.AddressOfData)
		{
			if (import_header_data->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				import_header_data->u1.Function = base_image + resolve_function_address(module_name, (LPCSTR)(import_header_data->u1.Ordinal & 0xFFFF));
			}
			else
			{
				IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)rva_va(import_header_data->u1.AddressOfData, nt_header, raw_data);
				import_header_data->u1.Function = base_image + resolve_function_address(module_name, (LPCSTR)ibn->Name);
			}
			import_header_data++;
		}
		import_description++;
	}

	return true;
}

auto relocate_image(PVOID base, uint8_t* raw_data, IMAGE_NT_HEADERS* nt_header) -> bool
{
	typedef struct _reloc_entry
	{
		ULONG to_rva;
		ULONG size;
		struct
		{
			WORD offset : 12;
			WORD type : 4;
		} item[1];
	} reloc_entry, * preloc_entry;

	uintptr_t delta_offset = (uintptr_t)base - nt_header->OptionalHeader.ImageBase;

	if (!delta_offset)
		return true;

	if (!nt_header->OptionalHeader.DllCharacteristics & !IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		return false;

	reloc_entry* relocation_entry = (reloc_entry*)rva_va(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_header, raw_data);
	uintptr_t relocation_end = (uintptr_t)relocation_entry + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if (relocation_entry == nullptr)
		return true;

	while ((uintptr_t)relocation_entry < relocation_end && relocation_entry->size)
	{
		DWORD records_count = (relocation_entry->size - 8) >> 1;

		for (DWORD i = 0; i < records_count; i++)
		{
			WORD fixed_type = (relocation_entry->item[i].type);
			WORD shift_delta = (relocation_entry->item[i].offset) % 4096;

			if (fixed_type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			if (fixed_type == IMAGE_REL_BASED_HIGHLOW || fixed_type == IMAGE_REL_BASED_DIR64)
			{
				uintptr_t fixed_va = (uintptr_t)rva_va(relocation_entry->to_rva, nt_header, raw_data);

				if (!fixed_va) {
					fixed_va = (uintptr_t)raw_data;
				}

				*(uintptr_t*)(fixed_va + shift_delta) += delta_offset;
			}
		}

		relocation_entry = (preloc_entry)((LPBYTE)relocation_entry + relocation_entry->size);
	}

	return true;
}

auto vmt_hook(DWORD process_id, DWORD thread_id, PVOID base, IMAGE_NT_HEADERS* nt_header) -> bool
{
	HMODULE ntdll = LoadLibraryW(L"ntdll.dll");

	if (!ntdll) {
		return false;
	}

	PVOID alloc_shell_code = comm->allocate(process_id, 0x1000, PAGE_EXECUTE_READWRITE);

	if (!alloc_shell_code) {
		return false;
	}

	size_t shell_size = sizeof(remote_call_dll_main) + sizeof(main_struct);
	PVOID alloc_local = VirtualAlloc(NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	RtlCopyMemory(alloc_local, &remote_call_dll_main, sizeof(remote_call_dll_main));
	ULONGLONG shell_data = (ULONGLONG)alloc_shell_code + sizeof(remote_call_dll_main);
	*(ULONGLONG*)((ULONGLONG)alloc_local + shell_data_offset) = shell_data;

	pmain_struct main_data = (pmain_struct)((ULONGLONG)alloc_local + sizeof(remote_call_dll_main));
	main_data->dll_base = (HINSTANCE)base;
	main_data->dll_main = ((ULONGLONG)base + nt_header->OptionalHeader.AddressOfEntryPoint);
	if (!comm->write(process_id, (uintptr_t)alloc_shell_code, (void*)alloc_local, shell_size)) {
		return false;
	}

	HHOOK hhook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)alloc_shell_code, ntdll, thread_id);
	while (main_data->status != 2) {
		PostThreadMessage(thread_id, WM_NULL, 0, 0);
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		comm->read(process_id, (uintptr_t)shell_data, (void*)main_data, sizeof(main_struct));
	}

	UnhookWindowsHookEx(hhook);

	BYTE zero_shell[116ui64] = { 0 };
	if (!comm->write(process_id, (uintptr_t)alloc_shell_code, zero_shell, 116ui64)) {
		return false;
	}

	if (!comm->free(process_id, alloc_shell_code)) {
		return false;
	}

	VirtualFree(alloc_local, 0, MEM_RELEASE);

	return true;
}

bool map(DWORD process_id, uint8_t* raw_data)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)raw_data;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(&raw_data[dos_header->e_lfanew]);
	if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}

	PVOID base = comm->allocate(process_id, nt_header->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READ); //this is the detection vector

	if (!relocate_image(base, raw_data, nt_header)) {
		return false;
	}

	if (!resolve_import(raw_data, nt_header)) {
		return false;
	}

	map_pe_sections(process_id, base, raw_data, nt_header);
	erase_discardable_section(process_id, base, nt_header);

	DWORD thread_id = GetWindowThreadProcessId(FindWindowA(NULL, "RustClient"), NULL);

	if (!thread_id) {
		return false;
	}

	printf("fuck")

		; if (!vmt_hook(process_id, thread_id, base, nt_header)) {
			return false;
		}

	VirtualFree(raw_data, 0, MEM_RELEASE);
}

int main()
{
	DWORD process_id = get_process_id("RustClient.exe");

	while (process_id == 0) { process_id = get_process_id("RustClient.exe"); }

	if (comm->initialize()) {

		std::cout << std::hex << comm->get_module_base(process_id, "RustClient.exe") << "\n";

		std::vector<uint8_t> raw_image = { 0 };
		std::ifstream file_ifstream("dev.dll", std::ios::binary);

		raw_image.assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
		file_ifstream.close();

		map(process_id, raw_image.data());
	}

	while (true) {}
}