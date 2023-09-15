#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <wdm.h>
#include <ntimage.h>
#include <intrin.h>

#define to_lower_c(c) ((c >= (char*)'A' && c <= (char*)'Z') ? (c + 32) : c)
#define rva(addr, size)	((uintptr_t)(addr + *(DWORD*)(addr + ((size) - 4)) + size))

extern "C"
{
	NTKERNELAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);

	NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

	NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
	NTSYSCALLAPI NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewAccessProtection, PULONG OldAccessProtection);
}

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemInformationClassMin = 0,
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemNotImplemented1 = 4,
	SystemProcessInformation = 5,
	SystemProcessesAndThreadsInformation = 5,
	SystemCallCountInfoInformation = 6,
	SystemCallCounts = 6,
	SystemDeviceInformation = 7,
	SystemConfigurationInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemProcessorTimes = 8,
	SystemFlagsInformation = 9,
	SystemGlobalFlag = 9,
	SystemCallTimeInformation = 10,
	SystemNotImplemented2 = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemLockInformation = 12,
	SystemStackTraceInformation = 13,
	SystemNotImplemented3 = 13,
	SystemPagedPoolInformation = 14,
	SystemNotImplemented4 = 14,
	SystemNonPagedPoolInformation = 15,
	SystemNotImplemented5 = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemPagefileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemInstructionEmulationCounts = 19,
	SystemVdmBopInformation = 20,
	SystemInvalidInfoClass1 = 20,
	SystemFileCacheInformation = 21,
	SystemCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemProcessorStatistics = 23,
	SystemDpcBehaviourInformation = 24,
	SystemDpcInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemNotImplemented6 = 25,
	SystemLoadImage = 26,
	SystemUnloadImage = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemTimeAdjustment = 28,
	SystemSummaryMemoryInformation = 29,
	SystemNotImplemented7 = 29,
	SystemNextEventIdInformation = 30,
	SystemNotImplemented8 = 30,
	SystemEventIdsInformation = 31,
	SystemNotImplemented9 = 31,
	SystemCrashDumpInformation = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemLoadAndCallImage = 38,
	SystemPrioritySeparation = 39,
	SystemPlugPlayBusInformation = 40,
	SystemNotImplemented10 = 40,
	SystemDockInformation = 41,
	SystemNotImplemented11 = 41,
	SystemInvalidInfoClass2 = 42,
	SystemProcessorSpeedInformation = 43,
	SystemInvalidInfoClass3 = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemSetTimeSlipEvent = 46,
	SystemCreateSession = 47,
	SystemDeleteSession = 48,
	SystemInvalidInfoClass4 = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemAddVerifier = 52,
	SystemSessionProcessesInformation = 53,
	SystemInformationClassMax
} SYSTEM_INFORMATION_CLASS;
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB_LDR_DATA {
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _PEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;
namespace crt
{
	template <typename t>
	__forceinline int strlen(t str) {
		if (!str)
		{
			return 0;
		}

		t buffer = str;

		while (*buffer)
		{
			*buffer++;
		}

		return (int)(buffer - str);
	}

	bool strcmp(const char* src, const char* dst)
	{
		if (!src || !dst)
		{
			return true;
		}

		const auto src_sz = crt::strlen(src);
		const auto dst_sz = crt::strlen(dst);

		if (src_sz != dst_sz)
		{
			return true;
		}

		for (int i = 0; i < src_sz; i++)
		{
			if (src[i] != dst[i])
			{
				return true;
			}
		}

		return false;
	}
}

typedef enum _request_codes
{
	base_request = 0x119,
	read_request = 0x129,
	write_request = 0x139,
	allocate_request = 0x149,
	free_request = 0x132,
	success_request = 0x91a,
	unique_request = 0x92b,
} request_codes, * prequest_codes;

typedef struct _request_write {
	DWORD process_id;
	uintptr_t address;
	void* buffer;
	size_t size;
} request_write, * prequest_write;

typedef struct _request_read {
	DWORD process_id;
	uintptr_t address;
	void* buffer;
	size_t size;
} request_read, * prequest_read;

typedef struct _request_allocate {
	DWORD process_id;
	PVOID out_address;
	DWORD size;
	DWORD protect;
} request_allocate, * prequest_allocate;

typedef struct _request_base {
	DWORD process_id;
	uintptr_t handle;
	WCHAR name[260];
} request_base, * prequest_base;

typedef struct _request_free {
	DWORD process_id;
	PVOID address;
} request_free, * prequest_free;

typedef struct _request_data {
	DWORD unique;
	request_codes code;
	PVOID data;
} request_data, * prequest_data;

PVOID get_system_information(SYSTEM_INFORMATION_CLASS information_class)
{
	unsigned long size = 32;
	char buffer[32];

	ZwQuerySystemInformation(information_class, buffer, size, &size);

	PVOID info = ExAllocatePoolZero(NonPagedPool, size, 0x4e754c4c);

	if (!info)
		return nullptr;

	if (!NT_SUCCESS(ZwQuerySystemInformation(information_class, info, size, &size)))
	{
		ExFreePool(info);
		return nullptr;
	}

	return info;
}
uintptr_t get_kernel_module(const char* name)
{
	PRTL_PROCESS_MODULES info = (PRTL_PROCESS_MODULES)get_system_information(SystemModuleInformation);

	if (!info)
		return NULL;

	for (size_t i = 0; i < info->NumberOfModules; ++i)
	{
		RTL_PROCESS_MODULE_INFORMATION mod = info->Modules[i];

		if (crt::strcmp(to_lower_c((char*)mod.FullPathName + mod.OffsetToFileName), name) == 0)
		{
			PVOID address = mod.ImageBase;
			ExFreePool(info);
			return (uintptr_t)address;
		}
	}

	ExFreePool(info);
	return NULL;
}
uintptr_t find_pattern(uintptr_t base, size_t range, const char* pattern, const char* mask)
{
	const auto check_mask = [](const char* base, const char* pattern, const char* mask) -> bool
	{
		for (; *mask; ++base, ++pattern, ++mask)
		{
			if (*mask == 'x' && *base != *pattern)
			{
				return false;
			}
		}

		return true;
	};

	range = range - crt::strlen(mask);

	for (size_t i = 0; i < range; ++i)
	{
		if (check_mask((const char*)base + i, pattern, mask))
		{
			return base + i;
		}
	}

	return NULL;
}
uintptr_t find_pattern(uintptr_t base, const char* pattern, const char* mask)
{
	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

	for (size_t i = 0; i < headers->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER section = &sections[i];

		if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			uintptr_t match = find_pattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);

			if (match) {
				return match;
			}
		}
	}

	return 0;
}
BOOL safe_copy(PVOID dest, PVOID src, SIZE_T size) {
	SIZE_T returnSize = 0;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), src, PsGetCurrentProcess(), dest, size, KernelMode, &returnSize)) && returnSize == size) {
		return TRUE;
	}

	return FALSE;
}
uintptr_t swap_process(uintptr_t new_process)
{
	uintptr_t current_thread = (uintptr_t)KeGetCurrentThread();

	uintptr_t apc_state = *(uintptr_t*)(current_thread + 0x98);
	uintptr_t old_process = *(uintptr_t*)(apc_state + 0x20);
	*(uintptr_t*)(apc_state + 0x20) = new_process;

	uintptr_t dir_table_base = *(uintptr_t*)(new_process + 0x28);
	__writecr3(dir_table_base);

	return old_process;
}

uintptr_t get_module_handle(DWORD process_id, LPCWSTR module_name)
{
	PEPROCESS target_proc;
	uintptr_t base = 0;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)process_id, &target_proc)))
		return 0;

	uintptr_t o_process = swap_process((uintptr_t)target_proc);

	PPEB peb = PsGetProcessPeb(target_proc);
	if (!peb)
		goto end;

	if (!peb->Ldr || !peb->Ldr->Initialized)
		goto end;

	UNICODE_STRING module_name_unicode;
	RtlInitUnicodeString(&module_name_unicode, module_name);
	for (PLIST_ENTRY list = peb->Ldr->InLoadOrderModuleList.Flink;
		list != &peb->Ldr->InLoadOrderModuleList;
		list = list->Flink) {
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (RtlCompareUnicodeString(&entry->BaseDllName, &module_name_unicode, TRUE) == 0) {
			base = (uintptr_t)entry->DllBase;
			goto end;
		}
	}

end:
	swap_process((uintptr_t)o_process);

	ObDereferenceObject(target_proc);

	return base;
}

NTSTATUS allocate(prequest_allocate args) {
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)args->process_id, &process);
	if (NT_SUCCESS(status))
	{
		PVOID address = NULL;
		SIZE_T size = args->size;

		KeAttachProcess(process);
		ZwAllocateVirtualMemory(NtCurrentProcess(), &address, 0, &size, MEM_COMMIT | MEM_RESERVE, args->protect);
		KeDetachProcess();

		safe_copy(args->out_address, &address, sizeof(address));

		ObDereferenceObject(process);
	}

	return status;
}

NTSTATUS free(prequest_free args) {
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)args->process_id, &process);
	if (NT_SUCCESS(status))
	{
		SIZE_T size = 0;

		KeAttachProcess(process);
		ZwFreeVirtualMemory(NtCurrentProcess(), &args->address, &size, MEM_RELEASE);
		KeDetachProcess();

		ObDereferenceObject(process);
	}

	return status;
}

__int64(__fastcall* original_function)(void*, void*) = nullptr;
__int64 __fastcall hooked_function(void* a1, void* a2)
{
	if (!a1 || ExGetPreviousMode() != UserMode || reinterpret_cast<request_data*>(a1)->unique != unique_request) {
		return original_function(a1, a2);
	}

	const auto request = reinterpret_cast<request_data*>(a1);

	switch (request->code)
	{
	case write_request: {
		request_write data{ 0 };

		if (!safe_copy(&data, request->data, sizeof(request_write))) {
			return 0;
		}

		if (!data.address || !data.process_id || !data.buffer || !data.size) {
			return 0;
		}

		PEPROCESS process;
		if (PsLookupProcessByProcessId((HANDLE)data.process_id, &process) == STATUS_SUCCESS)
		{
			size_t bytes = 0;
			if (MmCopyVirtualMemory(IoGetCurrentProcess(), (void*)reinterpret_cast<request_write*>(request->data)->buffer, process, (void*)data.address, data.size, KernelMode, &bytes) != STATUS_SUCCESS || bytes != data.size) {
				ObDereferenceObject(process);
				return 0;
			}

			ObDereferenceObject(process);
		}
		else
		{
			return 0;
		}

		return success_request;
	}
	case read_request: {
		request_read data{ 0 };

		if (!safe_copy(&data, request->data, sizeof(request_read))) {
			return 0;
		}

		if (!data.address || !data.process_id || !data.buffer || !data.size) {
			return 0;
		}

		PEPROCESS process;
		if (PsLookupProcessByProcessId((HANDLE)data.process_id, &process) == STATUS_SUCCESS)
		{
			size_t bytes = 0;
			if (MmCopyVirtualMemory(process, (void*)data.address, IoGetCurrentProcess(), reinterpret_cast<request_write*>(request->data)->buffer, data.size, KernelMode, &bytes) != STATUS_SUCCESS || bytes != data.size) {
				ObDereferenceObject(process);
				return 0;
			}

			ObDereferenceObject(process);
		}
		else
		{
			return 0;
		}

		return success_request;
	}
	case allocate_request: {
		request_allocate data{ 0 };

		if (!safe_copy(&data, request->data, sizeof(request_allocate))) {
			return 0;
		}

		allocate(&data);

		return success_request;
	}
	case free_request:
	{
		request_free data{ 0 };

		if (!safe_copy(&data, request->data, sizeof(request_free))) {
			return 0;
		}

		free(&data);

		return success_request;
	}
	case base_request: {
		request_base data{ 0 };

		if (!safe_copy(&data, request->data, sizeof(request_base))) {
			return 0;
		}

		if (!data.name || !data.process_id) {
			return 0;
		}

		uintptr_t base = get_module_handle(data.process_id, data.name);

		if (!base) {
			return 0;
		}

		reinterpret_cast<request_base*>(request->data)->handle = base;

		return success_request;
	}
	}

	return 0;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv_obj, PUNICODE_STRING reg_pth) {
	UNREFERENCED_PARAMETER(drv_obj);
	UNREFERENCED_PARAMETER(reg_pth);

	RTL_OSVERSIONINFOW info = { 0 };

	if (!info.dwBuildNumber) {
		RtlGetVersion(&info);
	}

	uintptr_t base = get_kernel_module("win32k.sys");

	if (!base) {
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	uintptr_t addr = find_pattern(base,
		"\x48\x8B\x05\x4D\x9E\x05\x00\x48\x85\xC0\x74\x20",
		"xxxxxx?xxxxx");

	if (!addr) {
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	addr = rva(addr, 7);

	*(void**)&original_function = _InterlockedExchangePointer((void**)addr, hooked_function);

	return STATUS_SUCCESS;
}