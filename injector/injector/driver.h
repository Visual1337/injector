class driver
{
private:
	__int64(__fastcall* original_function)(void*, void*) = nullptr;

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
public:
	bool loaded = false;

	inline auto initialize() -> bool
	{
		HMODULE user32 = LoadLibrary("user32.dll");
		HMODULE win32u = LoadLibrary("win32u.dll");

		if (!win32u and !user32) {
			return false;
		}

		*(void**)&original_function = GetProcAddress(win32u, "NtGdiHT_Get8BPPMaskPalette");

		if (!original_function) {
			return false;
		}

		return true;
	}

	inline auto send_cmd(void* data, request_codes code) -> bool
	{
		if (!data || !code) {
			return false;
		}

		request_data request{ 0 };

		request.unique = unique_request;
		request.data = data;
		request.code = code;

		const auto result = original_function(&request, 0);

		if (result != success_request) {
			return false;
		}

		return true;
	}
	
	inline auto read(DWORD process_id, uintptr_t address, void* buffer, size_t size) -> bool
	{
		request_read data{ 0 };

		data.process_id = process_id;
		data.address = address;
		data.buffer = buffer;
		data.size = size;

		return send_cmd(&data, read_request);
	}

	template <typename t>
	inline auto read(DWORD process_id, uintptr_t address) -> t
	{
		t response{ };
		read(process_id, address, &response, sizeof(t));
		return response;
	}

	inline auto write(DWORD process_id, uintptr_t address, void* buffer, size_t size) -> bool
	{
		request_write data{ 0 };

		data.process_id = process_id;
		data.address = address;
		data.buffer = buffer;
		data.size = size;

		return send_cmd(&data, write_request);
	}

	template <typename t>
	inline auto write(DWORD process_id, uintptr_t address, t value) -> bool
	{
		return write(process_id, address, &value, sizeof(t));
	}

	inline auto allocate(DWORD process_id, DWORD size, DWORD protect) -> PVOID
	{
		PVOID out_address = NULL;

		request_allocate data{ 0 };

		data.process_id = process_id;
		data.out_address = &out_address;
		data.size = size;
		data.protect = protect;

		send_cmd(&data, allocate_request);

		return out_address;
	}
	inline auto get_module_base(DWORD process_id, std::string module_name) -> uintptr_t
	{
		request_base data{ 0 };

		data.process_id = process_id;
		data.handle = 0;

		std::wstring wstr{ std::wstring(module_name.begin(), module_name.end()) };

		memset(data.name, 0, sizeof(WCHAR) * 260);
		wcscpy(data.name, wstr.c_str());

		send_cmd(&data, base_request);

		return data.handle;
	}

	inline auto free(DWORD process_id, PVOID address) -> bool
	{
		request_free data{ 0 };

		data.process_id = process_id;
		data.address = address;

		return send_cmd(&data, free_request);
	}
};

static driver* comm = new driver();