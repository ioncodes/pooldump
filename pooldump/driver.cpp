#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>

#define TAG 'enoN'
#define LOG(x, ...) DbgPrint("[pooldump] " x, __VA_ARGS__)
#define STATUS_ASSERT(x) \
	do { \
		if (!NT_SUCCESS(x)) \
			LOG("NTSTATUS = %x\n", x); \
		NT_VERIFY(NT_SUCCESS(x)); \
	} while (0)

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union
	{
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union
	{
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION
{
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBigPoolInformation = 0x42
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* ZwQuerySystemInformation)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength);

ZwQuerySystemInformation k_ZwQuerySystemInformation = nullptr;

template<class Routine>
Routine GetProcAddress(
	_In_ const wchar_t* Name)
{
    UNICODE_STRING routine{};
	Routine ptr{};

    RtlInitUnicodeString(&routine, Name);

    ptr = reinterpret_cast<Routine>(
		MmGetSystemRoutineAddress(&routine));
	STATUS_ASSERT(ptr != nullptr);

    return ptr;
}

SYSTEM_BIGPOOL_INFORMATION* FetchPoolInformation()
{
	SYSTEM_BIGPOOL_INFORMATION* query{};
	NTSTATUS status{};
	ULONG size{};

	do
	{
		query = static_cast<SYSTEM_BIGPOOL_INFORMATION*>(
			ExAllocatePoolWithTag(NonPagedPoolNx, size, TAG));
		ASSERT(query != nullptr);

		status = k_ZwQuerySystemInformation(SystemBigPoolInformation, query, size, &size);

		if (NT_SUCCESS(status))
			break;

		ExFreePoolWithTag(query, TAG);
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	STATUS_ASSERT(status);

	return query;
}

VOID DumpPools(VOID* ctx)
{
	UNREFERENCED_PARAMETER(ctx);

	OBJECT_ATTRIBUTES attributes{};
	IO_STATUS_BLOCK statusBlock{};
	UNICODE_STRING dumpFile{};
	WCHAR emptyBuffer[64]{};
	NTSTATUS status{};
	HANDLE handle{};
	UINT8* buffer{};
	ULONG size{};

	LOG("Loaded driver\n");

	k_ZwQuerySystemInformation =
		GetProcAddress<ZwQuerySystemInformation>(L"ZwQuerySystemInformation");

	SYSTEM_BIGPOOL_INFORMATION* information = FetchPoolInformation();

	for (ULONG i = 0; i < information->Count; ++i)
	{
		PSYSTEM_BIGPOOL_ENTRY entry = &information->AllocatedInfo[i];

		if (!entry->NonPaged)
			continue;

		LOG("Found %p\n", entry->VirtualAddress);

		buffer = (UINT8*)ExAllocatePoolWithTag(NonPagedPoolNx, entry->SizeInBytes, TAG);
		ASSERT(buffer != nullptr);

		for (ULONG_PTR j = 0; j < entry->SizeInBytes; ++j)
		{
			PVOID addr = (PVOID)((ULONG_PTR)entry->VirtualAddress + j);
			if (MmIsAddressValid(addr))
			{
				buffer[j] = *(UINT8*)addr;
				size++;
			}
			else
			{
				LOG("Aborted copying @ %p\n", addr);
				break;
			}
		}

		LOG("Copied to %p\n", buffer);

		if (size > 0)
		{
			RtlInitEmptyUnicodeString(
				&dumpFile, emptyBuffer, sizeof(emptyBuffer));
			status = RtlUnicodeStringPrintf(
				&dumpFile, L"\\??\\C:\\tmp\\pool_%lu.bin", i);
			STATUS_ASSERT(status);

			InitializeObjectAttributes(
				&attributes, &dumpFile,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				NULL, NULL);

			status = ZwCreateFile(
				&handle, GENERIC_WRITE,
				&attributes, &statusBlock, NULL,
				FILE_ATTRIBUTE_NORMAL, 0,
				FILE_OVERWRITE_IF,
				FILE_SYNCHRONOUS_IO_NONALERT,
				NULL, 0);
			STATUS_ASSERT(status);

			status = ZwWriteFile(
				handle, NULL, NULL, NULL,
				&statusBlock, buffer, size,
				NULL, NULL);
			STATUS_ASSERT(status);

			status = ZwClose(handle);
			STATUS_ASSERT(status);
		}

		ExFreePoolWithTag(buffer, TAG);

		size = 0;
	}

	ExFreePoolWithTag(information, TAG);
}

extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	// Doesn't necessarily need to run in a seperate thread,
	// but it's recommended for use with kdmapper.
	HANDLE handle = nullptr;
	PsCreateSystemThread(&handle, GENERIC_ALL, nullptr, nullptr, nullptr, DumpPools, nullptr);

	return STATUS_SUCCESS;
}