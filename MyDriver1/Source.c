#include "ntddk.h"
#include <wchar.h>

#define DEVICE_SEND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define DEVICE_REC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

NTSYSAPI NTSTATUS NTAPI ZwWriteFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);

typedef struct SystemServiceTable{
	UINT32* ServiceTable;
	UINT32* CounterTable;
	UINT32* SerivceLimit;
	PUCHAR ArgumentTable;
}SST;

__declspec(dllimport)SST KeServiceDescriptorTable;

PULONG old = NULL;
SST ssdt;
UINT32 old_index;
UINT32 selected;
UINT32 counter = 0;
UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\rootkit");
UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(L"\\??\\rootkitlink");
PDEVICE_OBJECT DeviceObject = NULL;
WCHAR mode;

VOID disableWritePermissionCheck() {
	__asm {
		push eax
		mov eax, cr0
		and eax, 0xFFFEFFFF
		mov cr0, eax
		pop eax
	}
	DbgPrint("Write protection off\r\n");
}

VOID enableWritePermmissionCheck() {
	__asm {
		push eax
		mov eax, cr0
		or eax, 0x00010000
		mov cr0, eax
		pop eax
	}
	DbgPrint("Write protection on\r\n");
}

VOID unhook() {
	if (old_index != -1) {
		if (old != NULL) {
			PLONG serviceTable;
			disableWritePermissionCheck();
			serviceTable = ssdt.ServiceTable;
			serviceTable[old_index] = old;
			old = NULL;
			old_index = -1;
			counter = 0;
			enableWritePermmissionCheck();
		}
	}
}

PULONG hookSSDT(PUCHAR syscall, PULONG hook) {
	UINT32 index;
	PLONG serviceTable;
	PLONG target;

	disableWritePermissionCheck();
	serviceTable = ssdt.ServiceTable;
	old_index = index = *((PULONG)(syscall + 0x1));
	target = serviceTable[index];
	serviceTable[index] = hook;
	enableWritePermmissionCheck();
	return target;
}

PULONG hookSSDTIndex(UINT32 index, PULONG hook) {
	PLONG serviceTable;
	PLONG target;
	if (old_index != -1) {
		unhook();
	}
	disableWritePermissionCheck();
	serviceTable = ssdt.ServiceTable;
	old_index = index;
	target = serviceTable[index];
	serviceTable[index] = hook;
	enableWritePermmissionCheck();
	return target;
}

__declspec(naked) NTSTATUS hook() {
	_asm {
		push ebp
		mov ebp, esp
		push ebx
		push ecx
		push edi
		push esi
		mov ebx, counter
		inc ebx
		mov counter, ebx
		mov esi, ssdt.ArgumentTable
		mov ecx, old_index
		mov ebx, 0
		mov bl, [esi + ecx]
		sub esp, ebx
		mov ecx, 0
		mov edi, esp
		ptl :
		mov bh, [ebp + 8 + ecx]
		mov [edi], bh
		inc edi
		inc cl
		cmp cl, bl
		jne ptl
		call old
		pop esi
		pop edi
		pop ecx
		pop ebx
		pop ebp
		ret
	}
}


VOID Unload(IN PDRIVER_OBJECT DriverObject) {
	IoDeleteSymbolicLink(&SymLinkName);
	IoDeleteDevice(DeviceObject);

	if (old != NULL) {
		unhook();
	}
}

NTSTATUS Dipatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	switch (irpsp->MajorFunction) {
	case IRP_MJ_CREATE:
		DbgPrint("create request successfull\r\n");
		break;
	default:
		status = STATUS_INVALID_PARAMETER;
		break;
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DispatchDevCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
	ULONG inLength = irpsp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outLength = irpsp->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG returnLength = 0;
	WCHAR counterMsg[30] = { 0 };

	switch (irpsp->Parameters.DeviceIoControl.IoControlCode) {
	case DEVICE_SEND:
		mode = ((WCHAR*)buffer)[0];
		selected = _wtoi((((WCHAR*)buffer) + 1));
		returnLength = (wcsnlen(buffer, 511) + 1) * 2;
		break;
	case DEVICE_REC:
		if (mode == 's') {
			old = hookSSDTIndex(selected, hook);
			WCHAR* msg = L"Hooked";
			wcsncpy(buffer, msg, 511);
			returnLength = (wcsnlen(buffer, 511) + 1) * 2;
		}
		else if (mode == 'g') {
			if (old == NULL || old_index != selected) {
				WCHAR* msg = L"No or different func hooked";
				wcsncpy(buffer, msg, 511);
				returnLength = (wcsnlen(buffer, 511) + 1) * 2;
			}
			else {
				_itow_s(counter, counterMsg, 30, 10);
				wcsncpy(buffer, counterMsg, 511);
				returnLength = (wcsnlen(buffer, 511) + 1) * 2;
			}
		}
		else if (mode == 'd') {
			if (old == NULL) {
				WCHAR* msg = L"No func hooked";
				wcsncpy(buffer, msg, 511);
				returnLength = (wcsnlen(buffer, 511) + 1) * 2;
			}
			else {
				unhook();
				WCHAR* msg = L"Hook deleted";
				wcsncpy(buffer, msg, 511);
				returnLength = (wcsnlen(buffer, 511) + 1) * 2;
			}
		}
		break;
	default:
		status = STATUS_INVALID_PARAMETER;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = returnLength;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
	DriverObject->DriverUnload = Unload;
	NTSTATUS status;

	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create a device\r\n");
		return status;
	}

	status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create symbolic link\r\n");
		IoDeleteDevice(DeviceObject);
		return status;
	}

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		DriverObject->MajorFunction[i] = Dipatch;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDevCTL;
	ssdt = KeServiceDescriptorTable;
	return status;
}