#include "ntddk.h"


NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(

	ULONG  SystemInformationClass,
	PVOID  SystemInformation,
	ULONG  SystemInformationLength,
	PULONG ReturnLength

);

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

VOID disableWritePermission() {
	__asm {
		push eax
		mov eax, cr0
		and eax, 0xFFFEFFFF
		mov cr0, eax
		pop eax
	}
}

VOID enableWritePermmission() {
	__asm {
		push eax
		mov eax, cr0
		or eax, 0x00010000
		mov cr0, eax
		pop eax
	}
}

PULONG hookSSDT(PUCHAR syscall, PUCHAR hook) {
	UINT32 index;
	PLONG serviceTable;
	PLONG target;

	disableWritePermission();
	DbgPrint("CR0 write permission off\r\n");
	serviceTable = ssdt.ServiceTable;
	old_index = index = *((PULONG)(syscall + 0x1));
	target = serviceTable[index];
	serviceTable[index] = hook;
	enableWritePermmission();
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
	if (old != NULL) {
		hookSSDT((PULONG)ZwQuerySystemInformation, (PULONG)old);
	}
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
	DriverObject->DriverUnload = Unload;
	ssdt = KeServiceDescriptorTable;
	old = hookSSDT((PULONG)ZwQuerySystemInformation, (PULONG)hook);
	return STATUS_SUCCESS;
}