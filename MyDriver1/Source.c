#include "ntddk.h"

VOID Unload(IN PDRIVER_OBJECT DriverObject) {
	DbgPrint("Bye world\n");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
	DriverObject->DriverUnload = Unload;
	DbgPrint("Hello world\n");
	DbgBreakPoint();
	return STATUS_SUCCESS;
}