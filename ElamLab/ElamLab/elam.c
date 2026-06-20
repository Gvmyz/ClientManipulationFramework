#include <ntddk.h>

DRIVER_UNLOAD     ElamUnload;
DRIVER_INITIALIZE DriverEntry;

void ElamUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = ElamUnload;
    return STATUS_SUCCESS;
}