#include "flt.h"

#define FLT_TAG 'xulF'

NTSTATUS DriverEntry(
	PDRIVER_OBJECT driver_object, 
	PUNICODE_STRING registry_path
) {

	UNREFERENCED_PARAMETER(registry_path);

	//
	// Register the minifilter with the OS
	//
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[i] Starting file system minifilter..!\n"));
	NTSTATUS status = FltRegisterFilter(
		driver_object,
		&g_filter_registration,
		&g_mini_flt_handle
	);

	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[-] Failed to register the minifilter. %#x!\n", status));
		return status;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Minifilter was registered!\n"));

	//
	// Start the minifilter
	//
	status = FltStartFiltering(g_mini_flt_handle);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[-] Failed to start filtering. %#x!\n", status));
		FltUnregisterFilter(g_mini_flt_handle);
		return status;
	}

	return status;
}