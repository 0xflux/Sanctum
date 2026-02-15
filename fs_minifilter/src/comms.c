#include "comms.h"
#include "globals.h"

#define FLT_MAX_CONNECTIONS 1
#define MAX_FIELD_BYTES 1024

typedef struct DriverMessage {
	int path_len;
	char path[MAX_FIELD_BYTES];
	int message_len;
	char message[MAX_FIELD_BYTES];
} DriverMessage;

NTSTATUS InitComms(PFLT_FILTER filter) {

	g_filter = filter;

	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING flt_port_name = { 0 };

	RtlInitUnicodeString(&flt_port_name, FILTER_PORT_NAME);
	
	PSECURITY_DESCRIPTOR p_security_descriptor = NULL;
	status = FltBuildDefaultSecurityDescriptor(
		&p_security_descriptor,
		FLT_PORT_ALL_ACCESS
	);

	if (!NT_SUCCESS(status)) return status;

	OBJECT_ATTRIBUTES object_attrs = { 0 };
	InitializeObjectAttributes(
		&object_attrs,
		&flt_port_name,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		p_security_descriptor
	);

	status = FltCreateCommunicationPort(
		g_filter,
		&g_server_port,
		&object_attrs,
		NULL,
		FltConnectCallback,
		FltDisconnectCallback,
		NULL,
		FLT_MAX_CONNECTIONS
	);

	FltFreeSecurityDescriptor(p_security_descriptor);

	if (!NT_SUCCESS(status)) return status;

	return STATUS_SUCCESS;
}

NTSTATUS FltConnectCallback(
	PFLT_PORT ClientPort,
	PVOID ServerPortCookie,
	PVOID ConnectionContext,
	ULONG SizeOfContext,
	PVOID* ConnectionPortCookie
) {
	UNREFERENCED_PARAMETER(ConnectionPortCookie);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(ServerPortCookie);
	if (ClientPort == NULL)
		return STATUS_INVALID_PARAMETER;

	g_client_port = ClientPort;
	return STATUS_SUCCESS;
}

VOID FltDisconnectCallback(PVOID ConnectionCookie)
{
	UNREFERENCED_PARAMETER(ConnectionCookie);
	if (g_client_port) {
		FltCloseClientPort(g_filter, &g_client_port);
		DbgPrint("[i] Client port closed from termination routine.\n");
		g_client_port = NULL;
	}
}

NTSTATUS SendTelemetry(
	PUNICODE_STRING path,
	char* message // MUST be null terminated on input, or a NULL POINTER
) {

	/**
	* TODO: 
	* 
	* This routine should start to take in params, and offload what it wants to send 
	* to a dispatch thread.
	* 
	* That thread should be guaranteed at IRQL(0) and store events in a ring buffer such that
	* we can send the request to usermode, make sure it is ready to accept, and then send the 
	* buffer of multiple events up to the usermode application. Or, is it fast enough now that
	* it is acceptable?
	* 
	*/

	//
	// Guard against sending data during unload
	//
	InterlockedIncrement(&g_inflight_sends);

	if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
		DbgPrint("[-] IRQL too high.\n");
		goto disallow_dispatch;
	}

	if (InterlockedOr(&g_unloading, 0) != 0) {
		goto disallow_dispatch;
	}

	if (!g_client_port) {
		goto disallow_dispatch;
	}

	size_t message_len = (message) ? strlen(message) : 0;

	if (message_len > MAX_FIELD_BYTES || path->Length > MAX_FIELD_BYTES) {
		goto disallow_dispatch;
	}

	// Copy the path UNICODE_STRING into the buffer
	DriverMessage driver_message = {0};
	driver_message.path_len = path->Length; // in bytes
	RtlCopyMemory(driver_message.path, path->Buffer, driver_message.path_len);

	// Same for any message, if present. Null pointer checks done above
	if (message_len >= 1) {
		driver_message.message_len = (int)message_len + 1; // in bytes, +1 for null terminator which we will keep
		RtlCopyMemory(driver_message.message, message, driver_message.message_len);
	}
	else {
		driver_message.message_len = 0;
	}

	ULONG reply_len = 0;
	LARGE_INTEGER timeout = { 0 };
	timeout.QuadPart = -10000000LL; // 1 second timeout

	NTSTATUS status = FltSendMessage(
		g_filter,
		&g_client_port,
		&driver_message,
		sizeof(driver_message),
		NULL,
		&reply_len,
		&timeout
	);

	InterlockedDecrement(&g_inflight_sends);

	return status;

disallow_dispatch:
	InterlockedDecrement(&g_inflight_sends);
	return STATUS_PORT_DISCONNECTED;
}