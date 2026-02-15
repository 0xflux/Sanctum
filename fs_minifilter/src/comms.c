#include "comms.h"
#include "globals.h"

#define FLT_MAX_CONNECTIONS 1
#define MAX_MESSAGE 256

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

typedef struct DriverMessage {
	int len;
	char buf[MAX_MESSAGE];
} DriverMessage;

NTSTATUS SendTelemetry() {

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

	char* my_string = "hello\0";
	if (strlen(my_string) > MAX_MESSAGE) {
		goto disallow_dispatch;
	}

	DriverMessage driver_message = {0};
	driver_message.len = (int)strlen(my_string) + 1;
	RtlCopyMemory(driver_message.buf, my_string, driver_message.len);

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