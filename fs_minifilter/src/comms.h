#pragma once

#include <fltKernel.h>

#define FILTER_PORT_NAME L"\\SanctumFilterPort"

typedef enum InterceptedEventType {
	WriteAccessFileEvent,
	SetInformationEvent,
	SuspiciousExtention,
} InterceptedEventType;

//
// FUNCTIONS
//
NTSTATUS InitComms(PFLT_FILTER filter);
//NTSTATUS FltUnregister(FLT_FILTER_UNLOAD_FLAGS flags);
NTSTATUS FltConnectCallback(
	PFLT_PORT ClientPort,
	PVOID ServerPortCookie,
	PVOID ConnectionContext,
	ULONG SizeOfContext,
	PVOID* ConnectionPortCookie
);
VOID FltDisconnectCallback(PVOID ConnectionCookie);
NTSTATUS SendTelemetry(PUNICODE_STRING, InterceptedEventType, char*);