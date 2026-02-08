#pragma once
#include <fltKernel.h>

//
// PROTOTYPES
//

FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationCreate(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
);

NTSTATUS FLTAPI InstanceFilterUnloadCallback(FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS FLTAPI InstanceQueryTeardownCallback(
	PCFLT_RELATED_OBJECTS FltObjects,
	FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

NTSTATUS FLTAPI InstanceSetupCallback(
	PCFLT_RELATED_OBJECTS  FltObjects,
	FLT_INSTANCE_SETUP_FLAGS  Flags,
	DEVICE_TYPE  VolumeDeviceType,
	FLT_FILESYSTEM_TYPE  VolumeFilesystemType
);

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostOperationCreate(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
);

BOOLEAN ContainsScil(PUNICODE_STRING Name);

FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationSetInformation(
	PFLT_CALLBACK_DATA data,
	PCFLT_RELATED_OBJECTS flt_objects,
	PVOID* completion_ctx
);

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostOperationSetInformation(
	PFLT_CALLBACK_DATA data,
	PCFLT_RELATED_OBJECTS flt_objects,
	PVOID completion_ctx,
	FLT_POST_OPERATION_FLAGS flags
);

//
// GLOABLS
// 

extern PFLT_FILTER g_minifilterHandle;
extern CONST FLT_OPERATION_REGISTRATION g_callbacks[];
extern const FLT_REGISTRATION g_filterRegistration;