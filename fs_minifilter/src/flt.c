#include "flt.h"
#include "string_utils.h"

CONST FLT_OPERATION_REGISTRATION g_callbacks[] =
{
    {
        IRP_MJ_CREATE,
        0,
        PreOperationCreate,
        PostOperationCreate
    },

    {
        IRP_MJ_SET_INFORMATION,
        0,
        PreOperationSetInformation,
        PostOperationSetInformation
    },

    { IRP_MJ_OPERATION_END }
};

PFLT_FILTER g_mini_flt_handle = NULL;

const FLT_REGISTRATION g_filter_registration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    g_callbacks,
    InstanceFilterUnloadCallback,
    InstanceSetupCallback,
    InstanceQueryTeardownCallback,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

const LPCWSTR KNOWN_RANSOMWARE_FILE_EXTS[] = {
    // Associated with Lockbit
    // https://www.trendmicro.com/en_gb/research/22/g/lockbit-ransomware-group-augments-its-latest-variant--lockbit-3-.html
    L".HLJkNskOq",
};

BOOLEAN IsFileExtKnownRansomware(PUNICODE_STRING input) {
    if (input == NULL) return FALSE;
    if (input->Length == 0 || input->Buffer == NULL) return FALSE;

    size_t input_num_chars = input->Length / sizeof(WCHAR);
    for (int i = 0; i < RTL_NUMBER_OF(KNOWN_RANSOMWARE_FILE_EXTS); ++i) {
        //
        // Safety checks
        //
        if (KNOWN_RANSOMWARE_FILE_EXTS[i] == NULL) continue;
        size_t num_chars_ransom_ext = wcslen(KNOWN_RANSOMWARE_FILE_EXTS[i]);
        if (input_num_chars < num_chars_ransom_ext) continue;

        //
        // Now loop through the chars at the end of the input string, and try match
        // for the known ransomware extensions 
        //
        BOOLEAN total_match = TRUE;
        size_t start = input_num_chars - num_chars_ransom_ext;


        for (int j = 0; j < num_chars_ransom_ext; ++j) {
            size_t idx = start + (size_t)j;

            if (input->Buffer[idx] != KNOWN_RANSOMWARE_FILE_EXTS[i][j]) {
                total_match = FALSE;
                break;
            }

        }

        if (!total_match) continue;

        return total_match;
    }

    return FALSE;
}

NTSTATUS LookupImageFromThread(PETHREAD p_ethread, PUNICODE_STRING* image) {

    if (image == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    *image = NULL;

    PEPROCESS p_eprocess = IoThreadToProcess(p_ethread);
    if (p_eprocess == NULL) {
        DbgPrint("[-] Failed to get EPROCESS.\n");
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = SeLocateProcessImageName(p_eprocess, image);
    if ((!NT_SUCCESS(status)) || *image == NULL) {
        DbgPrint("[-] Failed to locate process image.\n");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostOperationCreate(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS flt_objects,
    PVOID completion_ctx,
    FLT_POST_OPERATION_FLAGS flags
)
{
    UNREFERENCED_PARAMETER(flt_objects);
    UNREFERENCED_PARAMETER(completion_ctx);
    UNREFERENCED_PARAMETER(flags);

    PUNICODE_STRING image = NULL;

    // For now we only care about things in the /scil/ dir for testing (noise reduction)
    if (!UnicodeContainsLiteral(
        &data->Iopb->TargetFileObject->FileName,
        L"scil",
        TRUE
    )) {
        goto post_complete;
    }

    // Get the full image path from the thread making the fs access
    if (!NT_SUCCESS(LookupImageFromThread(data->Thread, &image))) goto post_complete;
    int process_pid = HandleToLong(PsGetProcessId(IoThreadToProcess(data->Thread)));

    if (data->Iopb->TargetFileObject->WriteAccess) {
        // TODO we will send telemetry at this point to the subscriber - whether
        // that is the Sanctum driver or is in usermode.
        DbgPrint(
            "[i] Filter WRITE access on file:\n\tFile name=%wZ\n\tBy pid=%d\n\tBy process=%wZ\n\n",
            &data->Iopb->TargetFileObject->FileName,
            process_pid,
            image
        );
    }
    
post_complete:
    if (image != NULL) {
        ExFreePool(image);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationCreate(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_obj, PVOID* completion_ctx)
{
    UNREFERENCED_PARAMETER(completion_ctx);
    UNREFERENCED_PARAMETER(flt_obj);
    UNREFERENCED_PARAMETER(data);

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationSetInformation(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS flt_objects,
    PVOID* completion_ctx
) {
    UNREFERENCED_PARAMETER(completion_ctx);
    UNREFERENCED_PARAMETER(flt_objects);
    UNREFERENCED_PARAMETER(data);
    
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI PostOperationSetInformation(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS flt_objects,
    PVOID completion_ctx,
    FLT_POST_OPERATION_FLAGS flags
) {
    UNREFERENCED_PARAMETER(flt_objects);
    UNREFERENCED_PARAMETER(completion_ctx);
    UNREFERENCED_PARAMETER(flags);

    PUNICODE_STRING thread_image_path = NULL;
    PFLT_FILE_NAME_INFORMATION name_info = NULL;

    //
    // Only filter for now on rename events in this handler
    //
    FILE_INFORMATION_CLASS info_class = data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    switch (info_class) {
    case FileRenameInformation:
    case FileRenameInformationEx:
        break;
    default:
        goto post_complete;
    }

    if (!UnicodeContainsLiteral(
        &data->Iopb->TargetFileObject->FileName,
        L"scil",
        TRUE
    )) {
        goto post_complete;
    }

    NTSTATUS status = FltGetFileNameInformation(
        data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &name_info
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to get file name information in filter driver.\n");
        goto post_complete;
    }

    // Now parse the information so we get the full name, not just the last 3 file ext chars
    FltParseFileNameInformation(name_info);

    //
    // https://www.trendmicro.com/en_gb/research/22/g/lockbit-ransomware-group-augments-its-latest-variant--lockbit-3-.html
    // Simple approach to detecting ransomware - looking for a known 
    // extension for ransomware (lockbit) = HLJkNskOq
    // 
    if (IsFileExtKnownRansomware(&name_info->Name)) {
        // As we care about this - lets get the process name and pid making the change.
        LookupImageFromThread(data->Thread, &thread_image_path);
        int process_pid = HandleToLong(PsGetProcessId(IoThreadToProcess(data->Thread)));

        DbgPrint(
            "[!!!!!] Possible ransomware detected targeting file: %wZ\n\t\tPid: %d, Process: %wZ\n\n",
            &name_info->Name,
            process_pid,
            thread_image_path
        );

    }

post_complete:
    if (name_info != NULL) {
        FltReleaseFileNameInformation(name_info);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

BOOLEAN ContainsScil(PUNICODE_STRING name)
{
    UNICODE_STRING expr;
    RtlInitUnicodeString(&expr, L"*s*");
    return FsRtlIsNameInExpression(&expr, name, TRUE, NULL);
}

NTSTATUS FLTAPI InstanceFilterUnloadCallback(FLT_FILTER_UNLOAD_FLAGS flags)
{
    UNREFERENCED_PARAMETER(flags);

    if (NULL != g_mini_flt_handle)
    {
        FltUnregisterFilter(g_mini_flt_handle);
    }

    return STATUS_SUCCESS;
}

NTSTATUS FLTAPI InstanceSetupCallback(
    PCFLT_RELATED_OBJECTS  flt_obj,
    FLT_INSTANCE_SETUP_FLAGS  flags,
    DEVICE_TYPE  volume_device_type,
    FLT_FILESYSTEM_TYPE  volume_fs_type)
{
    UNREFERENCED_PARAMETER(flt_obj);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(volume_device_type);
    UNREFERENCED_PARAMETER(volume_fs_type);

    return STATUS_SUCCESS;
}

NTSTATUS FLTAPI InstanceQueryTeardownCallback(
    PCFLT_RELATED_OBJECTS flt_obj,
    FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags
) {
    UNREFERENCED_PARAMETER(flt_obj);
    UNREFERENCED_PARAMETER(flags);

    return STATUS_SUCCESS;
}