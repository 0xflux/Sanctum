//! This module handles callback implementations and and other function related to processes.

use alloc::{string::String, vec::Vec};
use core::{
    ffi::c_void,
    iter::once,
    ptr::{null_mut, slice_from_raw_parts},
    sync::atomic::Ordering,
    time::Duration,
};
use shared_no_std::driver_ipc::{HandleObtained, ProcessStarted};
use wdk::println;
use wdk_sys::{
    _IMAGE_INFO,
    _MODE::KernelMode,
    _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS,
    _UNICODE_STRING, APC_LEVEL, HANDLE, NTSTATUS, OB_CALLBACK_REGISTRATION,
    OB_FLT_REGISTRATION_VERSION, OB_OPERATION_HANDLE_CREATE, OB_OPERATION_HANDLE_DUPLICATE,
    OB_OPERATION_REGISTRATION, OB_PRE_OPERATION_INFORMATION, OB_PREOP_CALLBACK_STATUS, PEPROCESS,
    PROCESS_ALL_ACCESS, PS_CREATE_NOTIFY_INFO, PsProcessType, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
    TRUE, UNICODE_STRING,
    ntddk::{
        KeDelayExecutionThread, KeGetCurrentIrql, ObOpenObjectByPointer, ObRegisterCallbacks,
        PsGetCurrentProcessId, PsGetProcessId, PsRemoveLoadImageNotifyRoutine,
        PsSetLoadImageNotifyRoutine, RtlInitUnicodeString,
    },
};

use crate::{
    DRIVER_MESSAGES, REGISTRATION_HANDLE,
    core::{
        injection::inject_dll,
        process_monitor::{LoadedModule, ProcessMonitor},
    },
    device_comms::ImageLoadQueueForInjector,
    utils::{duration_to_large_int, get_process_name, unicode_to_string},
};

/// Callback function for a new process being created on the system.
pub unsafe extern "C" fn process_create_callback(
    process: PEPROCESS,
    pid: HANDLE,
    create_info: *mut PS_CREATE_NOTIFY_INFO,
) {
    //
    // If `created` is not a null pointer, this means a new process was started, and you can query the
    // args for information about the newly spawned process.
    //
    // In the event that `create` is null, it means a process was terminated.
    //

    if !create_info.is_null() {
        //
        // process started
        //

        let image_name = unicode_to_string(unsafe { (*create_info).ImageFileName });
        let command_line = unicode_to_string(unsafe { (*create_info).CommandLine });
        let parent_pid = unsafe { (*create_info).ParentProcessId as u32 };
        let pid = pid as u32;

        if image_name.is_err() || command_line.is_err() {
            return;
        }

        // todo was trying to do this before!
        // let mut peprocess: PEPROCESS = null_mut();
        // let mut proc_name: PUNICODE_STRING = null_mut();
        // unsafe { PsLookupProcessByProcessId(pid as *mut _, &mut peprocess) };
        // unsafe { SeLocateProcessImageName(peprocess, &mut proc_name) };

        let mut process_handle: HANDLE = null_mut();
        let _ = unsafe {
            ObOpenObjectByPointer(
                process as *mut _,
                0,
                null_mut(),
                PROCESS_ALL_ACCESS,
                *PsProcessType,
                KernelMode as _,
                &mut process_handle,
            )
        };

        // Set both bits: EnableReadVmLogging (bit 0) and EnableWriteVmLogging (bit 1)
        let mut logging_info = ProcessLoggingInformation { flags: 0x03 };
        let _ = unsafe {
            ZwSetInformationProcess(
                process_handle,
                87,
                &mut logging_info as *mut _ as *mut _,
                size_of::<ProcessLoggingInformation>() as _,
            )
        };

        let process_started = ProcessStarted {
            image_name: image_name.unwrap().replace("\\??\\", ""),
            command_line: command_line.unwrap().replace("\\??\\", ""),
            parent_pid,
            pid,
        };

        // Add the new process to the monitor
        if let Err(e) = ProcessMonitor::onboard_new_process(&process_started) {
            println!("[sanctum] [-] Error onboarding new process to PM. {:?}", e)
        };
    } else {
        //
        // process terminated
        //

        let pid = pid as u32;
        ProcessMonitor::remove_process(pid);
    }
}

pub struct ProcessHandleCallback {}

impl ProcessHandleCallback {
    pub fn register_callback() -> Result<(), NTSTATUS> {
        // IRQL <= APC_LEVEL required for ObRegisterCallbacks
        let irql = unsafe { KeGetCurrentIrql() };
        if irql as u32 > APC_LEVEL {
            return Err(1);
        }

        // todo will need a microsoft issues 'altitude'
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request
        let mut callback_registration = OB_CALLBACK_REGISTRATION::default();
        let mut altitude = UNICODE_STRING::default();
        let altitude_str = "327146";
        let altitude_str = altitude_str
            .encode_utf16()
            .chain(once(0))
            .collect::<Vec<_>>();
        unsafe { RtlInitUnicodeString(&mut altitude, altitude_str.as_ptr()) };

        // operation registration
        let mut operation_registration = OB_OPERATION_REGISTRATION::default();
        operation_registration.ObjectType = unsafe { PsProcessType };
        operation_registration.Operations =
            OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        operation_registration.PreOperation = Some(pre_process_handle_callback);

        // // assign to the callback registration
        callback_registration.Altitude = altitude;
        callback_registration.Version = OB_FLT_REGISTRATION_VERSION as u16;
        callback_registration.OperationRegistrationCount = 1;
        callback_registration.RegistrationContext = null_mut();
        callback_registration.OperationRegistration = &mut operation_registration;

        let mut reg_handle: *mut c_void = null_mut();

        let status = unsafe { ObRegisterCallbacks(&mut callback_registration, &mut reg_handle) };
        if status != STATUS_SUCCESS {
            println!(
                "[sanctum] [-] Unable to register callback for handle interception. Failed with code: {status}."
            );
            return Err(STATUS_UNSUCCESSFUL);
        }
        REGISTRATION_HANDLE.store(reg_handle as *mut _, Ordering::Relaxed);

        Ok(())
    }
}

/// Callback function to handle process handle request,s
/// TODO this needs updating to pause on handle, communicate with engine, and make a decision as per drawing
pub unsafe extern "C" fn pre_process_handle_callback(
    ctx: *mut c_void,
    oi: *mut OB_PRE_OPERATION_INFORMATION,
) -> OB_PREOP_CALLBACK_STATUS {
    return OB_PREOP_SUCCESS;
    // todo pick up from here after thread testing

    // println!("Inside callback for handle. oi: {:?}", oi);

    // Check the inbound pointer is valid before attempting to dereference it. We will return 1 as an error code
    if oi.is_null() {
        return 1;
    }

    let p_target_process = (*oi).Object as PEPROCESS;
    let target_pid = PsGetProcessId(p_target_process);
    let source_pid = PsGetCurrentProcessId();

    let desired_access = (*(*oi).Parameters).CreateHandleInformation.DesiredAccess;
    let og_desired_access = (*(*oi).Parameters)
        .CreateHandleInformation
        .OriginalDesiredAccess;

    // if target_pid as u64 == 5228 && source_pid as u64 != 9552 {
    //     println!("[sanctum] [i] Sending PROCESS STARTED INFO {:?}", HandleObtained {
    //         source_pid: source_pid as u64,
    //         dest_pid: target_pid as u64,
    //         rights_desired: og_desired_access,
    //         rights_given: desired_access,
    //     });

    // }

    if !DRIVER_MESSAGES.load(Ordering::SeqCst).is_null() {
        let obj = unsafe { &mut *DRIVER_MESSAGES.load(Ordering::SeqCst) };
        obj.add_process_handle_to_queue(HandleObtained {
            source_pid: source_pid as u64,
            dest_pid: target_pid as u64,
            rights_desired: og_desired_access,
            rights_given: desired_access,
        });
    } else {
        println!("[sanctum] [-] Driver messages is null");
    };

    OB_PREOP_SUCCESS
}

#[repr(C)]
pub union ProcessLoggingInformation {
    pub flags: u32,
}

unsafe extern "system" {
    fn ZwSetInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: u32,
    ) -> NTSTATUS;
}

pub fn register_image_load_callback() -> NTSTATUS {
    // Register the ImageLoadQueueForInjector which will instantiate the Grt containing the mutex for async
    // access.
    ImageLoadQueueForInjector::init();
    unsafe { PsSetLoadImageNotifyRoutine(Some(image_load_callback)) }
}

pub fn unregister_image_load_callback() {
    let _ = unsafe { PsRemoveLoadImageNotifyRoutine(Some(image_load_callback)) };
}

/// The callback function for image load events (exe, dll)
///
/// # Remarks
/// This routine will be called by the operating system to notify the driver when a driver image or a user image
/// (for example, a DLL or EXE) is mapped into virtual memory. The operating system invokes this routine after an
/// image has been mapped to memory, but before its entrypoint is called.
///
/// **IMPORTANT NOTE:** The operating system does not call load-image notify routines when sections created with the `SEC_IMAGE_NO_EXECUTE`
/// attribute are mapped to virtual memory. This shouldn't affect early bird techniques - but WILL need attention in the future
/// as this attribute could be used in process hollowing etc to avoid detection with our filter callback here.
///
/// todo One way to defeat this once I get round to it would be hooking the NTAPI with our DLL and refusing any attempt to use that
/// parameter; or we could dynamically change it at runtime. My Ghost Hunting technique should allow us to detect a threat actor
/// trying to use direct syscalls etc to bypass the hook.
///
/// Some links on this:
///
/// - https://www.secforce.com/blog/dll-hollowing-a-deep-dive-into-a-stealthier-memory-allocation-variant/
/// - https://www.cyberark.com/resources/threat-research-blog/masking-malicious-memory-artifacts-part-ii-insights-from-moneta
extern "C" fn image_load_callback(
    image_name: *mut _UNICODE_STRING,
    pid: HANDLE,
    image_info: *mut _IMAGE_INFO,
) {
    // todo can i use this callback in an attempt to detect DLL SOH?? :)

    // I guess these should never be null
    if image_info.is_null() || image_name.is_null() {
        return;
    }

    // Check that we aren't dealing with a driver load, we dont care about those for now
    if pid.is_null() {
        return;
    }

    // Check the inbound pointers
    if image_info.is_null() || image_name.is_null() {
        println!(
            "[sanctum] [-] Pointers were null in image_load_callback, and this is unexpected."
        );
        return;
    }

    // SAFETY: Pointers validated above
    let image_info = unsafe { *image_info };
    let Some(image_name_string) = get_image_name(image_name) else {
        println!("[sanctum] [-] No image name");
        return;
    };
    let process_name = get_process_name();
    let pid = pid as u32;

    //
    // PROCESS MONITORING SECTION
    // Gate-keep what processes we are monitoring
    //
    if !(process_name.contains("otepad.e") || process_name.contains("alware.e")) {
        return;
    }

    if image_name_string.contains("kernel32.dll") {
        let _ = inject_dll();
    }

    // In the event it is a DLL load, we want to grab & track its mappings
    if image_name_string.contains(".dll") {
        // todo hash check on the sanctum DLL to make sure an adversary isn't calling their malicious DLL `sanctum.dll`
        // which would interfere with what we are doing in this segment.

        // todo is it re-loading NTDLL when NTDLL already exists in the process? Bad, we want to stop this and report
        // on it.

        let lm = LoadedModule::new(image_info.ImageBase as _, image_info.ImageSize as _);
        ProcessMonitor::add_loaded_module(lm, &image_name_string, pid);

        return;
    }

    //
    // We force the sanctum DLL to load before kernel32 is loaded, therefore we need to block at kernelbase.
    // We cannot block at kernel32 as we need the thread to continue with its execution in order to have the Sanctum
    // loaded in.
    //
    // The thread loading kernelbase will loop until the sanctum DLL has notified the driver it has loaded and the
    // relocations have taken place.
    //
    block_until_sanctum_loaded(&image_name_string, pid);
}

fn block_until_sanctum_loaded(image_name_string: &String, pid: u32) {
    if image_name_string.contains("kernelbase.dll") {
        let mut thread_sleep_time = duration_to_large_int(Duration::from_secs(1));
        let mut count = 0;

        loop {
            let _ = unsafe {
                KeDelayExecutionThread(KernelMode as _, TRUE as _, &mut thread_sleep_time)
            };

            if ProcessMonitor::is_sanc_dll_initialised(pid) {
                break;
            }

            count += 1;
            if count > 4 {
                // todo some telemetry, this is either a bug or threat, we need this in otherwise the driver will go into
                // UB with current implementation :)
                println!(
                    "Process started: {}, but did not load Sanctum dll, or it did not initialise. PID: {}",
                    get_process_name(),
                    unsafe { PsGetCurrentProcessId() as u32 }
                );

                break;
            }
        }
    }
}

/// Gets the image name of the process for which the image is being loaded, provided by the
/// callback routine (we convert to a rust String).
fn get_image_name(image_name: *mut UNICODE_STRING) -> Option<String> {
    if image_name.is_null() {
        return None;
    }

    let image_name = unsafe { *image_name };

    let name_slice = slice_from_raw_parts(image_name.Buffer, (image_name.Length / 2) as usize);
    Some(String::from_utf16_lossy(unsafe { &*name_slice }).to_lowercase())
}
