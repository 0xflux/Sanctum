// Sanctum Windows Kernel Mode Driver written in Rust
// Date: 12/10/2024
// Author: flux
//      GH: https://github.com/0xflux
//      Blog: https://fluxsec.red/

#![feature(map_try_insert)]
#![feature(extract_if)]
#![no_std]
extern crate alloc;

#[cfg(not(test))]
extern crate wdk_panic;

use ::core::{
    ffi::c_void,
    iter::once,
    ptr::null_mut,
    sync::atomic::{AtomicPtr, Ordering},
};
use alloc::{boxed::Box, format, vec::Vec};
// use alt_sys_new::register_hooks;
use alt_syscalls::AltSyscalls;
use core::{
    etw_mon::monitor_kernel_etw,
    process_callbacks::{
        ProcessHandleCallback, process_create_callback, register_image_load_callback,
        unregister_image_load_callback,
    },
    process_monitor::ProcessMonitor,
    registry::{enable_registry_monitoring, unregister_registry_monitor},
    syscall_processing::SyscallPostProcessor,
    threads::{set_thread_creation_callback, thread_callback, thread_reg_alt_callbacks},
};
use device_comms::{
    DriverMessagesWithMutex, ioctl_check_driver_compatibility, ioctl_dll_hook_syscall,
    ioctl_get_image_load_len, ioctl_handler_get_image_loads, ioctl_handler_get_kernel_msg_len,
    ioctl_handler_ping, ioctl_handler_ping_return_struct,
    ioctl_handler_send_kernel_msgs_to_userland,
};
use ffi::IoGetCurrentIrpStackLocation;
use shared_no_std::{
    constants::{DOS_DEVICE_NAME, NT_DEVICE_NAME, VERSION_DRIVER},
    ioctl::{
        SANC_IOCTL_CHECK_COMPATIBILITY, SANC_IOCTL_DLL_INJECT_FAILED, SANC_IOCTL_DLL_SYSCALL,
        SANC_IOCTL_DRIVER_GET_IMAGE_LOADS, SANC_IOCTL_DRIVER_GET_IMAGE_LOADS_LEN,
        SANC_IOCTL_DRIVER_GET_MESSAGE_LEN, SANC_IOCTL_DRIVER_GET_MESSAGES, SANC_IOCTL_PING,
        SANC_IOCTL_PING_WITH_STRUCT, SANC_IOCTL_PROC_R_GH, SANC_IOCTL_SEND_BASE_ADDRS,
    },
};
use utils::{Log, LogLevel};
use wdk::{nt_success, println};
use wdk_mutex::{fast_mutex::FastMutex, grt::Grt, kmutex::KMutex};
use wdk_sys::{
    _IO_STACK_LOCATION,
    _KWAIT_REASON::Executive,
    _MODE::KernelMode,
    DEVICE_OBJECT, DO_BUFFERED_IO, DRIVER_OBJECT, FALSE, FILE_DEVICE_SECURE_OPEN,
    FILE_DEVICE_UNKNOWN, IO_NO_INCREMENT, IRP_MJ_CLOSE, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL,
    NTSTATUS, PCUNICODE_STRING, PDEVICE_OBJECT, PIRP, PUNICODE_STRING, STATUS_SUCCESS,
    STATUS_UNSUCCESSFUL, TRUE, UNICODE_STRING,
    ntddk::{
        IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink,
        IofCompleteRequest, KeWaitForSingleObject, ObUnRegisterCallbacks, ObfDereferenceObject,
        PsRemoveCreateThreadNotifyRoutine, PsSetCreateProcessNotifyRoutineEx, RtlInitUnicodeString,
    },
};

mod alt_syscalls;
mod core;
mod device_comms;
mod ffi;
mod response;
mod utils;

use wdk_alloc::WdkAllocator;

use crate::{
    core::{
        process_monitor::{MONITORED_FN_PTRS, set_monitored_dll_fn_ptrs},
        veh_monitor::search_for_amsi_veh_squared,
    },
    device_comms::{ioctl_failed_to_inject_dll, ioctl_process_finished_sanc_dll_load},
};
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

//
// STATICS
// Not ideal; but as DriverEntry exists whilst the driver is still loaded in memory, lifetimes etc
// wont ensure certain parts of memory isn't deallocated.
//

/// An atomic pointer to the DriverMessagesWithSpinLock struct so that it can be used anywhere in the
/// kernel.
static DRIVER_MESSAGES: AtomicPtr<DriverMessagesWithMutex> = AtomicPtr::new(null_mut());
static DRIVER_MESSAGES_CACHE: AtomicPtr<DriverMessagesWithMutex> = AtomicPtr::new(null_mut());
static DRIVER_CONTEXT_PTR: AtomicPtr<DeviceContext> = AtomicPtr::new(null_mut());
static REGISTRATION_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static AP_DEVICE_OBJECT: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(null_mut());

struct DeviceContext {
    log_file_mutex: KMutex<u32>,
}

/// DriverEntry is required to start the driver, and acts as the main entrypoint
/// for our driver.
#[unsafe(export_name = "DriverEntry")] // WDF expects a symbol with the name DriverEntry
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    println!(
        "[sanctum] [i] Starting Sanctum driver... Version: {}",
        VERSION_DRIVER
    );

    if let Err(e) = Grt::init() {
        println!("Error creating Grt!: {:?}", e);
        return STATUS_UNSUCCESSFUL;
    }

    let status = unsafe { configure_driver(driver, registry_path as *mut _) };

    if let Err(e) = initialise_sanctum(driver) {
        return e;
    };

    status
}

/// Performs the initialisation routines for the Sanctum driver, initialising things specific to the
/// actual tasking of the driver; as opposed to the driver configuration, which is done in
/// [`configure_driver`].
fn initialise_sanctum(driver: &mut DRIVER_OBJECT) -> Result<(), i32> {
    AltSyscalls::initialise_for_system(driver);

    // Process image loads
    if let Err(e) = ProcessMonitor::new() {
        println!(
            "[sanctum] [i] Failed to initialise the ProcessMonitor. {:?}. Exiting",
            e
        );
        return Err(STATUS_UNSUCCESSFUL);
    }

    ProcessMonitor::start_process_monitor_worker();

    if let Err(e) = SyscallPostProcessor::spawn() {
        println!("[sanctum] [-] Error starting SyscallPostProcessor. {:?}", e);
        return Err(STATUS_UNSUCCESSFUL);
    }

    let status = register_image_load_callback();
    if !nt_success(status) {
        println!("[sanctum] [-] Could not start PsSetLoadImageNotifyRoutine. Status: {status}");
        driver_exit(driver); // cleanup any resources before returning
        return Err(status);
    }

    // Registry callbacks
    if let Err(code) = enable_registry_monitoring(driver) {
        driver_exit(driver); // cleanup any resources before returning
        return Err(code);
    }

    // Thread interception
    set_thread_creation_callback();

    // Intercepting process creation
    let res =
        unsafe { PsSetCreateProcessNotifyRoutineEx(Some(process_create_callback), FALSE as u8) };
    if res != STATUS_SUCCESS {
        println!(
            "[sanctum] [-] Unable to create device via IoCreateDevice. Failed with code: {res}."
        );
        driver_exit(driver); // cleanup any resources before returning
        return Err(res);
    }

    // Requests for a handle
    // todo right now the result is just a ret
    if let Err(e) = ProcessHandleCallback::register_callback() {
        driver_exit(driver); // cleanup any resources before returning
        return Err(e);
    }

    Ok(())
}

/// This deals with setting up the driver and any callbacks / configurations required
/// for its operation and lifetime.
pub unsafe extern "C" fn configure_driver(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PUNICODE_STRING,
) -> NTSTATUS {
    println!("[sanctum] [i] running sanctum_entry...");
    let log = Log::new();
    log.log(LogLevel::Info, "Sanctum starting...");

    //
    // Initialise the global DRIVER_MESSAGES variable
    //
    let messages = Box::new(DriverMessagesWithMutex::new());
    let messages_cache = Box::new(DriverMessagesWithMutex::new());
    // take ownership of the pointer to the messages struct; the pointer shouldn't change as the
    // struct contains a pointer to the vec, that is allowed to change.
    DRIVER_MESSAGES.store(Box::into_raw(messages), Ordering::SeqCst);
    DRIVER_MESSAGES_CACHE.store(Box::into_raw(messages_cache), Ordering::SeqCst);

    log.log_to_userland(format!(
        "Starting Sanctum driver... Version: {}",
        VERSION_DRIVER
    ));

    search_for_amsi_veh_squared();

    //
    // Configure the strings required for symbolic links and naming
    //
    let mut dos_name = UNICODE_STRING::default();
    let mut nt_name = UNICODE_STRING::default();

    let dos_name_u16: Vec<u16> = DOS_DEVICE_NAME.encode_utf16().chain(once(0)).collect();
    let device_name_u16: Vec<u16> = NT_DEVICE_NAME.encode_utf16().chain(once(0)).collect();

    unsafe { RtlInitUnicodeString(&mut dos_name, dos_name_u16.as_ptr()) };
    unsafe { RtlInitUnicodeString(&mut nt_name, device_name_u16.as_ptr()) };

    //
    // Create the device
    //
    let mut device_object: PDEVICE_OBJECT = null_mut();

    let res = unsafe {
        IoCreateDevice(
            driver,
            size_of::<DeviceContext>() as u32,
            &mut nt_name,
            FILE_DEVICE_UNKNOWN, // If a type of hardware does not match any of the defined types, specify a value of either FILE_DEVICE_UNKNOWN
            FILE_DEVICE_SECURE_OPEN,
            0,
            &mut device_object,
        )
    };
    if !nt_success(res) {
        println!(
            "[sanctum] [-] Unable to create device via IoCreateDevice. Failed with code: {res}."
        );
        driver_exit(driver); // cleanup any resources before returning
        return res;
    }

    //
    // Create the symbolic link
    //
    let res = unsafe { IoCreateSymbolicLink(&mut dos_name, &mut nt_name) };
    if res != 0 {
        println!("[sanctum] [-] Failed to create driver symbolic link. Error: {res}");

        driver_exit(driver); // cleanup any resources before returning
        return STATUS_UNSUCCESSFUL;
    }

    //
    // Configure the drivers general callbacks
    //
    driver.MajorFunction[IRP_MJ_CREATE as usize] = Some(sanctum_create_close); // todo can authenticate requests coming from x
    driver.MajorFunction[IRP_MJ_CLOSE as usize] = Some(sanctum_create_close);
    // (*driver).MajorFunction[IRP_MJ_WRITE as usize] = Some(handle_ioctl);
    driver.MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(handle_ioctl);
    driver.DriverUnload = Some(driver_exit);

    // Specifies the type of buffering that is used by the I/O manager for I/O requests that are sent to the device stack.
    (*device_object).Flags |= DO_BUFFERED_IO;

    STATUS_SUCCESS
}

/// Driver unload functions when it is to exit.
///
/// # Safety
///
/// This function makes use of unsafe code.
extern "C" fn driver_exit(driver: *mut DRIVER_OBJECT) {
    // rm symbolic link
    let mut dos_name = UNICODE_STRING::default();
    let dos_name_u16: Vec<u16> = DOS_DEVICE_NAME.encode_utf16().chain(once(0)).collect();
    unsafe {
        RtlInitUnicodeString(&mut dos_name, dos_name_u16.as_ptr());
    }
    let _ = unsafe { IoDeleteSymbolicLink(&mut dos_name) };

    //
    // Unregister callback routines
    //

    AltSyscalls::uninstall();

    // registry
    unsafe { unregister_registry_monitor() };

    let _ = SyscallPostProcessor::exit();

    // drop the callback for new process interception
    let res =
        unsafe { PsSetCreateProcessNotifyRoutineEx(Some(process_create_callback), TRUE as u8) };
    if res != STATUS_SUCCESS {
        println!(
            "[sanctum] [-] Error removing PsSetCreateProcessNotifyRoutineEx from callback routines. Error: {res}"
        );
    }

    // Drop the callback on image load notifications
    unregister_image_load_callback();

    // drop the callback for new thread interception
    let res = unsafe { PsRemoveCreateThreadNotifyRoutine(Some(thread_callback)) };
    if res != STATUS_SUCCESS {
        println!(
            "[sanctum] [-] Error removing PsSetCreateProcessNotifyRoutineEx from callback routines. Error: {res}"
        );
    }

    // drop the callback routines for process handle interception
    unsafe {
        if !REGISTRATION_HANDLE.load(Ordering::Relaxed).is_null() {
            ObUnRegisterCallbacks(REGISTRATION_HANDLE.load(Ordering::Relaxed));
            REGISTRATION_HANDLE.store(null_mut(), Ordering::Relaxed);
        }
    }

    // drop the driver messages
    let ptr = DRIVER_MESSAGES.load(Ordering::SeqCst);
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }

    // drop the message cache
    let ptr = DRIVER_MESSAGES_CACHE.swap(null_mut(), Ordering::SeqCst);
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }

    // Drop the monitored APIs
    let ptr = MONITORED_FN_PTRS.load(Ordering::SeqCst);
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }

    //
    // Thread cleanup
    //

    terminate_thread_from_grt_str("TERMINATION_FLAG_ETW_MONITOR", "ETW_THREAD_HANDLE");
    terminate_thread_from_grt_str("TERMINATION_FLAG_GH_MONITOR", "GH_THREAD_HANDLE");

    if let Err(e) = unsafe { Grt::destroy() } {
        println!("Error destroying: {:?}", e);
    }

    // delete the device
    unsafe {
        IoDeleteDevice((*driver).DeviceObject);
    }

    println!("[sanctum] driver unloaded successfully...");
}

fn terminate_thread_from_grt_str(flag_str: &'static str, ob_str: &'static str) {
    if let Ok(terminate_etw_thread) = Grt::get_fast_mutex(flag_str) {
        let mut lock = terminate_etw_thread.lock().unwrap();
        *lock = true;
    }
    {
        let thread_handle_grt: Result<&FastMutex<*mut c_void>, wdk_mutex::errors::GrtError> =
            Grt::get_fast_mutex(ob_str);
        if let Ok(thread_handle_grt) = thread_handle_grt {
            let thread_handle = thread_handle_grt.lock().unwrap();

            if !thread_handle.is_null() {
                let status = unsafe {
                    KeWaitForSingleObject(
                        *thread_handle,
                        Executive,
                        KernelMode as _,
                        FALSE as _,
                        null_mut(),
                    )
                };

                if status != STATUS_SUCCESS {
                    println!(
                        "[sanctum] [-] Did not successfully call KeWaitForSingleObject when trying to exit system thread for ETW Monitoring."
                    );
                }
                let _ = unsafe { ObfDereferenceObject(*thread_handle) };
            }
        }
    }
}

unsafe extern "C" fn sanctum_create_close(_device: *mut DEVICE_OBJECT, pirp: PIRP) -> NTSTATUS {
    (*pirp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
    (*pirp).IoStatus.Information = 0;
    IofCompleteRequest(pirp, IO_NO_INCREMENT as i8);

    STATUS_SUCCESS
}

/// Device IOCTL input handler.
///
/// This function will process IOCTL commands as they come into the driver and executing the relevant actions.
///
/// # Arguments
///
/// - '_device': Unused
/// - 'irp': A pointer to the I/O request packet (IRP) that contains information about the request
unsafe extern "C" fn handle_ioctl(_device: *mut DEVICE_OBJECT, pirp: PIRP) -> NTSTATUS {
    let p_stack_location: *mut _IO_STACK_LOCATION = unsafe { IoGetCurrentIrpStackLocation(pirp) };

    if p_stack_location.is_null() {
        println!("[sanctum] [-] Unable to get stack location for IRP.");
        return STATUS_UNSUCCESSFUL;
    }

    let control_code = unsafe { (*p_stack_location).Parameters.DeviceIoControl.IoControlCode }; // IOCTL code

    // process the IOCTL based on its code, note that the functions implementing IOCTL's should
    // contain detailed error messages within the functions, returning a Result<(), NTSTATUS> this will
    // assist debugging exactly where an error has occurred, and not printing it at this level prevents
    // duplication.
    //
    // we still require calling IofCompleteRequest to return the IRP to the I/O manager otherwise we risk
    // causing the driver to hang.
    let result: NTSTATUS = match control_code {
        SANC_IOCTL_PING => {
            if let Err(e) = ioctl_handler_ping(p_stack_location, pirp) {
                println!("[sanctum] [-] Error: {e}");
                e
            } else {
                STATUS_SUCCESS
            }
        }
        SANC_IOCTL_PING_WITH_STRUCT => {
            if let Err(e) = ioctl_handler_ping_return_struct(p_stack_location, pirp) {
                println!("[sanctum] [-] Error: {e}");
                e
            } else {
                STATUS_SUCCESS
            }
        }
        SANC_IOCTL_CHECK_COMPATIBILITY => {
            if let Err(e) = ioctl_check_driver_compatibility(p_stack_location, pirp) {
                println!("[sanctum] [-] Error: {e}");
                e
            } else {
                STATUS_SUCCESS
            }
        }
        SANC_IOCTL_DRIVER_GET_MESSAGE_LEN => {
            if let Err(_) = ioctl_handler_get_kernel_msg_len(pirp) {
                STATUS_UNSUCCESSFUL
            } else {
                STATUS_SUCCESS
            }
        }
        SANC_IOCTL_DRIVER_GET_MESSAGES => {
            if let Err(_) = ioctl_handler_send_kernel_msgs_to_userland(pirp) {
                STATUS_UNSUCCESSFUL
            } else {
                STATUS_SUCCESS
            }
        }
        SANC_IOCTL_DRIVER_GET_IMAGE_LOADS_LEN => {
            if let Err(_) = ioctl_get_image_load_len(pirp) {
                STATUS_UNSUCCESSFUL
            } else {
                STATUS_SUCCESS
            }
        }
        SANC_IOCTL_DRIVER_GET_IMAGE_LOADS => {
            if let Err(_) = ioctl_handler_get_image_loads(pirp) {
                STATUS_UNSUCCESSFUL
            } else {
                STATUS_SUCCESS
            }
        }
        SANC_IOCTL_DLL_SYSCALL => {
            if let Err(_) = ioctl_dll_hook_syscall(p_stack_location, pirp) {
                STATUS_UNSUCCESSFUL
            } else {
                STATUS_SUCCESS
            }
        }
        SANC_IOCTL_SEND_BASE_ADDRS => {
            set_monitored_dll_fn_ptrs(p_stack_location, pirp);
            STATUS_SUCCESS
        }
        SANC_IOCTL_DLL_INJECT_FAILED => {
            if let Err(e) = ioctl_failed_to_inject_dll(p_stack_location, pirp) {
                return e;
            }

            STATUS_SUCCESS
        }
        SANC_IOCTL_PROC_R_GH => ioctl_process_finished_sanc_dll_load(p_stack_location, pirp),

        _ => {
            println!(
                "[sanctum] [-] IOCTL control code: {} not implemented.",
                control_code
            );
            STATUS_UNSUCCESSFUL
        }
    };

    // indicates that the caller has completed all processing for a given I/O request and
    // is returning the given IRP to the I/O manager
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocompleterequest
    unsafe { IofCompleteRequest(pirp, IO_NO_INCREMENT as i8) };

    result
}
