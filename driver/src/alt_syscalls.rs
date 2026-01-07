//! The `AltSyscalls` module is designed merely as the intercept mechanism for using Alternate Syscalls on Windows 11.
//! This module also defines the callback routine for handling the first stage interception; but actual post-processing of the data
//! is conducted elsewhere (in the case where we do not want to block a certain action).
//!
//! Currently; the Alt Syscalls mechanism is not designed to block activity - but it could be refactored in the future to do so
//! in certain situations.
//!
//! The mechanism of post processing [`queue_syscall_post_processing`] is using queued `wdk_mutex` and offloading the work to a system worker thread within
//! the driver, as to not degrade system performance.

use core::{arch::asm, ffi::c_void, ptr::null_mut};

use alloc::{boxed::Box, vec::Vec};
use wdk::println;
use wdk_sys::{
    _KTRAP_FRAME,
    _MODE::KernelMode,
    DISPATCHER_HEADER, DRIVER_OBJECT, HANDLE, KTRAP_FRAME, OBJ_KERNEL_HANDLE, PETHREAD, PKTHREAD,
    PROCESS_ALL_ACCESS, PsThreadType, THREAD_ALL_ACCESS,
    ntddk::{
        IoGetCurrentProcess, IoThreadToProcess, ObReferenceObjectByHandle, ObfDereferenceObject,
        ZwClose,
    },
};

use crate::{
    core::syscall_processing::{AllowSyscall, KernelSyscallIntercept},
    ffi::{ZwGetNextProcess, ZwGetNextThread},
    utils::{
        DriverError, get_module_base_and_sz, get_process_name, scan_module_for_byte_pattern,
        thread_to_process_name,
    },
};

const SLOT_ID: u32 = 0;
const SSN_COUNT: usize = 0x500;

pub const SSN_NT_OPEN_PROCESS: u32 = 0x26;
pub const SSN_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x18;
pub const SSN_NT_CREATE_THREAD_EX: u32 = 0x00c9;
pub const SSN_NT_WRITE_VM: u32 = 0x003a;

const NT_OPEN_FILE: u32 = 0x0033;
const NT_CREATE_SECTION: u32 = 0x004a;
const NT_CREATE_SECTION_EX: u32 = 0x00c6;
const NT_DEVICE_IO_CONTROL_FILE: u32 = 0x0007;
const NT_CREATE_FILE_SSN: u32 = 0x0055;
const NT_TRACE_EVENT_SSN: u32 = 0x005e;

pub struct AltSyscalls;

#[repr(C)]
pub struct PspServiceDescriptorGroupTable {
    rows: [PspServiceDescriptorRow; 0x20],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PspServiceDescriptorRow {
    driver_base: *const c_void,
    ssn_dispatch_table: *const AltSyscallDispatchTable,
    _reserved: *const c_void,
}

#[repr(C)]
struct PspSyscallProviderDispatchContext {
    level: u32,
    slot: u32,
}

#[repr(C)]
struct AltSyscallDispatchTable {
    pub count: u64,
    pub descriptors: [u32; SSN_COUNT],
}

#[derive(Copy, Clone)]
pub enum AltSyscallStatus {
    Enable,
    Disable,
}

impl AltSyscalls {
    /// Initialises the required tables in memory.
    ///
    /// This function should only be called once until it is disabled.
    pub fn initialise_for_system(driver: &mut DRIVER_OBJECT) {
        // How many stack args we want to memcpy; I use my own method to get these..
        const NUM_QWORD_STACK_ARGS_TO_CPY: u32 = 0x0;
        // These flags ensure we go the PspSyscallProviderServiceDispatchGeneric route
        const GENERIC_PATH_FLAGS: u32 = 0x10;

        // Enforce the SLOT_ID rules at compile time
        const _: () = assert!(SLOT_ID <= 20, "SLOT_ID for alt syscalls cannot be > 20");

        //
        // Get the base address of the driver, so that we can bit shift in the RVA of the callback.
        //
        let driver_base = match get_module_base_and_sz("sanctum.sys") {
            Ok(info) => info.base_address,
            Err(e) => {
                println!("[-] Could not get base address of driver. {:?}", e);
                return;
            }
        };

        //
        // Now build the 'mini dispatch table':  one per descriptor. Each index of the descriptor contains a relative pointer from the driver base
        // address to the callback function.
        //
        // low–4 bits   = metadata (0x10 = generic path + N args to capture via a later memcpy),
        // high bits    = descriptor index<<4.
        //
        // Setting FLAGS |= (METADATA & 0xF) means generic path, capture N args
        //
        let callback_address = syscall_handler as *const c_void as usize;
        let metadata_table = Box::new(AltSyscallDispatchTable {
            count: SSN_COUNT as _,
            descriptors: [0; SSN_COUNT],
        });

        // Leak the box so that we don't (for now) have to manage the memory; yes, this is a memory leak in the kernel, I'll fix it later.
        let p_metadata_table = Box::leak(metadata_table) as *const AltSyscallDispatchTable;

        let rva_offset_callback = callback_address - driver_base as usize;
        // SAFETY: Check the offset size will fit into a u32
        if rva_offset_callback > u32::MAX as _ {
            println!(
                "[sanctum] [-] Offset calculation very wrong? Offset: {:#x}",
                rva_offset_callback
            );
            return;
        }

        for i in 0..SSN_COUNT {
            unsafe { &mut *(p_metadata_table as *mut AltSyscallDispatchTable) }.descriptors[i] =
                ((rva_offset_callback as u32) << 4)
                    | (GENERIC_PATH_FLAGS | (NUM_QWORD_STACK_ARGS_TO_CPY & 0xF));
        }

        // Get the address of PspServiceDescriptorGroupTable from the kernel by doing some pattern matching; I don't believe
        // we can link to the symbol.
        let kernel_service_descriptor_table = match lookup_global_table_address(driver) {
            Ok(t) => t as *mut PspServiceDescriptorGroupTable,
            Err(_) => {
                println!("[sanctum] failed to find kernel table");
                return;
            }
        };

        //
        // Insert a new row at index 0 in the PspServiceDescriptorGroupTable; in theory, if these were already occupied by other software
        // using alt syscalls, we would want to find an unoccupied slot.
        // This is what the Slot field relates to on the _PSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT of _EPROCESS - essentially an index into which
        // syscall provider to use.
        //
        let new_row = PspServiceDescriptorRow {
            driver_base,
            ssn_dispatch_table: p_metadata_table,
            _reserved: core::ptr::null(),
        };

        // Write it to the table
        unsafe {
            (*kernel_service_descriptor_table).rows[SLOT_ID as usize] = new_row;
        }

        // Enumerate all active processes and threads, and enable the relevant bits so that the alt syscall 'machine' can work :)
        // Self::walk_active_processes_and_set_bits(AltSyscallStatus::Enable, None);
    }

    /// Sets the required context bits in memory on thread and KTHREAD.
    pub fn configure_thread_for_alt_syscalls(p_k_thread: PKTHREAD, status: AltSyscallStatus) {
        if p_k_thread.is_null() {
            return;
        }

        // Check if is pico process, if it is, we don't want to mess with it, as I haven't spent time reversing the branch
        // for this in PsSyscallProviderDispatch.
        let dispatch_hdr = unsafe { &mut *(p_k_thread as *mut DISPATCHER_HEADER) };

        if unsafe {
            dispatch_hdr
                .__bindgen_anon_1
                .__bindgen_anon_6
                .__bindgen_anon_2
                .DebugActive
                & 4
        } == 4
        {
            return;
        }

        // Assuming now we are not a pico-process; set / unset the AltSyscall bit on the ETHREAD depending upon
        // the `status` argument to this function.
        unsafe {
            match status {
                AltSyscallStatus::Enable => {
                    dispatch_hdr
                        .__bindgen_anon_1
                        .__bindgen_anon_6
                        .__bindgen_anon_2
                        .DebugActive |= 0x20
                }
                AltSyscallStatus::Disable => {
                    dispatch_hdr
                        .__bindgen_anon_1
                        .__bindgen_anon_6
                        .__bindgen_anon_2
                        .DebugActive &= !0x20
                }
            }
        }
    }

    pub fn configure_process_for_alt_syscalls(p_k_thread: PKTHREAD) {
        // We can cast the KTHREAD* as a ETHREAD* as KTHREAD = ETHREAD bytes 0x0 - 0x4c0
        // so they directly map.
        // We will cast the resulting EPROCESS as a *mut u8 as EPROCESS is not defined by the Windows API, and we can just use
        // some pointer arithmetic to edit the fields we want.
        let p_eprocess = unsafe { IoThreadToProcess(p_k_thread as PETHREAD) } as *mut u8;
        let syscall_provider_dispatch_ctx: &mut PspSyscallProviderDispatchContext =
            if !p_eprocess.is_null() {
                unsafe {
                    let addr = p_eprocess.add(0x7d0) as *mut PspSyscallProviderDispatchContext;
                    // SAFETY: I think the dereference of this is fine; we are dereferencing an offset from the EPROCESS - it is not a double pointer.
                    // We check the validity of the EPROCESS above before doing this, as that should always be valid. But this deref should be safe.
                    &mut *addr
                }
            } else {
                return;
            };

        // Set slot id
        syscall_provider_dispatch_ctx.slot = SLOT_ID;
    }

    /// Uninstall the Alt Syscall handlers from the kernel.
    pub fn uninstall() {
        Self::walk_active_processes_and_set_bits(AltSyscallStatus::Disable, None);

        // todo clean up the allocated memory
    }

    /// Walk all processes and threads, and set the bits on the process & thread to either enable or disable the
    /// alt syscall method.
    ///
    /// # Args:
    /// - `status`: Whether you wish to enable, or disable the feature
    /// - `isolated_processes`: If you wish just to set the relevant bits on a single process; then add a vec of process names
    /// to match on, with a *name* logic.
    ///
    /// # Note:
    /// This function is specifically crafted for W11 24H2; to generalise in the future after POC
    fn walk_active_processes_and_set_bits(
        status: AltSyscallStatus,
        isolated_processes: Option<&[&str]>,
    ) {
        let current_process = unsafe { IoGetCurrentProcess() };
        if current_process.is_null() {
            println!("[sanctum] [-] current_process was NULL");
            return;
        }

        //
        // Walk the active processes & threads via reference counting to ensure that the
        // threads & processes aren't terminated during the walk (led to race condition).
        //
        // For each process & thread, enable to relevant bits for Alt Syscalls.
        //

        let mut next_proc: HANDLE = null_mut();
        let mut cur_proc: HANDLE = null_mut();
        let mut cur_thread: HANDLE = null_mut();
        let mut next_thread: HANDLE = null_mut();

        // Store a vec of handles to be closed after we have completed all operations
        let mut handles: Vec<HANDLE> = Vec::new();

        loop {
            let result = unsafe {
                ZwGetNextProcess(
                    cur_proc,
                    PROCESS_ALL_ACCESS,
                    OBJ_KERNEL_HANDLE,
                    0,
                    &mut next_proc,
                )
            };

            if result != 0 || cur_proc == next_proc {
                break;
            }

            cur_proc = next_proc;

            // Now walk the threads of the process
            loop {
                let result = unsafe {
                    ZwGetNextThread(
                        cur_proc,
                        cur_thread,
                        THREAD_ALL_ACCESS,
                        OBJ_KERNEL_HANDLE,
                        0,
                        &mut next_thread,
                    )
                };

                if result != 0 || cur_thread == next_thread {
                    break;
                }

                cur_thread = next_thread;

                let mut pe_thread: *mut c_void = null_mut();

                let _ = unsafe {
                    ObReferenceObjectByHandle(
                        cur_thread,
                        THREAD_ALL_ACCESS,
                        *PsThreadType,
                        KernelMode as _,
                        &mut pe_thread,
                        null_mut(),
                    )
                };

                if !pe_thread.is_null() {
                    // Before we actually go ahead and set the bits; we wanna check whether the caller is requesting the bits
                    // set ONLY on certain processes. The below logic will check whether that argument is Some, and if so,
                    // check the process information to set the bits.
                    // If it is `None`, we will skip the check and just set all process & thread info

                    if let Some(proc_vec) = &isolated_processes {
                        match thread_to_process_name(pe_thread as *mut _) {
                            Ok(current_process_name) => {
                                for needle in proc_vec.into_iter() {
                                    if current_process_name
                                        .to_lowercase()
                                        .contains(&needle.to_lowercase())
                                    {
                                        println!(
                                            "[sanctum] [+] Process name found for alt syscalls: {}",
                                            needle
                                        );
                                        Self::configure_thread_for_alt_syscalls(
                                            pe_thread as *mut _,
                                            status,
                                        );
                                        Self::configure_process_for_alt_syscalls(
                                            pe_thread as *mut _,
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                println!(
                                    "[sanctum] [-] Unable to get process name to set alt syscall bits on targeted process. {:?}",
                                    e
                                );
                                let _ = unsafe { ObfDereferenceObject(pe_thread) };
                                continue;
                            }
                        }
                    }

                    Self::configure_thread_for_alt_syscalls(pe_thread as *mut _, status);
                    Self::configure_process_for_alt_syscalls(pe_thread as *mut _);

                    let _ = unsafe { ObfDereferenceObject(pe_thread) };
                }

                handles.push(cur_thread);
            }

            // Reset so we can walk the threads again on the next process
            cur_thread = null_mut();

            handles.push(cur_proc);
        }

        // Close the handles to dec the ref count
        for handle in handles {
            let _ = unsafe { ZwClose(handle) };
        }
    }
}

/// A local definition of a KTHREAD, seeing as though the WDK doesn't export one for us. If this changes
/// between kernel builds, it will cause problems :E
#[repr(C)]
struct KThreadLocalDef {
    junk: [u8; 0x90],
    k_trap_ptr: *mut KTRAP_FRAME,
}

#[inline(always)]
fn extract_trap() -> Option<*const _KTRAP_FRAME> {
    let mut k_thread: *const c_void = null_mut();
    unsafe {
        asm!(
            "mov {}, gs:[0x188]",
            out(reg) k_thread,
        );
    }

    if k_thread.is_null() {
        println!("[-] [Sanctum] No KTHREAD discovered.");
        return None;
    }

    let p_ktrap = unsafe { &*(k_thread as *const KThreadLocalDef) }.k_trap_ptr;

    Some(p_ktrap)
}

/// The callback routine which we control to run when a system call is dispatched via my alt syscall technique.
///
/// # Args:
/// - `p_nt_function`: A function pointer to the real Nt* dispatch function (e.g. NtOpenProcess)
/// - `ssn`: The System Service Number of the syscall
/// - `args_base`: The base address of the args passed into the original syscall rcx, rdx, r8 and r9
/// - `p3_home`: The address of `P3Home` of the _KTRAP_FRAME
///
/// # Note:
/// We can use the `p3_home` arg that is passed into this callback to calculate the actual address of the
/// `KTRAP_FRAME`, where we can get the address of the stack pointer, that we can use to gather any additional
/// arguments which were passed into the syscall.
///
/// # Safety
/// This function is **NOT** compatible with the `PspSyscallProviderServiceDispatch` branch of alt syscalls, it
/// **WILL** result in a bug check in that instance. This can only be used with
/// `PspSyscallProviderServiceDispatchGeneric`.
pub unsafe extern "system" fn syscall_handler(
    _p_nt_function: c_void,
    ssn: u32,
    _args_base: *const c_void,
    _p3_home: *const c_void,
) -> i32 {
    // todo remove once ready for mass testing
    let proc_name = get_process_name().to_lowercase();
    if !proc_name.contains("notepad.e") && !proc_name.contains("alware.e") {
        return 1;
    }

    let ktrap_frame = match extract_trap() {
        Some(p) => unsafe { *p },
        None => {
            println!("[-] [sanctum] Could not get trap for syscall intercept.");
            return 1;
        }
    };

    let allowed = match ssn {
        SSN_NT_OPEN_PROCESS
        | SSN_NT_ALLOCATE_VIRTUAL_MEMORY
        | SSN_NT_WRITE_VM
        | SSN_NT_CREATE_THREAD_EX => KernelSyscallIntercept::from_alt_syscall(ktrap_frame),
        _ => AllowSyscall::Yes,
    };

    allowed as i32
}

/// Get the address of the non-exported kernel symbol: `PspServiceDescriptorGroupTable`
fn lookup_global_table_address(_driver: &DRIVER_OBJECT) -> Result<*mut c_void, DriverError> {
    let module = match get_module_base_and_sz("ntoskrnl.exe") {
        Ok(k) => k,
        Err(e) => {
            println!("[sanctum] [-] Unable to get kernel base address. {:?}", e);
            return Err(DriverError::ModuleNotFound);
        }
    };

    let fn_address = scan_module_for_byte_pattern(
        module.base_address,
        module.size_of_image,
        &[
            // from nt!PsSyscallProviderDispatch
            0x48, 0x89, 0x5c, 0x24, 0x08, //mov     qword ptr [rsp+8], rbx
            0x55, // push    rbp
            0x56, // push    rsi
            0x57, // push    rdi
            0x41, 0x56, // push    r14
            0x41, 0x57, // push    r15
            0x48, 0x83, 0xec, 0x30, // sub     rsp, 30h
            0x48, 0x83, 0x64, 0x24, 0x70, 0x00, // and     qword ptr [rsp+70h], 0
            0x48, 0x8b, 0xf1, // mov     rsi, rcx
            0x65, 0x48, 0x8b, 0x2c, 0x25, 0x88, 0x01, 0x00,
            0x00, // mov     rbp, qword ptr gs:[188h]
            0xf6, 0x45, 0x03, 0x04, // test    byte ptr [rbp+3], 4
        ],
    )? as *const u8;

    // offset from fn
    let instruction_address = unsafe { fn_address.add(0x77) };

    let disp32 =
        unsafe { core::ptr::read_unaligned((instruction_address.add(3)) as *const i32) } as isize;
    let next_rip = instruction_address as isize + 7;
    let absolute = (next_rip + disp32) as *const c_void;

    Ok(absolute as *mut _)
}
