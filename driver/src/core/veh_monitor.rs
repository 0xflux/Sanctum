use core::{
    ffi::{CStr, c_void},
    mem::{transmute, zeroed},
    ptr::null_mut,
    slice::{self},
};

use alloc::{format, string::String};
use wdk::{nt_success, println};
use wdk_sys::{
    _CONTEXT,
    _MEMORY_INFORMATION_CLASS::MemoryBasicInformation,
    _MODE::{KernelMode, UserMode},
    CONTEXT_ALL, MEMORY_BASIC_INFORMATION, MEMORY_INFORMATION_CLASS, NTSTATUS, PASSIVE_LEVEL,
    PROCESS_ALL_ACCESS, PsProcessType, TRUE, UNICODE_STRING,
    ntddk::{
        KeGetCurrentIrql, KeStackAttachProcess, KeUnstackDetachProcess, ObOpenObjectByPointer,
        PsGetThreadProcess, PsIsSystemThread, PsIsThreadTerminating, ZwClose, ZwQueryVirtualMemory,
    },
};

use crate::utils::{AllThreadsIterator, get_module_base_and_sz, scan_module_for_byte_pattern};

unsafe extern "system" {

    // https://codemachine.com/articles/top_ten_kernel_apis.html
    fn RtlFindExportedRoutineByName(
        dll_base: *const c_void,
        routine_name: *const u8,
    ) -> *const c_void;
}

type PspGetContextThreadInternal = unsafe extern "system" fn(
    thread: *const c_void,
    ctx: *mut _CONTEXT,
    _: u8,
    _: u8,
    _: u8,
) -> NTSTATUS;

#[allow(non_snake_case)]
pub fn search_for_amsi_veh_squared() {
    let PspGetContextThreadInternal = if let Some(f) = get_addr_psp_get_context_thread_internal() {
        unsafe { transmute::<_, PspGetContextThreadInternal>(f) }
    } else {
        println!("[sanctum] [-] Did not get address of PspGetContextThreadInternal.");
        return;
    };

    for pe_thread in AllThreadsIterator::new() {
        // Check we aren't about to deref a thread which could cause us a headache
        unsafe {
            let irql = KeGetCurrentIrql();

            if PsIsSystemThread(pe_thread as _) == TRUE as u8
                || PsIsThreadTerminating(pe_thread as _) == TRUE as u8
                || irql != PASSIVE_LEVEL as u8
            {
                continue;
            }
        }

        let mut ctx = unsafe { zeroed::<_CONTEXT>() };
        ctx.ContextFlags = CONTEXT_ALL;

        unsafe {
            //
            // Get thread context.. Tried for a long time to make PsGetThreadContext to work
            // but alas, it failed. Thx to:
            // https://www.unknowncheats[.]me/forum/c-and-c-/210736-psgetcontextthread-returns-status_unsuccessful.html
            //
            // I also have no issue here needing not to suspend threads.. so.. I guess we good
            //
            let status = PspGetContextThreadInternal(
                pe_thread,
                &mut ctx,
                KernelMode as u8,
                UserMode as u8,
                KernelMode as u8,
            );

            if !nt_success(status) {
                println!("[sanctum][-] Failed to get thread context. {status:#X}.");
                continue;
            }

            //
            // Do we have a debug register in use?
            //
            if ctx.Dr0 != 0 {
                let msg = format!(
                    "[sanctum] [i] Thread: {pe_thread:p} - rip: {:p}, dr0: {:p}",
                    ctx.Rip as *const c_void, ctx.Dr0 as *const c_void,
                );
                println!("{}", msg);

                //
                // Does the address match that of NtEventWrite (userland ETW evasion detection)?
                //
                check_veh_abuse(pe_thread, ctx.Dr0 as *const c_void);
            }
        }
    }
}

#[rustfmt::skip]
fn get_addr_psp_get_context_thread_internal() -> Option<*const c_void> {
    let module = match get_module_base_and_sz("ntoskrnl.exe") {
        Ok(k) => k,
        Err(e) => {
            println!("[sanctum] [-] Unable to get kernel base address. {:?}", e);
            return None;
        }
    };

    // note valid for at least 25H2
    let fn_address = scan_module_for_byte_pattern(
        module.base_address,
        module.size_of_image,
        &[
            0x40, 0x55,                                 // push rbp
            0x56,                                       // push rsi
            0x57,                                       // push rdi
            0x41, 0x54,                                 // push r12
            0x41, 0x55,                                 // push r13
            0x41, 0x56,                                 // push r14
            0x41, 0x57,                                 // push r15
            0x48, 0x81, 0xec, 0x00, 0x02, 0x00, 0x00,   // sub rsp, 200h
            0x48, 0x8d, 0x6c, 0x24, 0x40,               // lea rbp, [rsp+40h]
            0x48, 0x89, 0x9d, 0x10, 0x02, 0x00, 0x00,   // mov qword ptr [rbp+210h], rbx
        ],
    );

    let fn_address = match fn_address {
        Ok(f) => f,
        Err(e) => {
            println!("[sanctum] [-] Could not find function bytes. Error: {e:?}");
            return None;
        },
    } as *const c_void;

    Some(fn_address)
}

#[allow(non_upper_case_globals)]
fn check_veh_abuse(pe_thread: *const c_void, offending_address: *const c_void) {
    let pe_process = unsafe { PsGetThreadProcess(pe_thread as _) } as *const c_void;
    let mut apc_state = unsafe { zeroed() };
    unsafe {
        KeStackAttachProcess(pe_process as _, &mut apc_state);
    }

    let mut handle = null_mut();
    let mut status = unsafe {
        ObOpenObjectByPointer(
            pe_process as _,
            0,
            null_mut(),
            PROCESS_ALL_ACCESS,
            *PsProcessType,
            KernelMode as i8,
            &mut handle,
        )
    };

    if !nt_success(status) {
        println!("[sanctum] [-] Failed to get a handle to the process. Error: {status:#X}");
        unsafe { KeUnstackDetachProcess(&mut apc_state) };
        return;
    }

    unsafe {
        let mut mem_info = MEMORY_BASIC_INFORMATION::default();
        let mut out_len: u64 = 0;

        status = ZwQueryVirtualMemory(
            handle,
            offending_address as _,
            MemoryBasicInformation,
            &mut mem_info as *mut _ as *mut c_void,
            size_of::<MEMORY_BASIC_INFORMATION>() as u64,
            &mut out_len,
        );
        if !nt_success(status) {
            println!("[sanctum] [-] Failed to call ZwQueryVirtualMemory. Error: {status:#X}");
            KeUnstackDetachProcess(&mut apc_state);
            let _ = ZwClose(handle);
            return;
        }

        //
        // Now retrieve the module name
        //

        let mut path_buf = [0u8; 512];
        // source https://docs.rs/ntapi/latest/ntapi/ntmmapi/constant.MemoryMappedFilenameInformation.html
        const MemoryMappedFilenameInformation: MEMORY_INFORMATION_CLASS = 2;

        status = ZwQueryVirtualMemory(
            handle,
            offending_address as _,
            MemoryMappedFilenameInformation,
            &mut path_buf as *mut _ as *mut c_void,
            path_buf.len() as u64,
            &mut out_len,
        );
        if !nt_success(status) {
            println!(
                "[sanctum] [-] Failed to call ZwQueryVirtualMemory 2nd time. Error: {status:#X}"
            );
        }

        let unicode = &*(path_buf.as_ptr() as *const UNICODE_STRING);

        let module_name = if unicode.Length != 0 {
            let s = slice::from_raw_parts(unicode.Buffer, (unicode.Length as usize) / 2);
            String::from_utf16_lossy(s)
        } else {
            String::from("Unknown")
        };

        println!("Module name: {:?}", module_name);

        if module_name.to_ascii_lowercase().ends_with("amsi.dll") {
            if let Some(name) =
                search_module_for_sensitive_addresses(mem_info.AllocationBase, offending_address)
            {
                println!(
                    "[sanctum] [ABUSE] Vectored Exception Handling abuse detected at function {name}"
                );
            }
        }

        KeUnstackDetachProcess(&mut apc_state);
        let _ = ZwClose(handle);
    }
}

const SENSITIVE_API_NAMES: [&[u8]; 5] = [
    b"AmsiScanBuffer\0",
    b"AmsiScanString\0",
    b"EtwEventWrite\0",
    b"EtwEventWriteFull\0",
    b"NtTraceEvent\0",
];

/// Searches through a **mapped** module in memory for a series of pre-defined functions that are protected against
/// Vectored Exception Handling abuse through the debug registers. This works against VEH^2 also which was researched
/// first by CrowdStrike.
///
/// # Safety
///
/// This function **MUST** be called whilst attached to a process stack via `KeStackAttachProcess` or it will Bug Check.
///
/// # Args
///
/// - `allocation_base`: The base address of the module you wish to search, with it being a **mapped** image.
/// - `target_address`: The address you are looking to see if it is a monitored, sensitive address.
unsafe fn search_module_for_sensitive_addresses(
    allocation_base: *const c_void,
    target_address: *const c_void,
) -> Option<String> {
    // Some safety..
    if allocation_base.is_null() || target_address.is_null() {
        return None;
    }

    //
    // Iterate through each API name we are monitoring and see if we get a match on the address
    //
    unsafe {
        for name in SENSITIVE_API_NAMES {
            let result = RtlFindExportedRoutineByName(allocation_base, name.as_ptr());
            if result.is_null() {
                continue;
            }

            //
            // Check whether the debug register is set on our API of concern
            //
            if result == target_address {
                let cstr = CStr::from_bytes_with_nul(name)
                    .unwrap_or(CStr::from_bytes_with_nul(b"Unknown\0").unwrap());

                return Some(cstr.to_string_lossy().into_owned());
            }
        }
    }

    None
}
