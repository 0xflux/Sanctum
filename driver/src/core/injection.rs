use core::{arch::asm, ffi::c_void, iter::once, ptr::null_mut, sync::atomic::Ordering};

use alloc::{vec, vec::Vec};
use anyhow::{Result, bail};
use wdk::{nt_success, println};
use wdk_sys::{
    _MODE::{KernelMode, UserMode},
    HANDLE, IO_NO_INCREMENT, KAPC, MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READWRITE, PKTHREAD,
    POOL_FLAG_NON_PAGED, PRKAPC, PVOID, UNICODE_STRING,
    ntddk::{
        ExAllocatePool2, ExFreePool, RtlCopyMemoryNonTemporal, RtlInitUnicodeString,
        ZwAllocateVirtualMemory,
    },
};

use crate::{
    core::process_monitor::{MONITORED_FN_PTRS, SensitiveAPI},
    ffi::{
        GetCurrentThread, KeInitializeApc, KeInsertQueueApc, KeTestAlertThread, PKNORMAL_ROUTINE,
        ZwProtectVirtualMemory,
    },
};

const SANCTUM_HOOK_DLL_PATH: &str = r"sanctum.dll";

/// Injects the sanctum DLL which hooks NTDLL into the current process (must be called from an image load callback).
///
/// ### With massive thanks to:
/// - eversinc33 https://x.com/eversinc33 - who provided me access to his src for getting this to work :3
/// - Dennis A. Babkin & Rbmm - helpful blog https://dennisbabkin.com/blog/?t=depths-of-windows-apc-aspects-of-asynchronous-procedure-call-internals-from-kernel-mode
/// - 0xrepnz https://x.com/0xrepnz - cool blog https://repnz.github.io/posts/apc/kernel-user-apc-api/
pub fn inject_dll() -> Result<()> {
    // Inject shellcode into the process to bootstrap the DLL injection
    let shellcode_va = write_shellcode_in_process_for_injection()?;
    // Queue and force the APC to execute LdrLoadDll to inject the DLL
    let _ = queue_apc_run_shellcode(shellcode_va, GetCurrentThread())?;

    Ok(())
}

/// Queues two APC's to execute LdrLoadDll in the process which is being created. The first APC is the user
/// routine which runs a shellcode bootstrap. The second is a kernel APC which forces the thread to become
/// alertable, thus, immediately executing our usermode APC.
fn queue_apc_run_shellcode(shellcode_addr: *const c_void, thread: PKTHREAD) -> Result<()> {
    if shellcode_addr.is_null() {
        bail!("Shellcode address was null.");
    }

    //
    // Initialise kernel APC
    //

    let kapc = unsafe {
        ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            size_of::<KAPC>() as u64,
            u32::from_le_bytes(*b"sanc"),
        )
    } as *mut KAPC;

    unsafe {
        KeInitializeApc(
            &mut *kapc,
            thread,
            crate::ffi::_KAPC_ENVIRONMENT::OriginalApcEnvironment,
            kernel_prepare_inject_apc as *const c_void,
            rundown as *const c_void,
            null_mut(),
            KernelMode as i8,
            null_mut(),
        );
    }

    //
    // Initialize user mode APC to call LdrLoadDll
    //

    let apc = unsafe {
        ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            size_of::<KAPC>() as u64,
            u32::from_le_bytes(*b"sanc"),
        )
    } as *mut KAPC;

    unsafe {
        KeInitializeApc(
            &mut *apc,
            thread,
            crate::ffi::_KAPC_ENVIRONMENT::OriginalApcEnvironment,
            apc_callback_inject_sanctum as *const c_void, // failure = access violation
            rundown as *const c_void,
            shellcode_addr,
            UserMode as i8,
            null_mut(),
        );
    }

    let status =
        unsafe { KeInsertQueueApc(&mut *apc, null_mut(), null_mut(), IO_NO_INCREMENT as _) };
    if !nt_success(status as _) {
        bail!("Failed to insert APC for shellcode execution. Code: {status:#X}");
    }

    let status =
        unsafe { KeInsertQueueApc(&mut *kapc, null_mut(), null_mut(), IO_NO_INCREMENT as _) };
    if !nt_success(status as _) {
        bail!("Failed to insert KAPC for shellcode execution. Code: {status:#X}");
    }

    Ok(())
}

unsafe extern "C" fn rundown(apc: PRKAPC) {
    unsafe {
        ExFreePool(apc as _);
    }
}

unsafe extern "C" fn apc_callback_inject_sanctum(
    apc: PRKAPC,
    _normal_routine: *mut c_void,
    _normal_context: *mut PVOID,
    _system_arg_1: *mut PVOID,
    _system_arg_2: *mut PVOID,
) {
    unsafe { rundown(apc) };
}

unsafe extern "C" fn kernel_prepare_inject_apc(
    apc: PRKAPC,
    _normal_routine: PKNORMAL_ROUTINE,
    _normal_context: *mut PVOID,
    _system_arg_1: *mut PVOID,
    _system_arg_2: *mut PVOID,
) {
    unsafe { KeTestAlertThread(UserMode as i8) };
    unsafe { rundown(apc) };
}

/// Write shellcode into the **current** process for which this is called. The shellcode written causes
/// LdrLoadDll to load the Sanctum DLL into the target process.
///
/// # Returns
/// The virtual address within the target process of where the shellcode was written, or an error.
fn write_shellcode_in_process_for_injection() -> Result<*const c_void> {
    let path: Vec<u16> = SANCTUM_HOOK_DLL_PATH
        .encode_utf16()
        .chain(once(0))
        .collect();

    let mut dll_path_to_inject = UNICODE_STRING::default();

    unsafe { RtlInitUnicodeString(&mut dll_path_to_inject, path.as_ptr()) };

    //
    // Shellcode to load a DLL into a process via LdrLoadDll
    //
    let mut shellcode = vec![
        0x48u8, 0x83, 0xEC, 0x28, // sub rsp, 0x28
        0x48, 0x31, 0xD2, // xor rdx, rdx
        0x48, 0x31, 0xC9, // xor rcx, rcx
        0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov r8, [remoteUnicodeString]
        0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0, // mov r9, [handleOut]
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, [LdrLoadDll]
        0xFF, 0xD0, // call rax
        0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
        0xC3, // ret
    ];

    //
    // Allocate memory for the DLL name and the unicode_string struct
    //
    let dll_name_len: usize = dll_path_to_inject.Length as usize + size_of::<u16>(); // include space for null terminator
    let mut shellcode_size = shellcode.len() as u64;
    let mut total_size: u64 = shellcode_size
        + size_of::<UNICODE_STRING>() as u64
        + dll_name_len as u64
        + size_of::<*const c_void>() as u64;
    let mut remote_shellcode_memory = null_mut();
    let mut remote_memory = null_mut();

    let cur_proc_handle: HANDLE = (-1isize) as HANDLE;

    let status = unsafe {
        ZwAllocateVirtualMemory(
            cur_proc_handle,
            &mut remote_shellcode_memory,
            0,
            &mut shellcode_size,
            MEM_COMMIT,
            PAGE_READWRITE,
        )
    };

    if !nt_success(status) {
        bail!("DLL injection failed on ZwAllocateVirtualMemory with status: {status:#X}");
    }

    let status = unsafe {
        ZwAllocateVirtualMemory(
            cur_proc_handle,
            &mut remote_memory,
            0,
            &mut total_size,
            MEM_COMMIT,
            PAGE_READWRITE,
        )
    };

    if !nt_success(status) {
        bail!("DLL injection failed on ZwAllocateVirtualMemory 2 with status: {status:#X}");
    }

    //
    // Structure of memory:
    //
    // Alloc 1  - Shellcode R(W)X (remote_shellcode_memory)
    //
    // Alloc 2  - UNICODE_STRING RW (remote_memory)
    //          - OUT HANDLE
    //          - Dll Name
    //

    let remote_unicode_string = remote_memory;
    let remote_handle_out = unsafe { remote_memory.add(size_of::<UNICODE_STRING>()) };
    let remote_dll_name = (remote_memory as usize
        + size_of::<UNICODE_STRING>()
        + size_of::<*mut c_void>()) as *mut c_void;

    let ldr_ld_dll_addr = {
        let p_mon_apis = MONITORED_FN_PTRS.load(Ordering::SeqCst);
        let mut addr: usize = 0;

        if !p_mon_apis.is_null() {
            let mon = unsafe { &*p_mon_apis };

            for api in &mon.inner {
                if api.1.1 == SensitiveAPI::LdrLoadDll {
                    addr = *api.0;
                    break;
                }
            }
        }

        addr
    };

    if ldr_ld_dll_addr == 0 {
        bail!("Failed to get address of LdrLoadDll whilst trying DLL injection.")
    }

    //
    // Memory patching
    //

    const OFF_R8_IMM: usize = 12;
    const OFF_R9_IMM: usize = 22;
    const OFF_RAX_IMM: usize = 32;
    const PTR_WIDTH: usize = size_of::<usize>();

    let val_r8 = remote_memory as usize;
    let val_r9 = remote_handle_out as usize;
    let val_rax = ldr_ld_dll_addr as usize;

    //
    // Write to the shellcode block with the newly allocated addresses and addr of LdrLoadDll
    //
    shellcode[OFF_R8_IMM..OFF_R8_IMM + PTR_WIDTH].copy_from_slice(&val_r8.to_le_bytes());
    shellcode[OFF_R9_IMM..OFF_R9_IMM + PTR_WIDTH].copy_from_slice(&val_r9.to_le_bytes());
    shellcode[OFF_RAX_IMM..OFF_RAX_IMM + PTR_WIDTH].copy_from_slice(&val_rax.to_le_bytes());

    unsafe {
        // Patch in the shellcode to the remote region in the target process
        RtlCopyMemoryNonTemporal(
            remote_shellcode_memory,
            shellcode.as_ptr() as *const _,
            shellcode_size,
        );

        // Write the DLL name
        RtlCopyMemoryNonTemporal(
            remote_dll_name,
            dll_path_to_inject.Buffer as *const _,
            dll_name_len as u64,
        );

        let mut remote_unicode = UNICODE_STRING::default();
        remote_unicode.Length = dll_path_to_inject.Length;
        remote_unicode.MaximumLength = dll_path_to_inject.MaximumLength;
        remote_unicode.Buffer = remote_dll_name as *mut u16;

        RtlCopyMemoryNonTemporal(
            remote_unicode_string,
            &remote_unicode as *const UNICODE_STRING as *const c_void,
            size_of::<UNICODE_STRING>() as u64,
        );

        //
        // Make shellcode executable
        //
        let mut op = 0;
        let status = ZwProtectVirtualMemory(
            cur_proc_handle,
            &mut remote_shellcode_memory,
            &mut shellcode_size,
            PAGE_EXECUTE_READ,
            &mut op,
        );

        if !nt_success(status) {
            println!("Failed to mark shellcode memory as executable. Status: {status:#X}");

            // todo free memory
        }
    }

    Ok(remote_shellcode_memory)
}
