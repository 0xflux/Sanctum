//! Stubs that act as callback functions from syscalls.

use std::{arch::asm, ffi::c_void};

use windows::{core::PCSTR, Win32::{Foundation::HANDLE, System::WindowsProgramming::CLIENT_ID, UI::WindowsAndMessaging::{MessageBoxA, MB_OK}}};

/// Injected DLL routine for examining the arguments passed to ZwOpenProcess and NtOpenProcess from 
/// any process this DLL is injected into.
#[unsafe(no_mangle)]
unsafe extern "system" fn open_process(
    process_handle: HANDLE,
    desired_access: u32,
    object_attrs: *mut c_void,
    client_id: *mut CLIENT_ID,
) {
    // todo automate the syscall number so not hardcoded
    if !client_id.is_null() {
        let pid = unsafe {(*client_id).UniqueProcess};
        let x = format!("UniqueProcess: {:?}, proc hand: {:?}\0", pid, process_handle);
        unsafe { MessageBoxA(None, PCSTR::from_raw(x.as_ptr()), PCSTR::from_raw(x.as_ptr()), MB_OK) };
    }
    
    let ssn = 0x26; // give the compiler awareness of rax

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",
            in("rax") ssn,
            // Use the asm macro to load our registers so that the Rust compiler has awareness of the
            // use of the registers. Loading these by hands caused some instability
            inlateout("rcx") process_handle.0 => _,
            inlateout("rdx") desired_access => _,
            inlateout("r8") object_attrs => _,
            inlateout("r9") client_id => _,

            options(nostack, preserves_flags)
        );
    }
}
