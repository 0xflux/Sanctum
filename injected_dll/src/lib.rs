use integrity::start_ntdll_integrity_monitor;
use shared_no_std::ghost_hunting::DLLMessage;
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::mem;
use std::sync::LazyLock;
use stubs::nt_protect_virtual_memory;
use threads::{resume_all_threads, suspend_all_threads};
use windows::core::s;
use windows::{
    Win32::{
        Foundation::{GetLastError, STATUS_SUCCESS},
        System::{
            Diagnostics::Debug::FlushInstructionCache,
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect},
            SystemServices::*,
            Threading::{CreateThread, GetCurrentProcess, THREAD_CREATION_FLAGS},
        },
        UI::WindowsAndMessaging::{MB_OK, MessageBoxA},
    },
    core::PCSTR,
};

use crate::ipc::send_ipc_to_engine;
use crate::stubs::{
    nt_create_thread_ex_intercept, nt_open_process, nt_write_virtual_memory, virtual_alloc_ex,
};

mod integrity;
mod ipc;
mod stubs;
mod threads;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
fn DllMain(_: usize, dw_reason: u32, _: usize) -> i32 {
    match dw_reason {
        DLL_PROCESS_ATTACH => {
            // Initialise the DLL in a new thread. Calling this from DllMain is always a bad idea;
            // for more info check my blog: https://fluxsec.red/remote-process-dll-injection#a-dll-update-automatic-unloading
            unsafe {
                let _ = CreateThread(
                    None,
                    0,
                    Some(initialise_injected_dll),
                    None,
                    THREAD_CREATION_FLAGS(0),
                    None,
                );
            }
        }
        _ => (),
    }

    1
}

/// Initialise the DLL by resolving function pointers to our syscall hook callbacks.
unsafe extern "system" fn initialise_injected_dll(_: *mut c_void) -> u32 {
    //
    // The order of setup will be to:
    // 1) Suspend all threads except for this thread.
    // 2) Hash NTDLL which also starts the integrity checker in its own thread.
    // 3) Perform all modification and patching of the current process.
    // 4) Resume all threads
    //

    // suspend the threads
    let suspended_handles = suspend_all_threads();

    // Get the addresses of what we want to hook
    let stub_addresses = StubAddresses::new();

    patch_ntdll(&stub_addresses);

    // this must be called after the patching and BEFORE the resumption of all threads
    start_ntdll_integrity_monitor();

    ioctl_initialised();

    resume_all_threads(suspended_handles);

    STATUS_SUCCESS.0 as _
}

/// A structure to hold the stub addresses for each callback function we wish to have for syscalls.
///
/// The address of each function within the DLL will be used to overwrite memory in the syscall, allowing us to jmp
/// to the address.
pub struct StubAddresses<'a> {
    addresses: BTreeMap<&'a str, Addresses>,
}

struct Addresses {
    edr: usize,
    ntdll: usize,
}

impl<'a> StubAddresses<'a> {
    /// Retrieve the virtual addresses of all callback functions for the DLL.
    fn new() -> Self {
        // Get a handle to ntdll
        let h_ntdll = unsafe { GetModuleHandleA(s!("Ntdll.dll")) };
        let h_ntdll = match h_ntdll {
            Ok(h) => h,
            Err(_) => todo!(),
        };

        #[cfg(debug_assertions)]
        {
            let x = format!("Injecting Sanctum DLL\0");
            unsafe {
                MessageBoxA(
                    None,
                    PCSTR::from_raw(x.as_ptr() as *mut _),
                    PCSTR::from_raw(x.as_ptr() as *mut _),
                    MB_OK,
                )
            };
        }

        //
        // Get function pointers to the functions we wish to hook
        //

        // ZwOpenProcess
        let zwop = unsafe { GetProcAddress(h_ntdll, s!("ZwOpenProcess")) };
        let zwop = match zwop {
            None => {
                unsafe {
                    MessageBoxA(
                        None,
                        s!("Could not get fn addr"),
                        s!("Could not get fn addr"),
                        MB_OK,
                    )
                };
                panic!("Oh no :("); // todo dont panic a process?
            }
            Some(address) => address as *const (),
        } as usize;

        // NtCreateThreadEx
        let ntctx = unsafe { GetProcAddress(h_ntdll, s!("NtCreateThreadEx")) };
        let ntctx = match ntctx {
            None => {
                unsafe {
                    MessageBoxA(
                        None,
                        s!("Could not get fn addr ntctx"),
                        s!("Could not get fn addr ntctx"),
                        MB_OK,
                    )
                };
                panic!("Oh no :("); // todo dont panic a process?
            }
            Some(address) => address as *const (),
        } as usize;

        // ZwAllocateVirtualMemory
        let zwavm = unsafe { GetProcAddress(h_ntdll, s!("ZwAllocateVirtualMemory")) };
        let zwavm = match zwavm {
            None => {
                unsafe {
                    MessageBoxA(
                        None,
                        s!("Could not get fn addr"),
                        s!("Could not get fn addr"),
                        MB_OK,
                    )
                };
                panic!("Oh no :("); // todo dont panic a process?
            }
            Some(address) => address as *const (),
        } as usize;

        // NtWriteVirtualMemory
        let zwvm = unsafe { GetProcAddress(h_ntdll, s!("NtWriteVirtualMemory")) };
        let zwvm = match zwvm {
            None => {
                unsafe {
                    MessageBoxA(
                        None,
                        s!("Could not get fn addr NtWriteVirtualMemory"),
                        s!("Could not get fn addr NtWriteVirtualMemory"),
                        MB_OK,
                    )
                };
                panic!("Oh no :("); // todo dont panic a process?
            }
            Some(address) => address as *const (),
        } as usize;

        // NtProtectVirtualMemory
        let ntpvm = unsafe { GetProcAddress(h_ntdll, s!("NtProtectVirtualMemory")) };
        let ntpvm = match ntpvm {
            None => {
                unsafe {
                    MessageBoxA(
                        None,
                        s!("Could not get fn addr NtProtectVirtualMemory"),
                        s!("Could not get fn addr NtProtectVirtualMemory"),
                        MB_OK,
                    )
                };
                panic!("Oh no :("); // todo dont panic a process?
            }
            Some(address) => address as *const (),
        } as usize;

        //
        // Insert into the BTreeMap tracking the address resolutions
        //
        let mut hm: BTreeMap<&str, Addresses> = BTreeMap::new();
        hm.insert(
            "NtOpenProcess",
            Addresses {
                edr: nt_open_process as usize,
                ntdll: zwop,
            },
        );
        hm.insert(
            "NtAllocateVirtualMemory",
            Addresses {
                edr: virtual_alloc_ex as usize,
                ntdll: zwavm,
            },
        );
        hm.insert(
            "NtWriteVirtualMemory",
            Addresses {
                edr: nt_write_virtual_memory as usize,
                ntdll: zwvm,
            },
        );
        hm.insert(
            "NtCreateThreadEx",
            Addresses {
                edr: nt_create_thread_ex_intercept as usize,
                ntdll: ntctx,
            },
        );

        // Prefix this with ZZZ to make sure it is to be the very last item. We need to make sure this is processed
        // last, otherwise we will crash each process whilst we set them up!
        hm.insert(
            "ZZZNtProtectVirtualMemory",
            Addresses {
                edr: nt_protect_virtual_memory as usize,
                ntdll: ntpvm,
            },
        );

        Self { addresses: hm }
    }
}

/// Patches hooks into NTDLL functions to redirect execution to our DLL so we can inspect params.
///
/// This works by doing the following:
///
/// 1) Overwrite a syscall stub we wish to hook with NOPs
/// 2) Replace the starting bytes of that memory with a jmp to our EDR DLL function callback
/// 3) Write the jmp instruction
#[unsafe(no_mangle)]
fn patch_ntdll(addresses: &StubAddresses) {
    // Before we patch NTDLL, we need to initialise the LazyLock, this is a patch following a PR from
    // https://github.com/lzty where the author has created a static containing the SSN's for the hooked
    // syscalls. This led to a bug in that it was trying to read memory after the NTDLL patching by the EDR
    // DLL had taken place, so was reading now invalid memory. If we now try access an SSN, and do a check
    // that it doesn't return None via `unwrap()`, we can ensure the SSN's are properly initialised before the
    // DLL's thread has chance to start overwriting and in some cases nullifying memory.
    SYSCALL_NUMBER.get("ZwOpenProcess").unwrap();

    // Iterate over each item in the BTreeMap, and for each, hook the syscall stub.
    // We use a BTreeMap so we can have a predictive ordering to the order in which
    // we will iterate over them, or more specifically, we can control the last iteration,
    // which should be modifying NtProtectVirtualMemory.
    for (_, item) in &addresses.addresses {
        let buffer: &[u8] = &[
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90,
        ];

        //
        // As we are patching memory - we cannot use WriteProcessMemory which is one of the patched / hooked functions
        // by the EDR. Instead of using the windows API we can just directly use the Rust stdlib to write to the memory
        // address via copy_nonoverlapping.
        //
        // Because we aren't now using WriteProcessMemory, the memory protection needs changing of the .text segments of
        // ntdll to allow us to write to it via the stdlib.
        //

        // first change protection of this region, determined by the size of the nop overwrite
        let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS::default();
        if unsafe {
            VirtualProtect(
                item.ntdll as *const _,
                buffer.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
        }
        .is_err()
        {
            panic!("[-] Failed to change protection. {}", unsafe {
                GetLastError().0
            }) // todo should not panic
        }

        // now we can do the writes etc
        let addr = buffer.as_ptr();
        let len = buffer.len();

        unsafe { std::ptr::copy_nonoverlapping(addr, item.ntdll as *mut _, len) };

        // write movabs rax, _ (thanks to https://defuse.ca/online-x86-assembler.htm#disassembly)
        let mob_abs_rax: [u8; 2] = [0x48, 0xB8];
        unsafe {
            std::ptr::copy_nonoverlapping(
                mob_abs_rax.as_ptr(),
                item.ntdll as *mut _,
                mob_abs_rax.len(),
            )
        };

        //
        // convert the address of the function to little endian (8) bytes and write them at the correct offset
        //
        let mut addr_bytes = [0u8; 8]; // 8 for ptr, 2 for call
        let addr64 = item.edr as u64; // ensure we are 8-byte aligned
        for (i, b) in addr_bytes.iter_mut().enumerate() {
            *b = ((addr64 >> (i * 8)) & 0xFF) as u8;
        }

        // write it
        unsafe {
            std::ptr::copy_nonoverlapping(
                addr_bytes.as_ptr(),
                (item.ntdll + 2) as *mut _,
                addr_bytes.len(),
            )
        };

        let jmp_bytes: &[u8] = &[0xFF, 0xE0];
        unsafe {
            std::ptr::copy_nonoverlapping(
                jmp_bytes.as_ptr(),
                (item.ntdll + 10) as *mut _,
                jmp_bytes.len(),
            )
        };

        // revert the protection
        if unsafe {
            VirtualProtect(
                item.ntdll as *const _,
                buffer.len(),
                old_protect,
                &mut old_protect,
            )
        }
        .is_err()
        {
            panic!("[-] Failed to change protection. {}", unsafe {
                GetLastError().0
            }) // todo should not panic
        }
    }

    // Now the overwrites are done; flush the instruction cache as per remarks at:
    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
    let h_process = unsafe { GetCurrentProcess() };
    if let Err(e) = unsafe { FlushInstructionCache(h_process, None, 0) } {
        panic!("[-] Could not flush instruction cache. {e}"); // todo should not panic
    }
}

/// Automated syscall number repository
pub static SYSCALL_NUMBER: LazyLock<BTreeMap<&'static str, u32>> = LazyLock::new(|| {
    let mut syscall_num_repo = BTreeMap::new();

    static NT_FUNC_NAMES: [&str; 5] = [
        "ZwOpenProcess\0",
        "ZwAllocateVirtualMemory\0",
        "NtWriteVirtualMemory\0",
        "NtProtectVirtualMemory\0",
        "NtCreateThreadEx\0",
    ];

    if let Ok(h_ntdll) = unsafe { GetModuleHandleA(s!("Ntdll.dll")) } {
        for name in NT_FUNC_NAMES {
            if let Some(ntfunc) = unsafe { GetProcAddress(h_ntdll, PCSTR::from_raw(name.as_ptr())) }
            {
                let funcaddr = unsafe { mem::transmute::<_, *const u8>(ntfunc) };

                #[cfg(target_arch = "x86_64")]
                {
                    if unsafe { (funcaddr as *const u32).read_unaligned() } == 0xb8d18b4c {
                        let num = (unsafe { (funcaddr as *const u64).read_unaligned() } >> 32)
                            as u32
                            & 0xfff;

                        // eliminate the last trailing '\0' to make a normal rust str
                        syscall_num_repo.insert(&name[0..name.len() - 1], num);
                    }
                }

                #[cfg(target_arch = "x86")]
                {
                    if unsafe { funcaddr.read_unaligned() } == 0xb8 {
                        let num = unsafe {
                            ((funcaddr as *const u64).add(1) as *const u32).read_unaligned()
                        } & 0xfff;

                        syscall_num_repo.insert(&name[0..name.len() - 1], num);
                    }
                }
            } else {
                println!("[-] Could not find function");
            }
        }
    }

    if syscall_num_repo.len() != NT_FUNC_NAMES.len() {
        println!(
            "[-] Could not resolve all required SSN's. {:?}",
            syscall_num_repo
        );
    }

    syscall_num_repo
});

/// Send an IOCTL to the driver which informs it the process is ready for ghost hunting
fn ioctl_initialised() {
    send_ipc_to_engine(DLLMessage::ProcessReadyForGhostHunting);
}
