use core::{
    arch::asm,
    ffi::{CStr, c_void},
    iter::once,
    ptr::null_mut,
    slice::from_raw_parts,
    sync::atomic::Ordering,
    time::Duration,
};

use alloc::{
    borrow::{Cow, ToOwned},
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use shared_no_std::constants::SanctumVersion;
use wdk::{nt_success, println};
use wdk_sys::{
    _EPROCESS, _KTHREAD, _LARGE_INTEGER,
    _MODE::KernelMode,
    FALSE, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT,
    HANDLE, IO_STATUS_BLOCK, LARGE_INTEGER, LIST_ENTRY, OBJ_CASE_INSENSITIVE, OBJ_KERNEL_HANDLE,
    OBJECT_ATTRIBUTES, PASSIVE_LEVEL, PETHREAD, PHANDLE, PROCESS_ALL_ACCESS, PVOID, PsProcessType,
    PsThreadType, STATUS_SUCCESS, STRING, THREAD_ALL_ACCESS, ULONG, UNICODE_STRING,
    ntddk::{
        IoThreadToProcess, KeGetCurrentIrql, MmGetSystemRoutineAddress, ObOpenObjectByPointer,
        ObReferenceObjectByHandle, ObfDereferenceObject, PsGetProcessId, RtlInitUnicodeString,
        RtlUnicodeStringToAnsiString, ZwClose, ZwCreateFile, ZwWriteFile,
    },
};

use crate::{
    DRIVER_MESSAGES,
    ffi::{
        IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64, InitializeObjectAttributes,
        PsGetProcessImageFileName, ZwGetNextProcess, ZwGetNextThread,
    },
};

#[derive(Debug)]
/// A custom error enum for the Sanctum driver
pub enum DriverError {
    NullPtr,
    DriverMessagePtrNull,
    LengthTooLarge,
    CouldNotDecodeUnicode,
    CouldNotEncodeUnicode,
    CouldNotSerialize,
    NoDataToSend,
    ModuleNotFound,
    FunctionNotFoundInModule,
    ImageSizeNotFound,
    ResourceStateInvalid,
    MutexError,
    ProcessNotFound,
    UnexpectedSignature(String),
    Unknown(String),
}

#[repr(C)]
struct KLDR_DATA_TABLE_ENTRY {
    InLoadOrderLinks: LIST_ENTRY,
    ExceptionTable: PVOID,
    ExceptionTableSize: ULONG,
    GpValue: PVOID,
    NonPagedDebugInfo: *const c_void,
    DllBase: PVOID,
    EntryPoint: PVOID,
    SizeOfImage: usize,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
}

pub struct ModuleImageBaseInfo {
    pub base_address: *const c_void,
    pub size_of_image: usize,
}

unsafe extern "C" {
    static PsLoadedModuleList: LIST_ENTRY;
}

#[repr(C)]
struct LdrDataTableEntry {
    InLoadOrderLinks: LIST_ENTRY,           // 0x00
    InMemoryOrderLinks: LIST_ENTRY,         // 0x10
    InInitializationOrderLinks: LIST_ENTRY, // 0x20
    DllBase: *const c_void,                 // 0x30
    EntryPoint: *const c_void,              // 0x38
    SizeOfImage: u32,                       // 0x40
    _padding: u32,                          // 0x44
    FullDllName: UNICODE_STRING,            // 0x48
    BaseDllName: UNICODE_STRING,            // 0x58
}

/// Gets the base address and module size of a module in the kernel by traversing the InLoadOrderLinks struct of the `DRIVER_OBJECT`.
///
/// # Returns
/// - `ok` - The function will return `Ok` with a [`ModuleImageBaseInfo`].
/// - `err` - Returns DriverError.
#[inline(always)]
pub fn get_module_base_and_sz(needle: &str) -> Result<ModuleImageBaseInfo, DriverError> {
    let head = unsafe { &PsLoadedModuleList as *const LIST_ENTRY };

    let mut link = unsafe { (*head).Flink };

    while link != head as *mut LIST_ENTRY {
        let entry = link as *mut LdrDataTableEntry;

        let unicode = unsafe { &(*entry).BaseDllName };
        let len = (unicode.Length / 2) as usize;
        let buf = unicode.Buffer;
        if !buf.is_null() && len > 0 && len < 256 {
            let slice = unsafe { from_raw_parts(buf, len) };
            let name = String::from_utf16_lossy(slice);

            if name.eq_ignore_ascii_case(needle) {
                let base = unsafe { (*entry).DllBase };
                let size = unsafe { (*entry).SizeOfImage } as usize;
                return Ok(ModuleImageBaseInfo {
                    base_address: base,
                    size_of_image: size,
                });
            }
        }

        // Move to the next entry
        link = unsafe { (*entry).InLoadOrderLinks.Flink };
    }

    Err(DriverError::ModuleNotFound)
}

/// Scan a loaded module for a particular sequence of bytes, this will most commonly be used to resolve a pointer to
/// an unexported function we wish to use.
///
/// # Args
/// - `image_base`: The base address of the image you wish to search
/// - `image_size`: The total size of the image to search
/// - `pattern`: A byte slice containing the bytes you wish to search for
///
/// # Returns
/// - `ok`: The address of the start of the pattern match
/// - `err`: A [`DriverError`]
pub fn scan_module_for_byte_pattern(
    image_base: *const c_void,
    image_size: usize,
    pattern: &[u8],
) -> Result<*const c_void, DriverError> {
    // Convert the raw address pointer to a byte pointer so we can read individual bytes
    let image_base = image_base as *const u8;
    let mut cursor = image_base as *const u8;
    // End of image denotes the end of our reads, if nothing is found by that point we have not found the
    // sequence of bytes
    let end_of_image = unsafe { image_base.add(image_size) };

    while cursor != end_of_image {
        unsafe {
            let bytes = from_raw_parts(cursor, pattern.len());

            if bytes == pattern {
                return Ok(cursor as *const _);
            }

            cursor = cursor.add(1);
        }
    }

    Err(DriverError::FunctionNotFoundInModule)
}

/// Creates a Windows API compatible unicode string from a u16 slice.
///
///
/// <h1>Returns</h1>
/// Returns an option UNICODE_STRING, if the len of the input string is 0 then
/// the function will return None.
pub fn create_unicode_string(s: &Vec<u16>) -> Option<UNICODE_STRING> {
    //
    // Check the length of the input string is greater than 0, if it isn't,
    // we will return none
    //
    let len = if s.len() > 0 {
        s.len()
    } else {
        return None;
    };

    //
    // Windows docs specifies for UNICODE_STRING:
    //
    // param 1 - length, Specifies the length, in bytes, of the string pointed to by the Buffer member,
    // not including the terminating NULL character, if any.
    //
    // param 2 - max len, Specifies the total size, in bytes, of memory allocated for Buffer. Up to
    // MaximumLength bytes may be written into the buffer without trampling memory.
    //
    // param 3 - buffer, Pointer to a wide-character string
    //
    // Therefore, we will do the below check to remove the null terminator from the len

    let len_checked = if len > 0 && s[len - 1] == 0 {
        len - 1
    } else {
        len
    };

    Some(UNICODE_STRING {
        Length: (len_checked * 2) as u16,
        MaximumLength: (len * 2) as u16,
        Buffer: s.as_ptr() as *mut u16,
    })
}

/// Checks the compatibility of the driver and client versions based on major.minor.patch fields.
///
/// # Returns
///
/// True if compatible, false otherwise.
pub fn check_driver_version(client_version: &SanctumVersion) -> bool {
    // only compatible with versions less than 1
    if client_version.major >= 1 {
        return false;
    }

    true
}

/// Converts a UNICODE_STRING into a `String` (lossy) for printing.
///
/// # Errors
/// - `DriverError::NullPtr` if the input is null.
/// - `DriverError::LengthTooLarge` if the input exceeds `MAX_LEN`.
/// - `DriverError::Unknown` if the conversion fails.
pub fn unicode_to_string(input: *const UNICODE_STRING) -> Result<String, DriverError> {
    if input.is_null() {
        println!("[sanctum] [-] Null pointer passed to unicode_to_string.");
        return Err(DriverError::NullPtr);
    }

    let unicode = unsafe { &*input };

    // Allocate a heap buffer for the ANSI string with a size based on `unicode.Length`.
    let mut buf: Vec<i8> = vec![0; (unicode.Length + 1) as usize];
    let mut ansi = STRING {
        Length: 0,
        MaximumLength: (buf.len() + 1) as u16,
        Buffer: buf.as_mut_ptr(),
    };

    // convert the UNICODE_STRING to an ANSI string.
    let status = unsafe { RtlUnicodeStringToAnsiString(&mut ansi, unicode, FALSE as u8) };
    if status != STATUS_SUCCESS {
        println!("[sanctum] [-] RtlUnicodeStringToAnsiString failed with status {status}.");
        return Err(DriverError::Unknown(format!(
            "Conversion failed with status code: {status}"
        )));
    }

    // create the String
    let slice =
        unsafe { core::slice::from_raw_parts(ansi.Buffer as *const u8, ansi.Length as usize) };
    Ok(String::from_utf8_lossy(slice).to_string())
}

pub fn thread_to_process_name<'a>(thread: *mut _KTHREAD) -> Result<&'a str, DriverError> {
    let process = unsafe { IoThreadToProcess(thread as *mut _) };

    if process.is_null() {
        println!("[sanctum] [-] PEPROCESS was null.");
        return Err(DriverError::NullPtr);
    }

    eprocess_to_process_name(process as *mut _)
}

pub fn eprocess_to_process_name<'a>(process: *mut _EPROCESS) -> Result<&'a str, DriverError> {
    let name_ptr = unsafe { PsGetProcessImageFileName(process as *mut _) };

    if name_ptr.is_null() {
        println!("[sanctum] [-] Name ptr was null");
    }

    let name = match unsafe { CStr::from_ptr(name_ptr as *const i8) }.to_str() {
        Ok(name_str) => name_str,
        Err(e) => {
            println!("[sanctum] [-] Could not get the process name as a str. {e}");
            return Err(DriverError::ModuleNotFound);
        }
    };

    Ok(name)
}

/// The interface for message logging. This includes both logging to a file in \SystemRoot\ and an interface
/// for logging to userland (for example, in the event where the system log fails, the userland logger may want to
/// log that event fail)
pub struct Log<'a> {
    log_path: &'a str,
}

pub enum LogLevel {
    Info,
    Warning,
    Success,
    Error,
}

impl<'a> Log<'a> {
    pub fn new() -> Self {
        Log {
            log_path: r"\SystemRoot\sanctum_driver.log",
        }
    }

    /// Log kernel events / debug messages directly to the sanctum_driver.log file in
    /// \SystemRoot\sanctum\. This will not send any log messages to userland, other than when an error
    /// occurs writing to sanctum_driver.log
    ///
    /// # Args
    /// - level: LogLevel - the level of logging required for the event
    /// - msg: &str - a formatted str to be logged
    pub fn log(&self, level: LogLevel, msg: &str) {
        //
        // Cast the log path as a Unicode string.
        // TODO: Move this to the constructor if InitializeObjectAttributes
        // doesn't modify the string. Consider RefCell for interior mutability.
        //
        let mut log_path_unicode = UNICODE_STRING::default();
        let src = self
            .log_path
            .encode_utf16()
            .chain(once(0))
            .collect::<Vec<_>>();
        unsafe { RtlInitUnicodeString(&mut log_path_unicode, src.as_ptr()) };

        //
        // Initialise OBJECT_ATTRIBUTES
        //
        let mut oa: OBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES::default();
        let result = unsafe {
            InitializeObjectAttributes(
                &mut oa,
                &mut log_path_unicode,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                null_mut(),
                null_mut(),
            )
        };
        if result.is_err() {
            println!(
                "[sanctum] [-] Error calling InitializeObjectAttributes. No log event taking place.."
            );
            self.log_to_userland(
                "[-] Error calling InitializeObjectAttributes. No log event taking place.."
                    .to_string(),
            );
            return;
        }

        //
        // Do not perform file operations at higher IRQL levels
        //
        unsafe {
            if KeGetCurrentIrql() as u32 != PASSIVE_LEVEL {
                println!("[sanctum] [-] IRQL level too high to log event.");
                self.log_to_userland("[-] IRQL level too high to log event.".to_string());
                return;
            }
        }

        //
        // Create the driver log file if it doesn't already exist
        //
        let mut handle: PHANDLE = null_mut();
        let mut io_status_block = IO_STATUS_BLOCK::default();

        let result = unsafe {
            ZwCreateFile(
                &mut handle as *mut _ as *mut _,
                FILE_APPEND_DATA,
                &mut oa,
                &mut io_status_block,
                null_mut(),
                FILE_ATTRIBUTE_NORMAL,
                0,
                FILE_OPEN_IF,
                FILE_SYNCHRONOUS_IO_NONALERT,
                null_mut(),
                0,
            )
        };

        if result != STATUS_SUCCESS || handle.is_null() {
            println!(
                "[sanctum] [-] Result of ZwCreateFile was not success - result: {result}. Returning."
            );
            self.log_to_userland(format!(
                "Result of ZwCreateFile was not success - result: {result}. Returning."
            ));
            unsafe {
                if !handle.is_null() {
                    let _ = ZwClose(*handle);
                }
            }
            return;
        }

        //
        // Write data to the file
        //

        // convert the input message to a vector we can pass into the write file
        // heap allocating as the ZwWriteFile requires us to have a mutable pointer, so we
        // cannot use a &str.as_mut_ptr()
        let buf: Vec<u8> = msg
            .as_bytes()
            .iter()
            .chain("\r\n".as_bytes().iter())
            .cloned()
            .collect();

        let result = unsafe {
            ZwWriteFile(
                handle as *mut _ as *mut _,
                null_mut(),
                None,
                null_mut(),
                &mut io_status_block,
                buf.as_ptr() as *mut _,
                buf.len() as u32,
                null_mut(), // should be ignored due to flag FILE_APPEND_DATA
                null_mut(),
            )
        };

        if result != STATUS_SUCCESS {
            println!("[sanctum] [-] Failed writing file. Code: {result}");
            self.log_to_userland(format!(" [-] Failed writing file. Code: {result}"));
            unsafe {
                if !handle.is_null() {
                    let _ = ZwClose(*handle);
                }
            }

            return;
        }

        // close the file handle
        unsafe {
            if !handle.is_null() {
                let _ = ZwClose(handle as *mut _);
            }
        }
    }

    /// Send a message to userland from the kernel, via the DriverMessages feature
    pub fn log_to_userland(&self, msg: String) {
        if !DRIVER_MESSAGES.load(Ordering::SeqCst).is_null() {
            let obj = unsafe { &mut *DRIVER_MESSAGES.load(Ordering::SeqCst) };
            obj.add_message_to_queue(msg);
        } else {
            println!(
                "[sanctum] [-] Unable to log message for the attention of userland, {}. The global DRIVER_MESSAGES was null.",
                msg
            );
        }
    }
}

/// Converts a valid HANDLE to a process ID
pub fn handle_to_pid(handle: HANDLE) -> u32 {
    let mut ob: *mut c_void = null_mut();
    _ = unsafe {
        ObReferenceObjectByHandle(
            handle,
            PROCESS_ALL_ACCESS,
            *PsProcessType,
            KernelMode as _,
            &mut ob,
            null_mut(),
        )
    };

    let pid = unsafe { PsGetProcessId(ob as *mut _) } as u32;
    unsafe {
        ObfDereferenceObject(ob);
    }

    pid
}

/// Returns up to 15 characters of the process name of the **current thread**. Note, the returned process
/// name is case **insensitive**.
pub fn get_process_name() -> String {
    let mut pkthread: *mut c_void = null_mut();

    unsafe {
        asm!(
            "mov {}, gs:[0x188]",
            out(reg) pkthread,
        )
    };
    let p_eprocess = unsafe { IoThreadToProcess(pkthread as PETHREAD) } as *mut c_void;

    let mut img = unsafe { PsGetProcessImageFileName(p_eprocess) } as *const u8;
    let mut current_process_thread_name = String::new();
    let mut counter: usize = 0;
    while unsafe { core::ptr::read_unaligned(img) } != 0 || counter < 15 {
        current_process_thread_name.push(unsafe { *img } as char);
        img = unsafe { img.add(1) };
        counter += 1;
    }

    current_process_thread_name
}

/// Scan a module by its in memory base address for function offsets. The target param should NOT be null
/// terminated.
///
/// # Safety
/// The caller is responsible for ensuring the `base` address points to valid expected memory (base address of the loaded
/// module).
pub unsafe fn scan_usermode_module_for_function_address(
    base: *const c_void,
    target: &str,
) -> Result<*const c_void, DriverError> {
    // The memory should always be valid.. but.. Cannot use ProbeForRead as we don't
    // have access to __try :( this is as close as I can get right now I think
    if base.is_null() {
        println!("[sanctum [-] Address not valid.");
        return Err(DriverError::NullPtr);
    }

    let dos = unsafe { &*(base as *const IMAGE_DOS_HEADER) };
    if dos.e_magic != 0x5A4D {
        return Err(DriverError::UnexpectedSignature("DOS Header".into()));
    }

    let nth = unsafe { &*(base.add(dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64) };
    if nth.Signature != 0x00004550 {
        return Err(DriverError::UnexpectedSignature("NT Signarue".into()));
    }
    if nth.OptionalHeader.Magic != 0x20B {
        return Err(DriverError::UnexpectedSignature("NT Magic".into()));
    }

    unsafe {
        const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
        let dir = &nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if dir.VirtualAddress == 0 || dir.Size < size_of::<IMAGE_EXPORT_DIRECTORY>() as u32 {
            return Err(DriverError::Unknown("Invalid length".into()));
        }
        let exp = &*(rva(base as *const _, dir.VirtualAddress) as *const IMAGE_EXPORT_DIRECTORY);

        let names = rva(base as *const _, exp.AddressOfNames) as *const u32;
        let ords = rva(base as *const _, exp.AddressOfNameOrdinals) as *const u16;
        let funcs = rva(base as *const _, exp.AddressOfFunctions) as *const u32;

        for i in 0..exp.NumberOfNames {
            let name_ptr = rva(base as *const _, *names.add(i as usize));
            // compare ascii of the function name
            let mut p = name_ptr;
            let mut ok = true;
            for b in target.as_bytes() {
                if *p != *b {
                    ok = false;
                    break;
                }
                p = p.add(1);
            }
            if ok && *p == 0 {
                let ord = *ords.add(i as usize) as usize;
                let rva_fn = *funcs.add(ord) as usize;
                let fn_ptr = (base as *const u8).add(rva_fn) as *const u8;
                let fn_rva = rva_fn as u32;
                if fn_rva >= dir.VirtualAddress && fn_rva < dir.VirtualAddress + dir.Size {
                    continue;
                }
                return Ok(fn_ptr as *const c_void);
            }
        }

        return Err(DriverError::FunctionNotFoundInModule);
    }
}

#[inline(always)]
unsafe fn rva<'a>(base: *const u8, off: u32) -> *const u8 {
    unsafe { base.add(off as usize) }
}

#[inline(always)]
pub fn duration_to_large_int(dur: Duration) -> _LARGE_INTEGER {
    LARGE_INTEGER {
        QuadPart: -((dur.as_nanos() / 100) as i64),
    }
}

/// Iterator over all active processes in the system
#[derive(Default)]
pub struct ProcessIterator {
    current: HANDLE,
    handles: Vec<HANDLE>,
}

impl ProcessIterator {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Iterator for ProcessIterator {
    type Item = HANDLE;

    fn next(&mut self) -> Option<Self::Item> {
        let mut next_proc: HANDLE = null_mut();

        let result = unsafe {
            ZwGetNextProcess(
                self.current,
                PROCESS_ALL_ACCESS,
                OBJ_KERNEL_HANDLE,
                0,
                &mut next_proc,
            )
        };

        if result != 0 || self.current == next_proc {
            return None;
        }

        self.current = next_proc;
        self.handles.push(self.current);
        Some(self.current)
    }
}

impl Drop for ProcessIterator {
    fn drop(&mut self) {
        for handle in &self.handles {
            let _ = unsafe { ZwClose(*handle) };
        }
    }
}

/// Iterator over all threads in a specific process
#[derive(Default)]
pub struct ThreadIterator {
    process: HANDLE,
    current: HANDLE,
    handles: Vec<HANDLE>,
}

impl ThreadIterator {
    pub fn new(process: HANDLE) -> Self {
        Self {
            process: process,
            current: null_mut(),
            handles: Vec::new(),
        }
    }
}

impl Iterator for ThreadIterator {
    // Opaque pointer for an ETHREAD which is not defined :(
    type Item = *mut c_void;

    fn next(&mut self) -> Option<Self::Item> {
        let mut next_thread: HANDLE = null_mut();

        let result = unsafe {
            ZwGetNextThread(
                self.process,
                self.current,
                THREAD_ALL_ACCESS,
                OBJ_KERNEL_HANDLE,
                0,
                &mut next_thread,
            )
        };

        if result != 0 || self.current == next_thread {
            return None;
        }

        self.current = next_thread;
        self.handles.push(self.current);

        let mut pe_thread = null_mut();
        let status = unsafe {
            ObReferenceObjectByHandle(
                self.current,
                THREAD_ALL_ACCESS,
                *PsThreadType,
                KernelMode as _,
                &mut pe_thread,
                null_mut(),
            )
        };

        if status == 0 && !pe_thread.is_null() {
            return Some(pe_thread);
        } else {
            None
        }
    }
}

impl Drop for ThreadIterator {
    fn drop(&mut self) {
        for handle in &self.handles {
            let _ = unsafe { ZwClose(*handle) };
        }
    }
}

/// Iterator that yields all threads across all processes
#[derive(Default)]
pub struct AllThreadsIterator {
    process_iter: ProcessIterator,
    current_thread_iter: Option<ThreadIterator>,
}

impl AllThreadsIterator {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Iterator for AllThreadsIterator {
    type Item = *mut c_void; // ETHREAD

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Try the current process
            if let Some(ref mut thread_iter) = self.current_thread_iter {
                if let Some(thread) = thread_iter.next() {
                    return Some(thread);
                }
            }

            // Try get a next process
            match self.process_iter.next() {
                Some(p) => {
                    self.current_thread_iter = Some(ThreadIterator::new(p));
                }
                None => return None,
            }
        }
    }
}

pub fn lookup_fn_ptr(fn_name: &str) -> Option<usize> {
    let mut function_name_unicode = UNICODE_STRING::default();
    let string_wide: Vec<u16> = fn_name.encode_utf16().collect();

    unsafe {
        RtlInitUnicodeString(&mut function_name_unicode, string_wide.as_ptr());
    }

    let function_address =
        unsafe { MmGetSystemRoutineAddress(&mut function_name_unicode) } as usize;

    if function_address == 0 {
        None
    } else {
        Some(function_address)
    }
}

pub fn ethread_to_handle(pe_thread: *mut c_void) -> Option<HANDLE> {
    let mut h_thread = null_mut();

    let status = unsafe {
        ObOpenObjectByPointer(
            pe_thread,
            OBJ_KERNEL_HANDLE,
            null_mut(),
            THREAD_ALL_ACCESS,
            *PsThreadType,
            KernelMode as _,
            &mut h_thread,
        )
    };

    if !nt_success(status) {
        println!("[sanctum] [-] Failed to open thread. Status: {status:#X}");
        return None;
    }

    Some(h_thread)
}
