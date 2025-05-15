use core::{
    ffi::{CStr, c_void},
    iter::once,
    ptr::null_mut,
    slice::from_raw_parts,
    sync::atomic::Ordering,
};

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use shared_no_std::constants::SanctumVersion;
use wdk::println;
use wdk_sys::{
    ntddk::{
        IoThreadToProcess, KeGetCurrentIrql, RtlInitUnicodeString, RtlUnicodeStringToAnsiString,
        ZwClose, ZwCreateFile, ZwWriteFile,
    }, DRIVER_OBJECT, FALSE, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_OPEN_IF, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT, GENERIC_WRITE, IO_STATUS_BLOCK, LIST_ENTRY, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE, OBJ_KERNEL_HANDLE, PASSIVE_LEVEL, PHANDLE, POBJECT_ATTRIBUTES, PVOID, STATUS_SUCCESS, STRING, ULONG, UNICODE_STRING, _EPROCESS, _KPROCESS, _KTHREAD
};

use crate::{ffi::{InitializeObjectAttributes, PsGetProcessImageFileName}, DRIVER_MESSAGES};

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

pub fn eprocess_to_pid(process: *mut _EPROCESS) -> Result<u64, DriverError> {
    if process.is_null() {
        return Err(DriverError::NullPtr);
    }

    // SAFETY: Null checked 
    // We are using a raw pointer offset here as the Rust wdk doesn't define / export the _EPROCESS / _KPROCESS
    // types.
    // There is **no** guarantee that this will work on any other build than my VM. Perhaps this needs a todo marker to fix at some
    // point?
    let pid_offset = unsafe { (process as *mut *const c_void).add(0x1d0) };

    if pid_offset.is_null() {
        return Err(DriverError::NullPtr);
    }

    let pid = unsafe { *pid_offset } as u64;

    Ok(pid)
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
                    println!("[sanctum] [+] Closed file handle");
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
                    println!("[sanctum] [+] Closed file handle");
                }
            }

            return;
        }

        // close the file handle
        unsafe {
            if !handle.is_null() {
                let _ = ZwClose(handle as *mut _);
                println!("[sanctum] [+] Closed file handle");
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
