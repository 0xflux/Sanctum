use core::{ffi::c_void, mem, ptr::null_mut, slice::from_raw_parts, sync::atomic::Ordering};

use crate::{
    DRIVER_MESSAGES, DRIVER_MESSAGES_CACHE,
    core::process_monitor::ProcessMonitor,
    utils::{DriverError, Log, check_driver_version},
};
use alloc::{format, string::String};
use shared_no_std::{
    constants::SanctumVersion,
    driver_ipc::{HandleObtained, ImageLoadQueues, ProcessStarted, ProcessTerminated},
    ghost_hunting::{DLLMessage, Syscall},
    ioctl::{DriverMessages, SancIoctlPing},
};
use wdk::println;
use wdk_mutex::{
    fast_mutex::{FastMutex, FastMutexGuard},
    grt::Grt,
};
use wdk_sys::{
    _IO_STACK_LOCATION, APC_LEVEL, NTSTATUS, PIRP, STATUS_BUFFER_ALL_ZEROS,
    STATUS_INVALID_BUFFER_SIZE, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
    ntddk::{KeGetCurrentIrql, RtlCopyMemoryNonTemporal},
};

/// DriverMessagesWithMutex object which contains a spinlock to allow for mutable access to the queue.
/// This object should be used to safely manage access to the inner DriverMessages which contains
/// the actual data. The DriverMessagesWithMutex contains metadata + the DriverMessages.
pub struct DriverMessagesWithMutex {
    data: FastMutex<DriverMessages>,
}

impl Default for DriverMessagesWithMutex {
    fn default() -> Self {
        let data = FastMutex::new(DriverMessages::default()).unwrap();

        {
            let mut lock = data.lock().unwrap();
            lock.is_empty = true;
        }

        DriverMessagesWithMutex { data }
    }
}

impl DriverMessagesWithMutex {
    pub fn new() -> Self {
        DriverMessagesWithMutex::default()
    }

    /// Adds a print msg to the queue.
    ///
    /// This function will wait for an acquisition of the spin lock to continue and will block
    /// until that point.
    pub fn add_message_to_queue(&mut self, data: String) {
        if data.is_empty() {
            return;
        }

        let irql = unsafe { KeGetCurrentIrql() };
        if irql > APC_LEVEL as u8 {
            println!("[sanctum] [-] IRQL is above APC_LEVEL: {}", irql);
            return;
        }

        {
            let mut lock = self.data.lock().unwrap();
            lock.is_empty = false;
            lock.messages.push(data);
        }
    }

    /// Adds serialised data to the message queue.
    ///
    /// This function will wait for an acquisition of the spin lock to continue and will block
    /// until that point.
    pub fn add_process_creation_to_queue(&mut self, data: ProcessStarted) {
        let irql = unsafe { KeGetCurrentIrql() };
        if irql > APC_LEVEL as u8 {
            println!("[sanctum] [-] IRQL is above APC_LEVEL: {}", irql);
            return;
        }

        {
            let mut lock = self.data.lock().unwrap();
            lock.is_empty = false;
            lock.process_creations.push(data);
        }
    }

    /// Adds a terminated process to the queue.
    ///
    /// This function will wait for an acquisition of the spin lock to continue and will block
    /// until that point.
    pub fn add_process_termination_to_queue(&mut self, data: ProcessTerminated) {
        let irql = unsafe { KeGetCurrentIrql() };
        if irql > APC_LEVEL as u8 {
            println!("[sanctum] [-] IRQL is above APC_LEVEL: {}", irql);
            return;
        }

        {
            let mut lock = self.data.lock().unwrap();
            lock.is_empty = false;
            lock.process_terminations.push(data);
        }
    }

    /// Add new granted handle information to the messages object
    pub fn add_process_handle_to_queue(&mut self, data: HandleObtained) {
        let irql = unsafe { KeGetCurrentIrql() };
        if irql > APC_LEVEL as u8 {
            println!("[sanctum] [-] IRQL is above APC_LEVEL: {}", irql);
            return;
        }

        {
            let mut lock = self.data.lock().unwrap();
            lock.is_empty = false;
            lock.handles.push(data);
        }
    }

    /// Extract all data out of the queue if there is data.
    ///
    /// # Returns
    ///
    /// The function will return None if the queue was empty.
    fn extract_all(&mut self) -> Option<DriverMessages> {
        let irql = unsafe { KeGetCurrentIrql() };
        if irql > APC_LEVEL as u8 {
            println!("[sanctum] [-] IRQL is above APC_LEVEL: {}", irql);
            return None;
        }

        {
            let mut lock = self.data.lock().unwrap();
            if lock.is_empty {
                return None;
            }

            //
            // Using mem::take now seems safe against kernel panics; we were having some issues
            // previous with this, leading to IRQL_NOT_LESS_OR_EQUAL bsod. That was likely a programming
            // error as opposed to a safety error with mem::take. If further bsod's occur around mem::take,
            // try swapping to mem::swap; however, the core functionality of both should be the same.
            //
            let extracted_data = mem::take(&mut *lock);

            lock.is_empty = true; // reset flag
            return Some(extracted_data);
        }
    }

    fn add_existing_queue(&mut self, q: &mut DriverMessages) -> usize {
        let mut lock = self.data.lock().unwrap();

        lock.is_empty = false;
        lock.messages.append(&mut q.messages);
        lock.process_creations.append(&mut q.process_creations);
        lock.process_terminations
            .append(&mut q.process_terminations);
        lock.handles.append(&mut q.handles);

        // IMPORTANT NOTE: As well as adding a new field to the below (compile time checked) you ALSO must
        // add the field to the above append instructions.
        let tmp = serde_json::to_vec(&DriverMessages {
            messages: lock.messages.clone(),
            process_creations: lock.process_creations.clone(),
            process_terminations: lock.process_terminations.clone(),
            handles: lock.handles.clone(),
            is_empty: false,
        });

        let len = match tmp {
            Ok(v) => v.len(),
            Err(e) => {
                println!("[sanctum] [-] Error serializing temp object for len. {e}.");
                return 0;
            }
        };

        len
    }
}

pub struct IoctlBuffer {
    pub len: u32,
    pub buf: *mut c_void,
    pub p_stack_location: *mut _IO_STACK_LOCATION,
    pub pirp: PIRP,
}

impl IoctlBuffer {
    /// Creates a new instance of the IOCTL buffer type
    pub fn new(p_stack_location: *mut _IO_STACK_LOCATION, pirp: PIRP) -> Self {
        IoctlBuffer {
            len: 0,
            buf: null_mut(),
            p_stack_location,
            pirp,
        }
    }

    /// Converts the input buffer from the IO Manager into a valid utf8 string.
    fn get_buf_to_str(&mut self) -> Result<&str, NTSTATUS> {
        // first initialise the fields with buf and len
        self.receive()?;

        // construct the message from the pointer (ascii &[u8])
        let input_buffer =
            unsafe { core::slice::from_raw_parts(self.buf as *const u8, self.len as usize) };
        if input_buffer.is_empty() {
            println!("[sanctum] [-] Error reading string passed to PING IOCTL");
            return Err(STATUS_UNSUCCESSFUL);
        }

        let input_buffer = core::str::from_utf8(input_buffer).unwrap();

        // this does not result in a dangling reference as we are referring to memory owned by Self, we are returning
        // a slice of that memory.
        Ok(input_buffer)
    }

    /// Receives raw data from the IO Manager and checks the validity of the data. If the data was valid, it will set the member
    /// fields for the length, buffer, and raw pointers to the required structs.
    ///
    /// If you want to get a string out of an ioctl buffer, it would be better to call get_buf_to_str.
    ///
    /// # Returns
    ///
    /// Success: a IoctlBuffer which will hold the length and a pointer to the buffer
    ///
    /// Error: NTSTATUS
    pub fn receive(&mut self) -> Result<(), NTSTATUS> {
        // length of in buffer
        let input_len: u32 = unsafe {
            (*self.p_stack_location)
                .Parameters
                .DeviceIoControl
                .InputBufferLength
        };
        // if input_len == 0 {
        //     println!("[sanctum] [-] IOCTL PING input length invalid.");
        //     return Err(STATUS_BUFFER_TOO_SMALL)
        // };

        // For METHOD_BUFFERED, the driver should use the buffer pointed to by Irp->AssociatedIrp.SystemBuffer as the output buffer.
        let input_buffer: *mut c_void = unsafe { (*self.pirp).AssociatedIrp.SystemBuffer };
        if input_buffer.is_null() {
            println!("[sanctum] [-] Input buffer is null.");
            return Err(STATUS_BUFFER_ALL_ZEROS);
        };

        // validate the pointer
        if input_buffer.is_null() {
            println!("[sanctum] [-] IOCTL input buffer was null.");
            return Err(STATUS_UNSUCCESSFUL);
        }

        self.len = input_len;
        self.buf = input_buffer;

        Ok(())
    }

    /// Sends a str slice &[u8] back to the userland application taking in a &str and making
    /// the necessary conversions.
    ///
    /// # Returns
    ///
    /// Success: ()
    ///
    /// Error: NTSTATUS
    fn send_str(&self, input_str: &str) -> Result<(), NTSTATUS> {
        // handled the request successfully
        unsafe { (*self.pirp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS };

        // response back to userland
        let response = input_str.as_bytes();
        let response_len = response.len();
        unsafe { (*self.pirp).IoStatus.Information = response_len as u64 };

        println!(
            "[sanctum] [i] Sending back to userland {:?}",
            core::str::from_utf8(response).unwrap()
        );

        // Copy the data now into the buffer to send back to usermode.
        // The driver should not write directly to the buffer pointed to by Irp->UserBuffer.
        unsafe {
            if !(*self.pirp).AssociatedIrp.SystemBuffer.is_null() {
                RtlCopyMemoryNonTemporal(
                    (*self.pirp).AssociatedIrp.SystemBuffer as *mut c_void,
                    response as *const _ as *mut c_void,
                    response_len as u64,
                );
            } else {
                println!("[sanctum] [-] Error handling IOCTL PING, SystemBuffer was null.");
                return Err(STATUS_UNSUCCESSFUL);
            }
        }

        Ok(())
    }
}

/// Simple IOCTL test ping from usermode
pub fn ioctl_handler_ping(
    p_stack_location: *mut _IO_STACK_LOCATION,
    pirp: PIRP,
) -> Result<(), NTSTATUS> {
    let mut ioctl_buffer = IoctlBuffer::new(p_stack_location, pirp);
    // ioctl_buffer.receive()?;

    let input_buffer = ioctl_buffer.get_buf_to_str()?;
    println!("[sanctum] [+] Input buffer: {:?}", input_buffer);

    // send a str response back to userland
    ioctl_buffer.send_str("Msg received!")?;

    Ok(())
}

/// Get the response size of the message we need to send back to the usermode application.
/// This function will also shift the kernel message queue into a temp (global) object which will
/// retain the size, resetting the live queue.
pub fn ioctl_handler_get_kernel_msg_len(pirp: PIRP) -> Result<(), DriverError> {
    unsafe {
        if (*pirp).AssociatedIrp.SystemBuffer.is_null() {
            println!("[sanctum] [-] SystemBuffer is a null pointer.");
            return Err(DriverError::NullPtr);
        }
    }

    let len_of_response = if !DRIVER_MESSAGES.load(Ordering::SeqCst).is_null() {
        let driver_messages = unsafe { &mut *DRIVER_MESSAGES.load(Ordering::SeqCst) };

        let local_drained_driver_messages = driver_messages.extract_all();
        if local_drained_driver_messages.is_none() {
            return Err(DriverError::NoDataToSend);
        }

        //
        // At this point, the transferred data form the queue has data in. Now try obtain a valid reference to
        // the driver message cache global
        //

        if !DRIVER_MESSAGES_CACHE.load(Ordering::SeqCst).is_null() {
            let driver_message_cache =
                unsafe { &mut *DRIVER_MESSAGES_CACHE.load(Ordering::SeqCst) };

            // add the drained data from the live driver messages to the cache, and return the size of the data
            let size_of_serialised_cache: usize = driver_message_cache
                .add_existing_queue(&mut local_drained_driver_messages.unwrap());

            size_of_serialised_cache
        } else {
            println!("[sanctum] [-] Driver messages is null");
            return Err(DriverError::DriverMessagePtrNull);
        }
    } else {
        println!("[sanctum] [-] Invalid pointer");
        return Err(DriverError::DriverMessagePtrNull);
    };

    if len_of_response == 0 {
        return Err(DriverError::NoDataToSend);
    }

    unsafe { (*pirp).IoStatus.Information = mem::size_of::<usize>() as u64 };

    // copy the memory into the buffer
    unsafe {
        RtlCopyMemoryNonTemporal(
            (*pirp).AssociatedIrp.SystemBuffer,
            &len_of_response as *const _ as *const _,
            mem::size_of::<usize>() as u64,
        )
    };

    Ok(())
}

/// Send any kernel messages in the DriverMessages struct back to userland.
pub fn ioctl_handler_send_kernel_msgs_to_userland(pirp: PIRP) -> Result<(), DriverError> {
    unsafe {
        if (*pirp).AssociatedIrp.SystemBuffer.is_null() {
            println!("[sanctum] [-] SystemBuffer is a null pointer.");
            return Err(DriverError::NullPtr);
        }
    }

    // Attempt to dereference the DRIVER_MESSAGES global; if the dereference is successful,
    // make a call to extract_all to get all data from the message queue.
    let data = if !DRIVER_MESSAGES_CACHE.load(Ordering::SeqCst).is_null() {
        let obj = unsafe { &mut *DRIVER_MESSAGES_CACHE.load(Ordering::SeqCst) };
        obj.extract_all()
    } else {
        println!("[sanctum] [-] Invalid pointer");
        return Err(DriverError::DriverMessagePtrNull);
    };

    if data.is_none() {
        return Err(DriverError::NoDataToSend);
    }

    let encoded_data = match serde_json::to_vec(&data.unwrap()) {
        Ok(v) => v,
        Err(_) => {
            println!(
                "[sanctum] [-] Error serializing data to string in ioctl_handler_send_kernel_msgs_to_userland"
            );
            return Err(DriverError::CouldNotSerialize);
        }
    };

    let size_of_struct = encoded_data.len() as u64;
    unsafe { (*pirp).IoStatus.Information = size_of_struct };

    // copy the memory into the buffer
    unsafe {
        RtlCopyMemoryNonTemporal(
            (*pirp).AssociatedIrp.SystemBuffer,
            encoded_data.as_ptr() as *const _,
            size_of_struct,
        )
    };

    Ok(())
}

pub fn ioctl_handler_ping_return_struct(
    p_stack_location: *mut _IO_STACK_LOCATION,
    pirp: PIRP,
) -> Result<(), NTSTATUS> {
    let mut ioctl_buffer = IoctlBuffer::new(p_stack_location, pirp);
    ioctl_buffer.receive()?; // receive the data

    let input_data = ioctl_buffer.buf as *mut c_void as *mut SancIoctlPing;
    if input_data.is_null() {
        println!("[sanctum] [-] Input struct data in IOCTL PING with struct was null.");
        return Err(STATUS_INVALID_BUFFER_SIZE);
    }

    let input_data = unsafe { &(*input_data) };

    // construct the input str from the array
    let input_str = unsafe {
        core::slice::from_raw_parts(input_data.version.as_ptr() as *const u8, input_data.str_len)
    };
    let input_str = match core::str::from_utf8(input_str) {
        Ok(v) => v,
        Err(e) => {
            println!("[sanctum] [-] Error converting input slice to string. {e}");
            return Err(STATUS_UNSUCCESSFUL);
        }
    };

    println!(
        "[sanctum] [+] Input bool: {}, input str: {:#?}",
        input_data.received, input_str
    );

    // setup output
    let msg = b"Msg received from the Kernel!";
    let mut out_buf = SancIoctlPing::new();

    if msg.len() > out_buf.capacity {
        println!("[sanctum] [-] Message too large to send back to usermode.");
        return Err(STATUS_UNSUCCESSFUL);
    }

    out_buf.received = true;
    out_buf.version[..msg.len()].copy_from_slice(msg);
    out_buf.str_len = msg.len();

    unsafe {
        if (*pirp).AssociatedIrp.SystemBuffer.is_null() {
            println!("[sanctum] [-] SystemBuffer is a null pointer.");
            return Err(STATUS_UNSUCCESSFUL);
        }
    }
    let size_of_struct = core::mem::size_of_val(&out_buf) as u64;
    unsafe { (*pirp).IoStatus.Information = size_of_struct };

    unsafe {
        RtlCopyMemoryNonTemporal(
            (*pirp).AssociatedIrp.SystemBuffer,
            &out_buf as *const _ as *const c_void,
            size_of_struct,
        )
    };

    Ok(())
}

pub fn ioctl_get_image_load_len(pirp: PIRP) -> Result<(), DriverError> {
    unsafe {
        if (*pirp).AssociatedIrp.SystemBuffer.is_null() {
            println!("[sanctum] [-] SystemBuffer is a null pointer in ioctl_get_image_load_len.");
            return Err(DriverError::NullPtr);
        }
    }

    // We want to drain the live copy of the ImageLoadQueueForInjector into the cache (handled by the `drain_queue` fn)
    // and check the size of the returned data, which will be the memory size of the cache. We can then send this back to
    // userland and make a subsequent IOCTL which will drain the cached copy, sending it to userland.
    let data = ImageLoadQueueForInjector::drain_queue(ImageLoadQueueSelector::Live);
    if data.is_none() {
        return Err(DriverError::NoDataToSend);
    }

    // safe to unwrap now with the above check
    let data = data.unwrap();
    let serialised = match serde_json::to_string(&data) {
        Ok(ser) => ser,
        Err(e) => {
            println!("[sanctum] [-] Unable to serialise the BTreeSet. {e}");
            return Err(DriverError::CouldNotSerialize);
        }
    };

    let data_len = serialised.as_bytes().len();

    unsafe { (*pirp).IoStatus.Information = mem::size_of::<usize>() as u64 };

    // copy the memory into the buffer
    unsafe {
        RtlCopyMemoryNonTemporal(
            (*pirp).AssociatedIrp.SystemBuffer,
            &data_len as *const _ as *const _,
            mem::size_of::<usize>() as u64,
        )
    };

    Ok(())
}

pub fn ioctl_handler_get_image_loads(pirp: PIRP) -> Result<(), DriverError> {
    unsafe {
        if (*pirp).AssociatedIrp.SystemBuffer.is_null() {
            println!(
                "[sanctum] [-] SystemBuffer is a null pointer in ioctl_handler_get_image_loads."
            );
            return Err(DriverError::NullPtr);
        }
    }

    // Load up the `ImageLoadQueueForInjector`. We will check to see whether it contains data; if not - we can return nothing.
    let data = ImageLoadQueueForInjector::drain_queue(ImageLoadQueueSelector::Cache);

    if data.is_none() {
        return Err(DriverError::NoDataToSend);
    }

    let encoded_data = match serde_json::to_string(&data.clone().unwrap()) {
        Ok(v) => v,
        Err(e) => {
            println!(
                "[sanctum] [-] Error serializing data to string in ioctl_handler_get_image_loads. {e}"
            );
            return Err(DriverError::CouldNotSerialize);
        }
    };

    let bytes = encoded_data.as_bytes();
    let data_len = bytes.len();

    unsafe { (*pirp).IoStatus.Information = data_len as _ };

    // copy the memory into the buffer
    unsafe {
        RtlCopyMemoryNonTemporal(
            (*pirp).AssociatedIrp.SystemBuffer,
            bytes.as_ptr() as *const _ as *const _,
            data_len as _,
        )
    };

    Ok(())
}

/// Checks the compatibility of the driver version with client version. For all intents and purposes this can be
/// considered the real 'ping' with the current pings being POC for passing data between UM and KM.
pub fn ioctl_check_driver_compatibility(
    p_stack_location: *mut _IO_STACK_LOCATION,
    pirp: PIRP,
) -> Result<(), NTSTATUS> {
    let mut ioctl_buffer = IoctlBuffer::new(p_stack_location, pirp);
    ioctl_buffer.receive()?; // receive the data

    let input_data = ioctl_buffer.buf as *const _ as *const SanctumVersion;
    if input_data.is_null() {
        println!("[sanctum] [-] Error receiving input data for checking driver compatibility.");
        return Err(STATUS_UNSUCCESSFUL);
    }

    // validated the pointer, data should be safe to dereference
    let input_data: &SanctumVersion = unsafe { &*input_data };

    // check whether we are compatible
    let response = check_driver_version(input_data);
    println!(
        "[sanctum] [i] Client version: {}.{}.{}, is compatible with driver version: {}.",
        input_data.major, input_data.minor, input_data.patch, response
    );
    let log = Log::new();
    log.log_to_userland(format!(
        "[i] Client version: {}.{}.{}, is compatible with driver version: {}.",
        input_data.major, input_data.minor, input_data.patch, response
    ));

    // prepare the data
    let res_size = core::mem::size_of_val(&response) as u64;
    unsafe { (*pirp).IoStatus.Information = res_size };

    unsafe {
        RtlCopyMemoryNonTemporal(
            (*pirp).AssociatedIrp.SystemBuffer,
            &response as *const bool as *const c_void,
            res_size,
        );
    }

    Ok(())
}

// todo docs
pub fn ioctl_dll_hook_syscall(
    p_stack_location: *mut _IO_STACK_LOCATION,
    pirp: PIRP,
) -> Result<(), NTSTATUS> {
    let mut ioctl_buffer = IoctlBuffer::new(p_stack_location, pirp);
    ioctl_buffer.receive()?; // receive the data

    let input_data = ioctl_buffer.buf as *const _ as *const u8;
    if input_data.is_null() {
        println!("[sanctum] [-] Error receiving input data for checking driver compatibility.");
        return Err(STATUS_UNSUCCESSFUL);
    }

    // SAFETY: Pointer validity checked above
    let input_data = unsafe { from_raw_parts(input_data, ioctl_buffer.len as usize) };
    let syscall_data: Syscall = match serde_json::from_slice(&input_data) {
        Ok(d) => d,
        Err(e) => {
            println!("Failed to parse JSON from user: {:?}", e);
            return Err(STATUS_INVALID_PARAMETER);
        }
    };

    ProcessMonitor::ghost_hunt_add_event(syscall_data);

    Ok(())
}

/// Tells the driver a given process is ready for ghost hunting (to be called after successful re-locations of ntdll by
/// sanctum.dll).
pub fn ioctl_process_finished_sanc_dll_load(
    p_stack_location: *mut _IO_STACK_LOCATION,
    pirp: PIRP,
) -> NTSTATUS {
    let mut ioctl_buffer = IoctlBuffer::new(p_stack_location, pirp);
    if ioctl_buffer.receive().is_err() {
        return STATUS_UNSUCCESSFUL;
    }

    let input_data = ioctl_buffer.buf as *const _ as *const u32;
    if input_data.is_null() {
        println!("[sanctum] [-] Error receiving input data for ioctl_proc_r_gh.");
        return STATUS_UNSUCCESSFUL;
    }

    // SAFETY: Pointer validity checked above
    let pid = unsafe { *input_data };

    ProcessMonitor::mark_process_ready_for_ghost_hunting(pid);

    STATUS_SUCCESS
}

pub fn ioctl_failed_to_inject_dll(
    p_stack_location: *mut _IO_STACK_LOCATION,
    pirp: PIRP,
) -> Result<(), NTSTATUS> {
    let mut ioctl_buffer = IoctlBuffer::new(p_stack_location, pirp);
    ioctl_buffer.receive()?; // receive the data

    let input_data = ioctl_buffer.buf as *const _ as *const u8;
    if input_data.is_null() {
        println!("[sanctum] [-] Error receiving input data ioctl_failed_to_inject_dll.");
        return Err(STATUS_UNSUCCESSFUL);
    }

    // SAFETY: Pointer validity checked above
    let input_data = unsafe { from_raw_parts(input_data, ioctl_buffer.len as usize) };
    let pid: u32 = match serde_json::from_slice(&input_data) {
        Ok(d) => d,
        Err(e) => {
            println!("Failed to parse JSON from user: {:?}", e);
            return Err(STATUS_INVALID_PARAMETER);
        }
    };

    if ImageLoadQueueForInjector::remove_pid_from_injection_waitlist(pid as usize).is_err() {
        // todo handle threat detection here (n.b. duplicate in image callbacks)
    }

    Ok(())
}

#[derive(Debug)]
enum ImageLoadQueueSelector {
    Cache,
    Live,
}

/// An interface to access processes pending creation after the image load callback has run.
///
/// Whilst this has the name 'queue', it is not strictly speaking a queue, but is an interface for a BTreeSet wrapped in a
/// FastMutex via `wdk_mutex` Grt.
pub struct ImageLoadQueueForInjector;

impl ImageLoadQueueForInjector {
    /// Initialises the ImageLoadQueueForInjector, which uses the `wdk_mutex` Grt for global access to a mutex containing
    /// the image load 'queue'.
    ///
    /// Initialises ImageLoadCache, which will be drained by the final IOCTL once the size is known.
    ///
    /// Initialises the `ImageLoadQueuePendingInjection` Grt, which is used by the image load callback routine to wait
    /// for notification that the engine has injected our DLL into the process.
    ///
    /// This function should only be called once in the drivers life.
    ///
    /// # Panics
    /// This function will cause a driver panic if it is unable to register the mutex with the `Grt`.
    pub fn init() {
        match Grt::register_fast_mutex_checked("ImageLoadQueueForInjector", ImageLoadQueues::new())
        {
            Ok(_) => (),
            Err(e) => {
                println!(
                    "[sanctum] [-] Error registering fast mutex for ImageLoadQueueForInjector. {:?}",
                    e
                );
                panic!();
            }
        };

        match Grt::register_fast_mutex_checked("ImageLoadCache", ImageLoadQueues::new()) {
            Ok(_) => (),
            Err(e) => {
                println!(
                    "[sanctum] [-] Error registering fast mutex for ImageLoadCache. {:?}",
                    e
                );
                panic!();
            }
        };

        match Grt::register_fast_mutex_checked(
            "ImageLoadQueuePendingInjection",
            ImageLoadQueues::new(),
        ) {
            Ok(_) => (),
            Err(e) => {
                println!(
                    "[sanctum] [-] Error registering fast mutex for ImageLoadQueuePendingInjection. {:?}",
                    e
                );
                panic!();
            }
        };
    }

    /// Queues a process by PID to the Grt `ImageLoadQueueForInjector` waiting for the usermode engine to take it away
    /// to instruct the Sanctum DLL to be injected.
    pub fn queue_process_for_usermode(pid: usize) {
        let mut lock: FastMutexGuard<ImageLoadQueues> = match Grt::get_fast_mutex(
            "ImageLoadQueueForInjector",
        ) {
            Ok(l) => match l.lock() {
                Ok(l) => l,
                Err(e) => {
                    println!(
                        "[sanctum] [-] Error getting lock for ImageLoadQueueForInjector in add_process. {:?}",
                        e
                    );
                    panic!();
                }
            },
            Err(e) => {
                println!(
                    "[sanctum] [-] Error getting FastMutex for ImageLoadQueueForInjector in add_process. {:?}",
                    e
                );
                panic!();
            }
        };

        if lock.insert(pid) == false {
            println!(
                "[sanctum] [i] ImageLoadQueueForInjector had duplicate key for pid: {pid}, this should not occur."
            );
            panic!(); // maybe bsod here? this state should never occur
        }

        // Add the pid to the queue so that we can match the resulting DLL image load
        Self::add_dll_injected_for_pid(pid);
    }

    /// Adds a process to the `Grt` for `ImageLoadQueuePendingInjection`.
    pub fn add_dll_injected_for_pid(pid: usize) {
        let mut lock: FastMutexGuard<ImageLoadQueues> = match Grt::get_fast_mutex(
            "ImageLoadQueuePendingInjection",
        ) {
            Ok(l) => match l.lock() {
                Ok(l) => l,
                Err(e) => {
                    println!(
                        "[sanctum] [-] Error getting lock for ImageLoadQueuePendingInjection in add_process. {:?}",
                        e
                    );
                    panic!();
                }
            },
            Err(e) => {
                println!(
                    "[sanctum] [-] Error getting FastMutex for ImageLoadQueuePendingInjection in add_process. {:?}",
                    e
                );
                panic!();
            }
        };

        if lock.insert(pid) == false {
            println!(
                "[sanctum] [i] ImageLoadQueuePendingInjection had duplicate key for pid: {pid}. This requires some further \
                    investigation at some point."
            );
        }
    }

    /// Removes a pid from the set which contains pids waiting for sanctum to be injected into them.
    ///
    /// # Returns
    /// - `Ok` if the PID was present
    /// - `Err` if the PID was not present - this would be indicative of threat actor manipulation
    pub fn remove_pid_from_injection_waitlist(pid: usize) -> Result<(), ()> {
        let mut lock: FastMutexGuard<ImageLoadQueues> = match Grt::get_fast_mutex(
            "ImageLoadQueuePendingInjection",
        ) {
            Ok(l) => match l.lock() {
                Ok(l) => l,
                Err(e) => {
                    println!(
                        "[sanctum] [-] Error getting lock for ImageLoadQueuePendingInjection in remove_pid_from_injection_waitlist. {:?}",
                        e
                    );
                    panic!();
                }
            },
            Err(e) => {
                println!(
                    "[sanctum] [-] Error getting FastMutex for ImageLoadQueuePendingInjection in remove_pid_from_injection_waitlist. {:?}",
                    e
                );
                panic!();
            }
        };

        if lock.remove(&pid) == false {
            return Err(());
        }

        Ok(())
    }

    /// Determines whether a PID is present in the waitlist for the ImageLoadQueuePendingInjection `Grt`.
    ///
    /// # Returns
    /// `true` if the PID is present
    /// `false` if the PID is not present
    pub fn pid_in_waitlist(pid: usize) -> bool {
        let lock: FastMutexGuard<ImageLoadQueues> = match Grt::get_fast_mutex(
            "ImageLoadQueuePendingInjection",
        ) {
            Ok(l) => match l.lock() {
                Ok(l) => l,
                Err(e) => {
                    println!(
                        "[sanctum] [-] Error getting lock for ImageLoadQueuePendingInjection in remove_pid_from_injection_waitlist. {:?}",
                        e
                    );
                    panic!();
                }
            },
            Err(e) => {
                println!(
                    "[sanctum] [-] Error getting FastMutex for ImageLoadQueuePendingInjection in remove_pid_from_injection_waitlist. {:?}",
                    e
                );
                panic!();
            }
        };

        lock.contains(&pid)
    }

    /// Drains the current state of the `ImageLoadQueueForInjector`, clearing the old structure for new data to be added in a
    /// async safe manner.
    ///
    /// # Returns
    /// - `none` if the set was empty.
    /// - `some` containing the newly created pids.
    pub fn drain_queue(queue_type: ImageLoadQueueSelector) -> Option<ImageLoadQueues> {
        let key = match queue_type {
            ImageLoadQueueSelector::Cache => "ImageLoadCache",
            ImageLoadQueueSelector::Live => "ImageLoadQueueForInjector",
        };

        let mut lock: FastMutexGuard<ImageLoadQueues> = match Grt::get_fast_mutex(key) {
            Ok(l) => match l.lock() {
                Ok(l) => l,
                Err(e) => {
                    println!(
                        "[sanctum] [-] Error getting lock for ImageLoadQueueForInjector in drain_queue. {:?}",
                        e
                    );
                    panic!();
                }
            },
            Err(e) => {
                println!(
                    "[sanctum] [-] Error getting FastMutex for ImageLoadQueueForInjector in drain_queue. {:?}",
                    e
                );
                panic!();
            }
        };

        if lock.is_empty() {
            return None;
        }

        let mut dup = mem::take(&mut *lock);

        // If we drained the live queue, we need to add this to the cache
        match queue_type {
            ImageLoadQueueSelector::Live => {
                let mut cache_lock: FastMutexGuard<ImageLoadQueues> = match Grt::get_fast_mutex(
                    "ImageLoadCache",
                ) {
                    Ok(l) => match l.lock() {
                        Ok(l) => l,
                        Err(e) => {
                            println!(
                                "[sanctum] [-] Error getting lock for ImageLoadQueueForInjector in drain_queue. {:?}",
                                e
                            );
                            panic!();
                        }
                    },
                    Err(e) => {
                        println!(
                            "[sanctum] [-] Error getting FastMutex for ImageLoadQueueForInjector in drain_queue. {:?}",
                            e
                        );
                        panic!();
                    }
                };

                cache_lock.append(&mut dup);
                return Some((*cache_lock).clone());
            }
            _ => (),
        }

        Some(dup)
    }
}
