use serde::{Deserialize, Serialize};

/// Bitfields which act as a mask to determine which event types (kernel, syscall hook, etw etc)
/// are required to fully cancel out the ghost hunt timers.
///
/// This is because not all events are capturable in the kernel without tampering with patch guard etc, so there are some events
/// only able to be caught by ETW and the syscall hook.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub enum SyscallEventSource {
    EventSourceKernel = 0x1,
    EventSourceSyscallHook = 0x2,
    EventSourceEtw = 0x4,
}

/// A wrapper for IPC messages sent by the injected DLL in all processes. This allows the same IPC interface to
/// be used across any number of IPC senders, so long as the enum has a discriminant for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DLLMessage {
    SyscallWrapper(Syscall),
    NtdllOverwrite,
}

/****************************** SYSCALLS *******************************/

/// Information relating to a syscall event which happened on the device. This struct holds:
///
/// - `data`: This field is generic over T which must implement the `HasPid` trait. This field contains the metadata associated
/// with the syscall.
/// - `source`: Where the system event was captured, e.g. a hooked syscall, ETW, or the driver.
/// - `evasion_weight`: The weight associated with the event if EDR evasion is detected.
/// - todo: `event_weight` for general weighting if this occurs, same as the normal weight i guess?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Syscall {
    pub nt_function: NtFunction,
    pub pid: u64,
    pub source: SyscallEventSource,
    pub evasion_weight: i16,
}

/// todo docs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NtFunction {
    NtOpenProcess(Option<NtOpenProcessData>),
    NtWriteVirtualMemory(Option<NtWriteVirtualMemoryData>),
    NtAllocateVirtualMemory(Option<NtAllocateVirtualMemory>),
}

impl NtFunction {
    /// Determines which API's can cancel out event signals
    pub fn find_cancellable_apis_ghost_hunting(&self) -> isize {
        match self {
            NtFunction::NtOpenProcess(_) => {
                SyscallEventSource::EventSourceKernel as isize
                    | SyscallEventSource::EventSourceSyscallHook as isize
            }
            NtFunction::NtWriteVirtualMemory(_) => {
                SyscallEventSource::EventSourceEtw as isize
                    | SyscallEventSource::EventSourceSyscallHook as isize
            }
            NtFunction::NtAllocateVirtualMemory(_) => {
                SyscallEventSource::EventSourceEtw as isize
                    | SyscallEventSource::EventSourceSyscallHook as isize
            }
        }
    }
}

/// todo docs
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NtOpenProcessData {
    pub target_pid: u32,
}

/// todo docs
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NtWriteVirtualMemoryData {
    pub target_pid: u32,
    pub base_address: usize,
    pub buf_len: usize,
}

/// todo docs
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NtAllocateVirtualMemory {
    /// The base address is the base of the remote process which is stored as a usize but is actually a hex
    /// address and will need converting if using as an address.
    pub base_address: usize,
    /// THe size of the allocated memory
    pub region_size: usize,
    /// A bitmask containing flags that specify the type of allocation to be performed.
    pub allocation_type: u32,
    /// A bitmask containing page protection flags that specify the protection desired for the committed
    /// region of pages.
    pub protect: u32,
    /// The pid in which the allocation is taking place in
    pub remote_pid: u32,
}

impl Syscall {
    /// Creates a new Syscall data packet where the source is from the ETW module
    pub fn new_etw(pid: u64, nt_function: NtFunction, evasion_weight: i16) -> Self {
        Self {
            nt_function,
            pid,
            source: SyscallEventSource::EventSourceEtw,
            evasion_weight,
        }
    }
}

unsafe impl Send for Syscall {}
