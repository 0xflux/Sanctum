//! # Sanctum Process Monitor
//!
//! The `process_monitor` module implements a Windows-kernel driver component
//! that tracks process lifecycles and applies “ghost-hunting” heuristics to detect
//! syscall-hooking evasion.  
//! 
//! For more info on GhostHunting, see my blog post:
//! https://fluxsec.red/edr-syscall-hooking
//!
//! Key features:
//! - Maintains a global map of `Process` metadata  
//! - Spawns a monitoring thread to time syscall events  
//! - Exposes APIs to register new processes, remove exited ones, and feed
//!   Ghost Hunting telemetry

use core::{ffi::c_void, ptr::null_mut, time::Duration};

use alloc::{collections::btree_map::BTreeMap, string::String, vec::Vec};
use shared_no_std::{
    driver_ipc::ProcessStarted,
    ghost_hunting::{NtFunction, Syscall, SyscallEventSource},
};
use wdk::println;
use wdk_mutex::{
    errors::GrtError,
    fast_mutex::{FastMutex, FastMutexGuard},
    grt::Grt,
};
use wdk_sys::{
    _MODE::KernelMode,
    HANDLE, LARGE_INTEGER, STATUS_SUCCESS, THREAD_ALL_ACCESS, TRUE,
    ntddk::{
        KeDelayExecutionThread, KeQuerySystemTimePrecise, ObReferenceObjectByHandle,
        PsCreateSystemThread,
    },
};

/// A `Process` is a Sanctum driver representation of a Windows process so that actions it preforms, and is performed
/// onto it, can be tracked and monitored.
pub struct Process {
    pid: u64,
    /// Parent pid
    ppid: u64,
    pub process_image: String,
    pub commandline_args: String,
    pub risk_score: u16,
    pub allow_listed: bool, // whether the application is allowed to exist without monitoring
    /// Creates a time window in which a process handle must match from a hooked syscall with
    /// the kernel receiving the notification. Failure to match this may be an indicator of hooked syscall evasion.
    pub ghost_hunting_timers: Vec<GhostHuntingTimer>,
    targeted_by_apis: Vec<ProcessTargetedApis>,
}

// todo needs implementing
#[derive(Debug, Default)]
pub struct ProcessTargetedApis {}

/// A `GhostHuntingTimer` is the timer metadata associated with the Ghost Hunting technique on my blog:
/// https://fluxsec.red/edr-syscall-hooking
///
/// The data contained in this struct allows timers to be polled and detects abuse of direct syscalls / hells gate.
pub struct GhostHuntingTimer {
    // Query the time via `KeQuerySystemTime`
    pub timer_start: LARGE_INTEGER,
    pub event_type: NtFunction,
    /// todo update docs
    pub origin: SyscallEventSource,
    /// Specifies which syscall types of a matching event this is cancellable by. As the EDR monitors multiple
    /// sources of telemetry, we cannot do a 1:1 cancellation process.
    pub cancellable_by: isize,
    pub weight: i16,
}

/// The ProcessMonitor is responsible for monitoring all processes running; this
/// structure holds a hashmap of all processes by the pid as an integer, and
/// the data within is a MonitoredProcess containing the details
///
/// The key of processes hashmap is the pid, which is duplicated inside the Process
/// struct.
pub struct ProcessMonitor;

#[derive(Debug)]
pub enum ProcessErrors {
    PidNotFound,
    DuplicatePid,
    BadHandle,
    BadFnAddress,
    BaseAddressNull,
    FailedToWriteMemory,
    FailedToCreateRemoteThread,
    FailedToOpenProcess,
}

impl ProcessMonitor {
    /// Instantiates a new `ProcessMonitor`; which is just an interface for access to the underlying
    /// globally managed mutex via `Grt` (my `wdk-mutex` crate).
    ///
    /// This function should only be called once on driver initialisation.
    ///
    /// The `ProcessMonitor` is required for use in driver callback routines, therefore we can either track via a single
    /// static; or use the `Grt` design pattern (favoured in this case).
    pub fn new() -> Result<(), GrtError> {
        Grt::register_fast_mutex("ProcessMonitor", BTreeMap::<u64, Process>::new())
    }

    pub fn onboard_new_process(process: &ProcessStarted) -> Result<(), ProcessErrors> {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        if process_lock.get(&process.pid).is_some() {
            return Err(ProcessErrors::DuplicatePid);
        }

        // todo this actually needs filling out with the relevant data
        process_lock.insert(process.pid, Process {
            pid: process.pid,
            ppid: process.parent_pid,
            process_image: process.image_name.clone(),
            commandline_args: process.command_line.clone(),
            risk_score: 0,
            allow_listed: false,
            ghost_hunting_timers: Vec::new(),
            targeted_by_apis: Vec::new(),
        });

        Ok(())
    }

    // todo need to remove processes from the monitor once they are terminated
    pub fn remove_process(pid: u64) {
        let mut process_lock = ProcessMonitor::get_mtx_inner();
        process_lock.remove(&pid);
    }

    /// Notifies the Ghost Hunting management that a new huntable event has occurred.
    pub fn ghost_hunt_add_event(pid: u64, signal: Syscall) {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        if let Some(process) = process_lock.get_mut(&pid) {
            let mut current_time = LARGE_INTEGER::default();
            unsafe { KeQuerySystemTimePrecise(&mut current_time) };

            process.add_ghost_hunt_timer(GhostHuntingTimer {
                timer_start: current_time,
                cancellable_by: signal.nt_function.find_cancellable_apis_ghost_hunting(),
                event_type: signal.nt_function,
                origin: signal.source,
                weight: signal.evasion_weight,
            });
        }
    }

    /// This function is responsible for polling all Ghost Hunting timers to try match up hooked syscall API calls
    /// with kernel events sent from our driver.
    ///
    /// This is part of my Ghost Hunting technique https://fluxsec.red/edr-syscall-hooking
    pub fn poll_ghost_timers() {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        for (_, process) in process_lock.iter_mut() {
            if process.ghost_hunting_timers.is_empty() {
                continue;
            }

            //
            // In here process each API event we are tracking in the ghost timers.
            //

            // todo try integrate the following into the windows-drivers-rs project:
            // https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/using-timers
            // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdftimer/nf-wdftimer-wdftimercreate
            // Kinda wanna do it as a driver POC for now, then once working, can try migrate it into the windows drivers
            // project so I can use event timers from the wdk, rather than a system thread.

            // todo these are being computed every time; perhaps they could be moved inside of the `FastMutex` and computed
            // only once
            let max_time_allowed = Duration::from_secs(1);
            let max_time_allowed = LARGE_INTEGER {
                QuadPart: ((max_time_allowed.as_nanos() / 100) as i64),
            };

            let max_time_allowed_etw = Duration::from_secs(3);
            let max_time_allowed_etw = LARGE_INTEGER {
                QuadPart: ((max_time_allowed_etw.as_nanos() / 100) as i64),
            };

            let mut index: usize = 0; // index of iterator over the ghost timers
            for item in &process.ghost_hunting_timers {
                let mut current_time = LARGE_INTEGER::default();
                unsafe { KeQuerySystemTimePrecise(&mut current_time) };

                // We are only running the driver on x64, so we can compute the delta using the QuadPart.

                let time_delta = unsafe { current_time.QuadPart - item.timer_start.QuadPart };

                // if we are waiting on the ETW feed, it takes a little longer
                if item.cancellable_by & SyscallEventSource::EventSourceEtw as isize
                    == SyscallEventSource::EventSourceEtw as isize
                {
                    if time_delta > unsafe { max_time_allowed_etw.QuadPart } {
                        // process.update_process_risk_score(item.weight);
                        println!(
                            "[sanctum] *** TIMER EXCEEDED on: {:?}, pid responsible: {}",
                            item.event_type, process.pid
                        );

                        process.ghost_hunting_timers.remove(index);
                        break;
                    }
                } else {
                    if time_delta > unsafe { max_time_allowed.QuadPart } {
                        // process.update_process_risk_score(item.weight);
                        println!(
                            "[sanctum] *** TIMER EXCEEDED on: {:?}, pid responsible: {}",
                            item.event_type, process.pid
                        );

                        process.ghost_hunting_timers.remove(index);
                        break;
                    }
                }

                index += 1;
            }
        }
    }

    pub fn handle_syscall_ghost_hunt_event(data: &Syscall) {
        // println!("[sanctum] [i] Syscall ghost hunt data: {:?}", data);
        ProcessMonitor::ghost_hunt_add_event(data.pid, data.clone());
    }

    fn get_mtx_inner<'a>() -> FastMutexGuard<'a, BTreeMap<u64, Process>> {
        // todo rather than panic, ? error
        let process_lock: FastMutexGuard<BTreeMap<u64, Process>> =
            match Grt::get_fast_mutex("ProcessMonitor") {
                Ok(mtx) => match mtx.lock() {
                    Ok(l) => l,
                    Err(e) => {
                        println!(
                            "[-] Error locking KMutex for new process. Panicking. {:?}",
                            e
                        );
                        panic!()
                    }
                },
                Err(e) => {
                    println!("[sanctum] [-] Could not lock fast mutex. {:?}", e);
                    panic!()
                }
            };

        process_lock
    }

    /// Spawns a system thread to poll Ghost Hunting timers.
    ///
    /// # Panics
    /// Panics if thread creation or handle reference fails.
    pub fn start_ghost_hunt_monitor() {
        // Start the thread that will monitor for changes
        let mut thread_handle: HANDLE = null_mut();

        let thread_status = unsafe {
            PsCreateSystemThread(
                &mut thread_handle,
                0,
                null_mut(),
                null_mut(),
                null_mut(),
                Some(thread_run_monitor_ghost_hunting),
                null_mut(),
            )
        };

        if thread_status != STATUS_SUCCESS {
            println!(
                "[sanctum] [-] Could not create new thread for monitoring ETW patching, kernel ETW is not being monitored."
            );
            panic!();
        }

        // To prevent a BSOD when exiting the thread on driver unload, we need to reference count the handle
        // so that it isn't deallocated whilst waiting on the thread to exit.
        let mut object: *mut c_void = null_mut();
        if unsafe {
            ObReferenceObjectByHandle(
                thread_handle,
                THREAD_ALL_ACCESS,
                null_mut(),
                KernelMode as _,
                &mut object,
                null_mut(),
            )
        } != STATUS_SUCCESS
        {
            println!(
                "[sanctum] [-] Could not get thread handle by ObRef.. kernel ETW is not being monitored."
            );
            panic!()
        }

        if Grt::register_fast_mutex("TERMINATION_FLAG_GH_MONITOR", false).is_err() {
            println!(
                "[sanctum] [-] Could not register TERMINATION_FLAG_GH_MONITOR as a FAST_MUTEX, PANICKING."
            );
            panic!()
        }
        if Grt::register_fast_mutex("GH_THREAD_HANDLE", object).is_err() {
            println!(
                "[sanctum] [-] Could not register GH_THREAD_HANDLE as a FAST_MUTEX, PANICKING"
            );
            panic!()
        }
    }
}

/// Remove an event source from a given Ghost Hunting timer.
///
/// This function will modify the timer object to remove a cancellable event origin in place.
///
/// # Args
/// - `timer`: A mutable reference to the GhostHuntingTimer for a given process
/// - `new_source`: An isize representing whether we need to unset a different bit (see remarks)
///
/// # Remarks
/// In the case where you are unsetting the cancellable bit for the 'self' i.e. there are no active Ghost Hunting
/// events in the queue for that API, you want to unset the bit for where it came from, as you only want to match on the
/// other bit fields. In this case, enter this `new_source` param as `None`.
///
/// However; if you are processing a **new** API where there **is** an active timer waiting for the relevant cancellation events
/// to come in, then opt for `Some` where the `T` is an `SyscallEventSource` representing the source of where the syscall
/// was detected from.
#[inline(always)]
fn unset_event_flag_in_timer(
    timer: &mut GhostHuntingTimer,
    new_source: Option<SyscallEventSource>,
) {
    // flip the set bit back to a 0
    match new_source {
        Some(new_source) => {
            timer.cancellable_by = timer.cancellable_by as isize ^ new_source as isize;
        }
        None => timer.cancellable_by = timer.cancellable_by as isize ^ timer.origin as isize,
    }
}

impl Process {
    /// Adds a ghost hunt timer specifically to a process.
    ///
    /// This function will internally deal with cases where a timer for the same API already exists. If the timer already exists, it will
    /// use bit flags to
    fn add_ghost_hunt_timer(&mut self, mut new_timer: GhostHuntingTimer) {
        // If the timers are empty; then its the first in so we can add it to the list straight up.
        if self.ghost_hunting_timers.is_empty() {
            // remove the current notification from the cancellable by (prevent dangling timers)
            unset_event_flag_in_timer(&mut new_timer, None);
            self.ghost_hunting_timers.push(new_timer);
            return;
        }

        // Otherwise, there is data in the ghost hunting timers ...
        for (index, timer_iter) in self.ghost_hunting_timers.iter_mut().enumerate() {
            // If the API Origin that this fn relates to is found in the list of cancellable APIs then cancel them out.
            // Part of the core Ghost Hunting logic. First though we need to check that the event type that can cancel it out
            // is present in the active flags (bugs were happening where other events of the same type were being XOR'ed, so if they
            // were previously unset, the flag  was being reset and the process was therefore failing).
            // To get around this we do a bitwise& check before running the XOR in unset_event_flag_in_timer.
            if core::mem::discriminant(&timer_iter.event_type)
                == core::mem::discriminant(&new_timer.event_type)
            {
                if timer_iter.cancellable_by & new_timer.origin as isize
                    == new_timer.origin as isize
                {
                    unset_event_flag_in_timer(timer_iter, Some(new_timer.origin));

                    // If everything is cancelled out (aka all bit fields set to 0 remove the timer completely from the process)
                    if timer_iter.cancellable_by == 0 {
                        self.ghost_hunting_timers.remove(index);
                        return;
                    }

                    return;
                }
            }
        }

        // we did not match on the above timer.event_type in the list of active timers, so add the element as a new timer
        // remove the current notification from the cancellable by (prevent dangling timers)
        unset_event_flag_in_timer(&mut new_timer, None);
        self.ghost_hunting_timers.push(new_timer);
    }
}

/// Worker thread entry point. Sleeps once per second, polls all `ghost_hunting_timers`, and exits when the driver is unloaded.
unsafe extern "C" fn thread_run_monitor_ghost_hunting(_: *mut c_void) {
    let delay_as_duration = Duration::from_secs(1);
    let mut thread_sleep_time = LARGE_INTEGER {
        QuadPart: -((delay_as_duration.as_nanos() / 100) as i64),
    };

    loop {
        let _ =
            unsafe { KeDelayExecutionThread(KernelMode as _, TRUE as _, &mut thread_sleep_time) };
        ProcessMonitor::poll_ghost_timers();

        // Check if we have received the cancellation flag, without this check we will get a BSOD. This flag will be
        // set to true on DriverExit.
        let terminate_flag_lock: &FastMutex<bool> = match Grt::get_fast_mutex(
            "TERMINATION_FLAG_GH_MONITOR",
        ) {
            Ok(lock) => lock,
            Err(e) => {
                // Maybe this should terminate the thread instead? This would be a bad error to have as it means we cannot.
                // instruct the thread to terminate cleanly on driver exit. Or maybe do a count with max tries? We shall see.
                println!(
                    "[sanctum] [-] Error getting fast mutex for TERMINATION_FLAG_GH_MONITOR. {:?}",
                    e
                );
                continue;
            }
        };
        let lock = match terminate_flag_lock.lock() {
            Ok(lock) => lock,
            Err(e) => {
                println!(
                    "[sanctum] [-] Failed to lock mutex for terminate_flag_lock/ {:?}",
                    e
                );
                continue;
            }
        };
        if *lock {
            break;
        }
    }
}
