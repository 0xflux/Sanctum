use std::{ffi::CStr, sync::Arc, time::Duration};

use shared_no_std::driver_ipc::ProcessStarted;
use shared_std::processes::Process;
use tokio::{sync::{Mutex, RwLock}, time::sleep};
use windows::Win32::{Foundation::{CloseHandle, GetLastError}, System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPALL}};

use crate::{driver_manager::SanctumDriverManager, utils::log::{Log, LogLevel}};

use super::process_monitor::ProcessMonitor;

/// The core struct contains information on the core of the usermode engine where decisions are being made, and directly communicates
/// with the kernel.
/// 
/// # Components
/// 
/// - `driver_poll_rate`: the poll rate in milliseconds that the kernel will be (approximately) queried. The 
/// approximation is because the polling / decision making loop is not asynchronous and other decision making
/// takes place prior to the poll rate sleep time.
/// - `driver_dbg_message_cache`: a temporary cache of messages which are returned from the kernel which the 
/// GUI can request.
#[derive(Debug, Default)]
pub struct Core {
    driver_poll_rate: u64,
    driver_dbg_message_cache: Mutex<Vec<String>>,
    process_monitor: RwLock<ProcessMonitor>,
}


impl Core {

    /// Initialises a new Core instance from a poll rate in milliseconds.
    pub fn from(poll_rate: u64) -> Self {
        let mut core = Core::default();
        
        core.driver_poll_rate = poll_rate;
        
        core
    }

    /// Starts the core of the usermode engine; kicking off the frequent polling of the driver, and conducts relevant decision making
    pub async fn start_core(
        &self,
        driver_manager: Arc<Mutex<SanctumDriverManager>>,
    ) -> ! {

        let logger = Log::new();

        //
        // To start with, we will snapshot all running processes and then add them to the active processes.
        // there is possible a short time window where processes are created / terminated, which may cause
        // a zone of 'invisibility' at this point in time, but this should be fixed in the future when
        // we receive handles / changes to processes, if they don't exist, they should be created then.
        // todo - marker for info re above.
        //
        let snapshot_processes = snapshot_all_processes().await;

        // extend the newly created local processes type from the results of the snapshot
        self.process_monitor.write().await.extend_processes(snapshot_processes);
        

        //
        // Enter the polling & decision making loop, this here is the core / engine of the usermode engine.
        //
        loop {
            // contact the driver and get any messages from the kernel 
            // todo needing to unlock the driver manager is an unnecessary bottleneck 
            let driver_response = {
                let mut mtx = driver_manager.lock().await;
                mtx.ioctl_get_driver_messages()
            };
            
            //
            // If we have new message(s) / emissions from the driver, process them in userland as appropriate 
            //
            if driver_response.is_some() {
                // first deal with process terminations to prevent trying to add to an old process id if there is a duplicate
                let mut driver_messages = driver_response.unwrap();
                let process_terminations = driver_messages.process_terminations;
                if !process_terminations.is_empty() {
                    for t in process_terminations {
                        self.process_monitor.write().await.remove_process(t.pid);
                    }
                }

                // add a new process to the running process hashmap
                let process_creations = driver_messages.process_creations;
                if !process_creations.is_empty() {
                    for p in process_creations {
                        if self.process_monitor.write().await.insert(&p).await.is_err() {
                            logger.log(LogLevel::Error, &format!("Failed to add new process to live processes. Process: {:?}", p));
                        }
                    }
                }

                // cache messages
                {
                    let mut message_cache = self.driver_dbg_message_cache.lock().await;
                    println!("Driver messages: {:?}", message_cache);
                    if !driver_messages.messages.is_empty() {
                        message_cache.append(&mut driver_messages.messages);
                    }
                }

                // add process creations to a hashmap (ProcessMonitor struct)

                /*
                    todo long term: 
                        - thread creation 
                        - handle requests
                        - change of handle type (e.g. trying to evade detection)
                        - is the process doing bad things itself (allocating foreign mem)
                        
                    ^ to the abv hashmap
                */
            }

            sleep(Duration::from_millis(self.driver_poll_rate)).await;
            
        }
    }


    /// Gets the cached driver messages for use in the GUI
    /// 
    /// # Returns
    /// 
    /// If there are no messages cached, None will be returned. Otherwise, a vector of the messages
    /// will be returned to the caller.
    pub async fn get_cached_driver_messages(&self) -> Option<Vec<String>> {
        let mut msg_lock = self.driver_dbg_message_cache.lock().await;

        if msg_lock.is_empty() {
            return None;
        }

        let tmp = msg_lock.clone();
        msg_lock.clear();
        
        Some(tmp)
    }


    /// Query a given process by its Pid, returning information about the process
    pub async fn query_process_by_pid(&self, pid: u64) -> Option<Process> {
        self.process_monitor.read().await.query_process_by_pid(pid)
    }

}

/// Enumerate all processes and add them to the active process monitoring hashmap.
async fn snapshot_all_processes() -> ProcessMonitor {

    let logger = Log::new();
    let mut all_processes = ProcessMonitor::new();
    let mut processes_cache: Vec<ProcessStarted> = vec![];

    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0)} {
        Ok(s) => {
            if s.is_invalid() {
                logger.panic(&format!("Unable to create snapshot of all processes. GLE: {}", unsafe { GetLastError().0 }));
            } else {
                s
            }
        },
        Err(_) => {
            // not really bothered about the error at this stage
            logger.panic(&format!("Unable to create snapshot of all processes. GLE: {}", unsafe { GetLastError().0 }));
        },
    };

    let mut process_entry = PROCESSENTRY32::default();
    process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(snapshot,&mut process_entry)}.is_ok() {
        loop {
            // 
            // Get the process name
            //
            let current_process_name_ptr = process_entry.szExeFile.as_ptr() as *const _;
            let current_process_name = match unsafe { CStr::from_ptr(current_process_name_ptr) }.to_str() {
                Ok(process) => process.to_string(),
                Err(e) => {
                    logger.log(LogLevel::Error, &format!("Error converting process name. {e}"));
                    continue;
                }
            };

            logger.log(LogLevel::Success, &format!("Process name: {}, pid: {}, parent: {}", current_process_name, process_entry.th32ProcessID, process_entry.th32ParentProcessID));
            let process = ProcessStarted {
                image_name: current_process_name,
                command_line: "".to_string(),
                parent_pid: process_entry.th32ParentProcessID as u64,
                pid: process_entry.th32ProcessID as u64,
            };

            processes_cache.push(process);

            // continue enumerating
            if !unsafe { Process32Next(snapshot, &mut process_entry) }.is_ok() {
                break;
            }
        }
    }

    unsafe { let _ = CloseHandle(snapshot); };

    // Now the HANDLE is closed we are able to call the async function insert on all_processes. 
    // We could not do this before closing the handle as teh HANDLE (aka *mut c_void) is not Send
    for process in processes_cache {
        if let Err(e) = all_processes.insert(&process).await {
            match e {
                super::process_monitor::ProcessErrors::DuplicatePid => {
                    logger.log(LogLevel::Error, &format!("Duplicate PID found in process hashmap, did not insert. Pid in question: {}", process_entry.th32ProcessID));
                },
                _ => {
                    logger.log(LogLevel::Error, "An unknown error occurred whilst trying to insert into process hashmap.");
                }
            }
        };
    }

    all_processes
}