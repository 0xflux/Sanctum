//! File scanner module 
//! 
//! This module provides functionality for scanning files and retrieving relevant
//! information about a file that the EDR may want to use in decision making. 

use std::{collections::{BTreeMap, BTreeSet}, fs::{self, File}, io::{self, BufRead, BufReader, Read}, os::windows::fs::MetadataExt, path::PathBuf, sync::{atomic::AtomicBool, Arc, Mutex}, thread, time::{Duration, Instant}};

use sha2::{Sha256, Digest};
use shared::constants::IOC_LIST_LOCATION;
use serde::{Deserialize, Serialize};
use tokio::{sync::watch, time::sleep};

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    File,
    Folder,
}

pub enum ScanResult {
    Results(Result<Vec<MatchedIOC>, io::Error>),
    ScanInProgress,
}


/// Structure for containing results pertaining to an IOC match
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct MatchedIOC {
    pub hash: String,
    pub file: PathBuf,
}


/// The FileScanner is the public interface into the module handling any static file scanning type capability.
/// This struct is public for visibility from lib.rs the core of um_engine, but it not intended to be accessed from the 
/// Tauri application - for handling state (which tauri will need to interact with), see FileScannerState
pub struct FileScanner {
    // iocs:
    // Using a BTreeSet for the IOCs as it has the best time complexity for searching - Rust's implementation in the stdlib
    // I don't think is the best optimised BTree out there, but it will do the job for now. Not adding any IOC metadata to this
    // list of hashes (aka turning this into a BTreeMap) as it's a waste of memory and that metadata can be looked up with automations
    // either locally on disk or in the cloud.
    iocs: BTreeSet<String>,
    // state - The state of the scanner so we can lock it whilst scanning
    pub state: Arc<Mutex<State>>,
    pub scanning_info: Arc<Mutex<ScanningLiveInfo>>,
}


/// The state of the scanner either Scanning or Inactive. If the scanner is scanning, then it contains
/// further information about the live-time information such as how many files have been scanned and time taken so far.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum State {
    Scanning,
    Finished,
    FinishedWithError(String),
    Inactive,
    Cancelled,
}


/// Live time information about the current scan
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct ScanningLiveInfo {
    pub num_files_scanned: u128,
    pub time_taken: Duration,
    pub scan_results: Vec<MatchedIOC>,
}

impl ScanningLiveInfo {
    pub fn new() -> Self {
        ScanningLiveInfo {
            num_files_scanned: 0,
            time_taken: Duration::new(0, 0),
            scan_results: Vec::<MatchedIOC>::new(),
        }
    }

    fn reset(&mut self) {
        self.num_files_scanned = 0;
        self.scan_results = Vec::new();
        self.time_taken = Duration::new(0, 0);
    }
}


impl FileScanner {
    /// Construct a new instance of the FileScanner with no parameters.
    pub fn new() -> Result<Self, std::io::Error> {

        //
        // ingest latest IOC hash list
        //
        let mut bts: BTreeSet<String> = BTreeSet::new();
        let file = File::open(IOC_LIST_LOCATION)?;
        let lines = BufReader::new(file).lines();

        for line in lines.flatten() {
            bts.insert(line);
        }

        Ok(
            FileScanner {
                iocs: bts,
                state: Arc::new(Mutex::new(State::Inactive)),
                scanning_info: Arc::new(Mutex::new(ScanningLiveInfo::new())),
            }
        )
    }


    /// Cancels the current scan
    pub fn cancel_scan(&self) -> Option<ScanningLiveInfo>{
        let mut lock = self.state.lock().unwrap();

        // check we are scanning, if not return
        if *lock == State::Scanning {
            *lock = State::Cancelled; // update state
            let sli = self.scanning_info.lock().unwrap();

            println!("[i] Scanning time: {:?}", self.scanning_info.lock().unwrap().time_taken);

            return Some(sli.clone());
        } 

        return None;
    }


    pub fn scan_started(&self) {
        let mut lock = self.state.lock().unwrap();
        *lock = State::Scanning;
        // reset the stats
        self.scanning_info.lock().unwrap().reset();
    }


    /// Checks whether a scan is in progress
    pub fn is_scanning(&self) -> bool {
        let lock = self.state.lock().unwrap();
        match *lock {
            State::Scanning => true,
            State::Finished => false,
            State::FinishedWithError(_) => false,
            State::Inactive => false,
            State::Cancelled => false,
        }
    }


    /// Checks whether the scan is cancelled, returning a bool
    // fn is_cancelled(&mut self) -> bool {
    //     self.is_cancelled.load(Ordering::SeqCst)
    // }


    /// Updates the internal is_scanning state to false
    pub fn end_scan(&self) {
        let mut lock = self.state.lock().unwrap();
        *lock = State::Inactive;
    }


    /// Scan the file held by the FileScanner against a set of known bad hashes
    /// 
    /// # Returns
    /// 
    /// The function will return a tuple of Ok (String, PathBuf) if there were no IO errors, and the result of the Ok will be an Option of type
    /// (String, PathBuf). If the function returns None, then there was no hash match made for malware. 
    /// 
    /// If it returns the Some variant, the hash of the IOC will be returned for post-processing and decision making, as well as the file name / path as PathBuf.
    fn scan_file_against_hashes(&self, target: &PathBuf) -> Result<Option<(String, PathBuf)>, std::io::Error>{
        //
        // In order to not read the whole file into memory (would be bad if the file size is > the amount of RAM available)
        // I've decided to loop over an array of 1024 bytes at at time until the end of the file, and use the hashing crate sha2
        // to update the hash values, this should produce the hash without requiring the whole file read into memory.
        //

        let file = File::open(&target)?;
        let mut reader = BufReader::new(&file);

        let hash = {
            let mut hasher = Sha256::new();

            //
            // We are going to put the file data as bytes onto the heap to prevent a stack buffer overrun, and in doing so
            // we don't want to consume all the available memory. Therefore, we will limit the maximum heap allocation to
            // 50 mb per file. If the file is of a size less than this, we will only heap allocate the amount of size needed
            // otherwise, we will heap allocate 50 mb.
            //

            const MAX_HEAP_SIZE: usize = 5000000; // 50 mb

            let alloc_size: usize = if let Ok(f) = file.metadata() {
                let file_size = f.file_size() as usize;

                if file_size < MAX_HEAP_SIZE {
                    // less than 50 mb
                    file_size
                } else {
                    MAX_HEAP_SIZE
                }                    
            } else {
                // if there was an error getting the metadata, default to the max size
                MAX_HEAP_SIZE
            };


            let mut buf = vec![0u8; alloc_size];
            
            //
            // ingest the file and update hash value per chunk(if chunking)
            //
            loop {
                //
                // This is a sensible place to check whether the user has cancelled the scan, anything before this is likely
                // too short a time period to have the user stop the scan.
                //
                // Putting this in the loop makes sense (in the event of a large file)
                //
                {
                    let lock = self.state.lock().unwrap();
                    if *lock == State::Cancelled {
                        // todo update the error type of this fn to something more flexible
                        println!("[i] Returning...");
                        return Err(io::Error::new(io::ErrorKind::Uncategorized, "User cancelled scan."));
                    }
                }

                let count = reader.read(&mut buf)?;
                if count == 0 {break;}
                hasher.update(&buf[..count]);
            }
            
            hasher.finalize()
        };
        let hash = format!("{:X}", hash); // format as string, uppercase

        // check the BTreeSet
        if self.iocs.contains(hash.as_str()) {
            // if we have a match on the malware..
            return Ok(Some((hash, target.clone())));
        }

        // No malware found
        Ok(None)

    }


    /// Public API entry point, scans from a root folder including all children, this can be used on a small 
    /// scale for a folder scan, or used to initiate a system scan.
    pub fn begin_scan(&self, target: PathBuf) -> Result<State, io::Error> {

        let stop_clock = Arc::new(Mutex::new(false));
        let clock_clone = Arc::clone(&stop_clock);
        let self_scanning_info_clone = Arc::clone(&self.scanning_info);

        // timer in its own green thread
        thread::spawn(move || {
            let timer = Instant::now();

            loop {
                // first check if the task is cancelled
                if *clock_clone.lock().unwrap() == true {
                    break;
                }

                // not cancelled, so get the elapsed time
                let elapsed = timer.elapsed();
                {
                    let mut lock = self_scanning_info_clone.lock().unwrap();
                    lock.time_taken = elapsed;

                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        
        if !target.is_dir() {
            let res = self.scan_file_against_hashes(&target);
            match res {
                Ok(res) => {
                    if let Some(v) = res {
                        let mut lock = self.scanning_info.lock().unwrap();
                        lock.scan_results.push(
                            MatchedIOC {
                                hash: v.0,
                                file: v.1,
                            }
                        );
                        
                        // result will contain the matched IOC
                        *stop_clock.lock().unwrap() = true;
                        return Ok(State::Finished);
                    }
                },
                Err(e) => {
                    *stop_clock.lock().unwrap() = true;

                    if e.kind() == io::ErrorKind::Uncategorized {
                        // results will be empty here
                        return Ok(State::Cancelled);
                    }

                    return Err(e);
                },
            }
        }

        let mut discovered_dirs: Vec<PathBuf> = vec![target];
        let mut time_map: BTreeMap<u128, PathBuf> = BTreeMap::new();

        while !discovered_dirs.is_empty() {

            // pop a directory
            let target = discovered_dirs.pop();
            if target.is_none() { continue; }

            // attempt to read the directory, if we don't have permission, continue to next item.
            let read_dir = fs::read_dir(target.unwrap());
            if read_dir.is_err() { continue; }

            for entry in read_dir.unwrap() {
                let entry = match entry {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("[-] Error with entry, e: {e}");
                        continue;
                    },
                };

                // check whether the scan is cancelled
                {
                    let lock = self.state.lock().unwrap();
                    if *lock == State::Cancelled {
                        // todo update the error type of this fn to something more flexible
                        println!("[i] Dirs left: {}", discovered_dirs.len());
                        *stop_clock.lock().unwrap() = true;
                        return Err(io::Error::new(io::ErrorKind::Uncategorized, "User cancelled scan."));
                    }
                }

                let path = entry.path();

                // todo some profiling here to see where the slowdowns are and if it can be improved
                // i suspect large file size ingests is causing the difference in speed as it reads it
                // into a buffer.
                println!("[i] Scanning file: {} for malware.", path.display());

                // add the folder to the next iteration 
                if path.is_dir() {
                    discovered_dirs.push(path);
                    continue; // keep searching for a file
                }

                //
                // Check the file against the hashes, we are only interested in positive matches at this stage
                //
                let now = Instant::now();
                match self.scan_file_against_hashes(&path) {
                    Ok(v) => {
                        if v.is_some() {
                            let v = v.unwrap();
                            let mut lock = self.scanning_info.lock().unwrap();
                            lock.scan_results.push(MatchedIOC {
                                hash: v.0,
                                file: v.1,
                            });
                        }
                    },
                    Err(e) => eprintln!("[-] Error scanning: {e}"),
                }

                let elapsed = now.elapsed().as_millis();

                time_map.insert(elapsed, path);
            }
        }

        let min_val = time_map.iter().next().unwrap();
        let max_val = time_map.iter().next_back().unwrap();

        println!("[i] Min: {:?}, Max: {:?}", min_val, max_val);

        *stop_clock.lock().unwrap() = true;

        Ok(State::Finished)

    }


    pub fn get_state(&self) -> State {
        let lock = self.state.lock().unwrap();
        lock.clone()
    }

}