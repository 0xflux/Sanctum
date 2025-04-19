//! Antivirus.rs contains all functions associated with the antivirus UI in Tauri.
//! This module will handle state, requests, async, and events.

use serde_json::{to_value, Value};
use shared_std::file_scanner::{FileScannerState, ScanningLiveInfo};
use std::path::PathBuf;
use tauri::Emitter;

use crate::ipc::IpcClient;

#[tauri::command]
pub async fn scanner_check_page_state() -> Result<String, ()> {
    match IpcClient::send_ipc::<FileScannerState, Option<Value>>("scanner_check_page_state", None)
        .await
    {
        Ok(response) => {
            return Ok(format!("{:?}", response));
        }
        Err(e) => {
            eprintln!("[-] Error with IPC: {e}");
            return Ok("Inactive".to_string()); // todo proper error handling
        }
    };
}

/// Reports the scan statistics back to the UI
#[tauri::command]
pub async fn scanner_get_scan_stats() -> Result<String, ()> {
    match IpcClient::send_ipc::<ScanningLiveInfo, Option<Value>>("scanner_get_scan_stats", None)
        .await
    {
        Ok(response) => {
            let response = serde_json::to_string(&response).unwrap();
            return Ok(response);
        }
        Err(e) => {
            eprintln!("[-] Error with IPC: {e}");
            return Ok("Inactive".to_string()); // todo proper error handling
        }
    };
}

#[tauri::command]
pub async fn scanner_stop_scan() -> Result<(), ()> {
    match IpcClient::send_ipc::<(), Option<Value>>("scanner_cancel_scan", None).await {
        Ok(_) => (),
        Err(e) => {
            eprintln!("[-] Error with IPC for stop scan: {e}");
        }
    };

    Ok(())
}

#[tauri::command]
pub async fn scanner_start_folder_scan(
    file_path: String,
    app_handle: tauri::AppHandle,
) -> Result<String, ()> {
    let path = to_value(vec![PathBuf::from(file_path)]).unwrap();

    tokio::spawn(async move {
        // The result is wrapped inside of an enum from the filescanner module, so we need to first match on that
        // as DirectoryResult (since we are scanning a dir). The result should never be anything else for this scan
        // so if it is something has gone wrong with the internal wiring.

        match IpcClient::send_ipc::<FileScannerState, _>("scanner_start_folder_scan", Some(path))
            .await
        {
            Ok(response) => match response {
                FileScannerState::Finished => {
                    let scan_result = IpcClient::send_ipc::<ScanningLiveInfo, Option<Value>>(
                        "scanner_get_scan_stats",
                        None,
                    )
                    .await
                    .unwrap();

                    if scan_result.scan_results.is_empty() {
                        app_handle
                            .emit("folder_scan_no_results", "No malicious files found.")
                            .unwrap();
                    } else {
                        app_handle
                            .emit("folder_scan_malware_found", &scan_result)
                            .unwrap();
                    }
                }
                FileScannerState::FinishedWithError(v) => {
                    app_handle.emit("folder_scan_error", &v).unwrap();
                }
                FileScannerState::Scanning => app_handle
                    .emit(
                        "folder_scan_error",
                        "A scan is already in progress.".to_string(),
                    )
                    .unwrap(),
                _ => (),
            },
            Err(e) => {
                eprintln!("[-] Error with IPC: {e}");
            }
        };
    });

    // // todo some kind of feedback like 1/1 file scanned; but then same for the mass scanner, be good to show x files scanned, and time taken so far. Then completed time and
    // // total files after.

    // todo this shouldn't show in every case..?
    Ok(format!("Scan in progress..."))
}

#[tauri::command]
pub async fn scanner_start_quick_scan(app_handle: tauri::AppHandle) -> Result<String, ()> {
    tokio::spawn(async move {
        let paths = IpcClient::send_ipc::<Vec<PathBuf>, Option<Value>>(
            "settings_get_common_scan_areas",
            None,
        )
        .await
        .unwrap();

        // The result is wrapped inside of an enum from the filescanner module, so we need to first match on that
        // as DirectoryResult (since we are scanning a dir). The result should never be anything else for this scan
        // so if it is something has gone wrong with the internal wiring.
        match IpcClient::send_ipc::<FileScannerState, _>("scanner_start_folder_scan", Some(paths))
            .await
        {
            Ok(response) => match response {
                FileScannerState::Finished => {
                    let scan_result = IpcClient::send_ipc::<ScanningLiveInfo, Option<Value>>(
                        "scanner_get_scan_stats",
                        None,
                    )
                    .await
                    .unwrap();

                    if scan_result.scan_results.is_empty() {
                        app_handle
                            .emit("folder_scan_no_results", "No malicious files found.")
                            .unwrap();
                    } else {
                        app_handle
                            .emit("folder_scan_malware_found", &scan_result)
                            .unwrap();
                    }
                }
                FileScannerState::FinishedWithError(v) => {
                    app_handle.emit("folder_scan_error", &v).unwrap();
                }
                FileScannerState::Scanning => app_handle
                    .emit(
                        "folder_scan_error",
                        "A scan is already in progress.".to_string(),
                    )
                    .unwrap(),
                _ => (),
            },
            Err(e) => {
                eprintln!("[-] Error with IPC: {e}");
            }
        };
    });

    // // todo some kind of feedback like 1/1 file scanned; but then same for the mass scanner, be good to show x files scanned, and time taken so far. Then completed time and
    // // total files after.

    // todo this shouldn't show in every case..
    Ok("Scan in progress...".to_string())
}
