#![allow(dead_code)]

use shared_std::{driver_manager::DriverState, settings::SanctumSettings};
use std::{fs, path::PathBuf, sync::{Arc, Mutex}};
use crate::{driver_manager::SanctumDriverManager, settings::SanctumSettingsImpl, utils::{env::get_logged_in_username, log::{Log, LogLevel}}};
use crate::settings::get_setting_paths;

// todo - decommission UsermodeAPI and split any functionality into the modules.
pub struct UsermodeAPI {
    pub sanctum_settings: Arc<Mutex<SanctumSettings>>,
    pub log: Log, // for logging events
}

impl UsermodeAPI {

    /// Initialises the usermode engine, ensuring the driver file exists in the image directory.
    pub async fn new() -> Self {

        let log = Log::new();

        log.log(LogLevel::Info, "Sanctum usermode engine staring..");

        //
        // Config setup
        //

         // settings and environment
         let sanctum_settings = Arc::new(Mutex::new(SanctumSettings::load()));        

        UsermodeAPI{
            sanctum_settings,
            log,
        }
    }


    //
    // Settings
    // 

    pub fn settings_get_common_scan_areas(&self) -> Vec<PathBuf> {
        let lock = self.sanctum_settings.lock().unwrap();
        lock.common_scan_areas.clone()
    }

    pub fn settings_update_settings(&self, settings: SanctumSettings) {
        // change the live state
        let mut lock = self.sanctum_settings.lock().unwrap();
        *lock = settings.clone();

        // write the new file
        let settings_str = serde_json::to_string(&settings).unwrap();
        let path = get_setting_paths(&get_logged_in_username().unwrap()).1;
        fs::write(path, settings_str).unwrap();
    }

}