//! Constant literals (or types not part of the Windows API) for use across the project

use core::fmt::Display;

// these should end with the same name
pub static NT_DEVICE_NAME: &str = "\\Device\\SanctumEDR";
pub static DOS_DEVICE_NAME: &str = "\\??\\SanctumEDR";
pub static DRIVER_UM_NAME: &str = "\\\\.\\SanctumEDR"; // \\.\ sets device namespace

pub static SYS_INSTALL_RELATIVE_LOC: &str = "sanctum.sys";
pub static SVC_NAME: &str = "Sanctum";

//
// version info
//
pub struct SanctumVersion<'a> {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub name: &'a str,
}

pub static RELEASE_NAME: &str = "Sanctify";
pub static VERSION_DRIVER: SanctumVersion = SanctumVersion { major: 0, minor: 0, patch: 1, name: "Light’s Resolve" };
pub static VERSION_CLIENT: SanctumVersion = SanctumVersion { major: 0, minor: 0, patch: 1, name: "Light’s Resolve"};

impl<'a> Display for SanctumVersion<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{} - {}", self.major, self.minor, self.patch, self.name)
    }
}

//
// Usermode specific constants
//
pub static SANC_SYS_FILE_LOCATION: &str = "C:\\Users\\flux\\AppData\\Roaming\\Sanctum\\sanctum.sys";
pub static IOC_LIST_LOCATION: &str = "C:\\Users\\flux\\git\\sanctum\\ioc_list.txt";
