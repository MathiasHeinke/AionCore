use std::io::{self, Read, Write};
use std::process::ExitCode;

use serde::{Deserialize, Serialize};

const SENTINEL: &str = "COMMAND_EVE_WINDOWS_PROCESS_IDENTITY_V1";
const MAX_REQUEST_BYTES: u64 = 65_537;
const MAX_BATCH: usize = 512;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeRequest {
    pids: Vec<u32>,
}

#[derive(Serialize)]
struct ProbeResponse {
    sentinel: &'static str,
    results: Vec<ProbeResult>,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum ProbeResult {
    Absent,
    Unknown,
    Observed {
        pid: u32,
        start_time_value: String,
        executable_path: String,
    },
}

pub(crate) fn run_process_identity_probe() -> ExitCode {
    let mut request_bytes = Vec::new();
    if io::stdin()
        .take(MAX_REQUEST_BYTES)
        .read_to_end(&mut request_bytes)
        .is_err()
        || request_bytes.len() >= MAX_REQUEST_BYTES as usize
    {
        return ExitCode::from(2);
    }
    let Ok(request) = serde_json::from_slice::<ProbeRequest>(&request_bytes) else {
        return ExitCode::from(2);
    };
    if request.pids.len() > MAX_BATCH || request.pids.contains(&0) {
        return ExitCode::from(2);
    }
    let mut unique = request.pids.clone();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != request.pids.len() {
        return ExitCode::from(2);
    }

    let response = ProbeResponse {
        sentinel: SENTINEL,
        results: request.pids.into_iter().map(probe_process_identity).collect(),
    };
    let Ok(payload) = serde_json::to_vec(&response) else {
        return ExitCode::from(1);
    };
    if io::stdout().write_all(&payload).is_err() {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

#[cfg(target_os = "windows")]
fn probe_process_identity(pid: u32) -> ProbeResult {
    use std::mem::MaybeUninit;
    use std::path::Path;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, GetLastError};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle == null_mut() {
        return if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
            ProbeResult::Absent
        } else {
            ProbeResult::Unknown
        };
    }
    let result = (|| {
        let mut creation = MaybeUninit::<FILETIME>::zeroed();
        let mut exit = MaybeUninit::<FILETIME>::zeroed();
        let mut kernel = MaybeUninit::<FILETIME>::zeroed();
        let mut user = MaybeUninit::<FILETIME>::zeroed();
        if unsafe {
            GetProcessTimes(
                handle,
                creation.as_mut_ptr(),
                exit.as_mut_ptr(),
                kernel.as_mut_ptr(),
                user.as_mut_ptr(),
            )
        } == 0
        {
            return ProbeResult::Unknown;
        }
        let creation = unsafe { creation.assume_init() };
        let mut path_buffer = vec![0_u16; 32_768];
        let mut path_len = path_buffer.len() as u32;
        if unsafe { QueryFullProcessImageNameW(handle, 0, path_buffer.as_mut_ptr(), &mut path_len) } == 0 {
            return ProbeResult::Unknown;
        }
        let Ok(executable_path) = String::from_utf16(&path_buffer[..path_len as usize]) else {
            return ProbeResult::Unknown;
        };
        if executable_path.is_empty() || !Path::new(&executable_path).is_absolute() {
            return ProbeResult::Unknown;
        }
        let start_time = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        if start_time == 0 {
            return ProbeResult::Unknown;
        }
        ProbeResult::Observed {
            pid,
            start_time_value: start_time.to_string(),
            executable_path,
        }
    })();
    unsafe {
        CloseHandle(handle);
    }
    result
}

#[cfg(not(target_os = "windows"))]
fn probe_process_identity(_pid: u32) -> ProbeResult {
    ProbeResult::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_schema_is_closed_and_content_free() {
        let payload = serde_json::to_value(ProbeResponse {
            sentinel: SENTINEL,
            results: vec![ProbeResult::Unknown, ProbeResult::Absent],
        })
        .unwrap();
        assert_eq!(
            payload,
            serde_json::json!({
                "sentinel": SENTINEL,
                "results": [{"state": "unknown"}, {"state": "absent"}],
            })
        );
    }
}
