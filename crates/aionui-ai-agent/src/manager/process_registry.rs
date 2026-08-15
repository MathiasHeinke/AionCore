use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use aionui_common::{AgentType, ErrorChain};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

#[cfg(unix)]
use std::fs::File;

use crate::capability::cli_process::CliAgentProcess;
use crate::error::AgentError;

pub(crate) const AGENT_PROCESS_REGISTRY_RELATIVE_PATH: &str = "runtime/agent-process-registry.json";
pub(crate) const AGENT_PROCESS_REGISTRY_EMERGENCY_RELATIVE_DIR: &str = "runtime/agent-process-registry-emergency";

const PROCESS_REGISTRY_VERSION: u32 = 2;
const PROCESS_TREE_TERMINATION_GRACE: Duration = Duration::from_millis(100);
const PROCESS_TREE_PROOF_TIMEOUT: Duration = Duration::from_secs(5);
const BACKGROUND_PROCESS_TREE_PROOF_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessStartTime {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessIdentity {
    pub platform: String,
    pub start_time: ProcessStartTime,
    pub parent_pid: u32,
    pub executable_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegisteredAgentProcess {
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_group_id: Option<u32>,
    pub conversation_id: String,
    pub agent_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_preview: Option<String>,
    pub registered_at_ms: u64,
    #[serde(default)]
    pub process_identity: Option<ProcessIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessRegistry {
    version: u32,
    processes: Vec<RegisteredAgentProcess>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmergencyProcessEvidence {
    version: u32,
    reason: String,
    process: RegisteredAgentProcess,
}

#[derive(Debug, Clone)]
pub(crate) struct RegisteredProcessLease {
    data_dir: PathBuf,
    pid: u32,
    registered_at_ms: u64,
    process_identity: Option<ProcessIdentity>,
}

impl RegisteredProcessLease {
    pub(crate) async fn retire_startup_failure(&self, process: &CliAgentProcess) -> Result<(), AgentError> {
        process
            .terminate_tree_and_prove_absence(PROCESS_TREE_TERMINATION_GRACE, PROCESS_TREE_PROOF_TIMEOUT)
            .await?;
        self.unregister_after_absence_proof(Ok(()))
    }

    fn unregister_after_absence_proof(&self, proof: Result<(), AgentError>) -> Result<(), AgentError> {
        proof?;
        unregister_agent_process_if_matching(
            &self.data_dir,
            self.pid,
            self.registered_at_ms,
            self.process_identity.as_ref(),
        )
        .map_err(|error| {
            AgentError::internal(format!(
                "Failed to retire proven-terminal process {} from runtime registry: {error}",
                self.pid
            ))
        })
    }
}

impl Default for ProcessRegistry {
    fn default() -> Self {
        Self {
            version: PROCESS_REGISTRY_VERSION,
            processes: Vec::new(),
        }
    }
}

static REGISTRY_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) fn agent_process_registry_path(data_dir: &Path) -> PathBuf {
    data_dir.join(AGENT_PROCESS_REGISTRY_RELATIVE_PATH)
}

pub(crate) fn agent_process_registry_emergency_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(AGENT_PROCESS_REGISTRY_EMERGENCY_RELATIVE_DIR)
}

fn platform_requires_proven_process_identity(platform: &str) -> bool {
    platform == "windows"
}

pub(crate) async fn register_session_process(
    data_dir: &Path,
    process: Arc<CliAgentProcess>,
    conversation_id: impl Into<String>,
    agent_type: AgentType,
    backend: Option<String>,
    command_preview: Option<String>,
) -> Result<RegisteredProcessLease, AgentError> {
    let pid = process.pid();
    let process_group_id = process.process_group_id();
    let process_identity = capture_process_identity_or_unproven(pid, process_group_id, capture_process_identity);
    let registered_at_ms = now_ms();
    let entry = RegisteredAgentProcess {
        pid,
        process_group_id,
        conversation_id: conversation_id.into(),
        agent_type: agent_type.serde_name().to_owned(),
        backend,
        command_preview,
        registered_at_ms,
        process_identity: process_identity.clone(),
    };

    let lease = RegisteredProcessLease {
        data_dir: data_dir.to_path_buf(),
        pid,
        registered_at_ms,
        process_identity: process_identity.clone(),
    };

    if process_identity.is_none() && platform_requires_proven_process_identity(std::env::consts::OS) {
        let cleanup = process
            .terminate_tree_and_prove_absence(PROCESS_TREE_TERMINATION_GRACE, PROCESS_TREE_PROOF_TIMEOUT)
            .await;
        return finish_process_registration(
            data_dir,
            &entry,
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "platform process identity is unavailable",
            )),
            cleanup,
        )
        .map(|()| lease);
    }

    let registration = register_agent_process(data_dir, entry.clone());
    if registration.is_err() {
        let cleanup = process
            .terminate_tree_and_prove_absence(PROCESS_TREE_TERMINATION_GRACE, PROCESS_TREE_PROOF_TIMEOUT)
            .await;
        finish_process_registration(data_dir, &entry, registration, cleanup)?;
    }

    let background_lease = lease.clone();
    tokio::spawn(async move {
        let _ = process.wait_for_exit().await;
        let proof = process.prove_tree_absent(BACKGROUND_PROCESS_TREE_PROOF_TIMEOUT).await;
        if let Err(e) = background_lease.unregister_after_absence_proof(proof) {
            warn!(
                pid,
                process_group_id = ?process_group_id,
                path = %agent_process_registry_path(&background_lease.data_dir).display(),
                error = %ErrorChain(&e),
                "Agent process tree absence or registry retirement remains unproven; retaining durable evidence"
            );
        }
    });

    Ok(lease)
}

fn register_agent_process(data_dir: &Path, entry: RegisteredAgentProcess) -> io::Result<()> {
    with_registry_lock(|| {
        let path = agent_process_registry_path(data_dir);
        let mut registry = read_registry_file(&path)?;
        registry.version = PROCESS_REGISTRY_VERSION;
        registry.processes.retain(|existing| existing.pid != entry.pid);
        registry.processes.push(entry);
        write_registry_file(&path, &registry)
    })
}

fn finish_process_registration(
    data_dir: &Path,
    entry: &RegisteredAgentProcess,
    registration: io::Result<()>,
    cleanup: Result<(), AgentError>,
) -> Result<(), AgentError> {
    match registration {
        Ok(()) => Ok(()),
        Err(registration_error) => {
            error!(
                pid = entry.pid,
                process_group_id = ?entry.process_group_id,
                error = %ErrorChain(&registration_error),
                "Failed to persist agent process registry entry; terminating spawned process tree"
            );
            if let Err(cleanup_error) = cleanup {
                let emergency = preserve_emergency_process_evidence(data_dir, entry);
                error!(
                    pid = entry.pid,
                    process_group_id = ?entry.process_group_id,
                    cleanup_error = %ErrorChain(&cleanup_error),
                    emergency_evidence = ?emergency.as_ref().ok(),
                    emergency_error = ?emergency.as_ref().err(),
                    "Spawned process tree cleanup is unproven; retaining emergency evidence"
                );
                return Err(AgentError::internal(format!(
                    "Failed to register agent process {} and process-tree cleanup is unproven{}",
                    entry.pid,
                    if emergency.is_ok() {
                        "; emergency evidence retained"
                    } else {
                        "; emergency evidence persistence also failed"
                    }
                )));
            }
            Err(AgentError::internal(format!(
                "Failed to register agent process {} in runtime registry: {registration_error}",
                entry.pid
            )))
        }
    }
}

fn unregister_agent_process_if_matching(
    data_dir: &Path,
    pid: u32,
    registered_at_ms: u64,
    process_identity: Option<&ProcessIdentity>,
) -> io::Result<()> {
    with_registry_lock(|| {
        let path = agent_process_registry_path(data_dir);
        let mut registry = read_registry_file(&path)?;
        let original_len = registry.processes.len();
        registry.processes.retain(|existing| {
            existing.pid != pid
                || existing.registered_at_ms != registered_at_ms
                || existing.process_identity.as_ref() != process_identity
        });
        if registry.processes.len() == original_len {
            return Ok(());
        }
        write_registry_file(&path, &registry)
    })
}

fn read_registry_file(path: &Path) -> io::Result<ProcessRegistry> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let registry: ProcessRegistry = serde_json::from_str(&contents).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to parse process registry {}: {e}", path.display()),
                )
            })?;
            if !matches!(registry.version, 1 | PROCESS_REGISTRY_VERSION) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Unsupported process registry version {} at {}",
                        registry.version,
                        path.display()
                    ),
                ));
            }
            Ok(registry)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(ProcessRegistry::default()),
        Err(e) => Err(e),
    }
}

fn write_registry_file(path: &Path, registry: &ProcessRegistry) -> io::Result<()> {
    let payload = serde_json::to_vec_pretty(registry).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to serialize process registry {}: {e}", path.display()),
        )
    })?;
    write_payload_atomic(path, &payload)
}

fn preserve_emergency_process_evidence(data_dir: &Path, process: &RegisteredAgentProcess) -> io::Result<PathBuf> {
    let directory = agent_process_registry_emergency_dir(data_dir);
    let path = directory.join(format!(
        "agent-process-{}-{}.json",
        process.registered_at_ms, process.pid
    ));
    let payload = serde_json::to_vec_pretty(&EmergencyProcessEvidence {
        version: 1,
        reason: "registry_write_failed_cleanup_unproven".to_owned(),
        process: process.clone(),
    })
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to serialize emergency process evidence: {error}"),
        )
    })?;
    write_payload_atomic(&path, &payload)?;
    Ok(path)
}

fn write_payload_atomic(path: &Path, payload: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension(format!("tmp-{}-{}", std::process::id(), now_ms()));

    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut tmp_file = options.open(&tmp_path)?;
        tmp_file.write_all(payload)?;
        tmp_file.sync_all()?;
        drop(tmp_file);

        replace_registry_file(&tmp_path, path)?;
        sync_parent_directory(path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

#[cfg(unix)]
fn replace_registry_file(tmp_path: &Path, path: &Path) -> io::Result<()> {
    fs::rename(tmp_path, path)
}

#[cfg(not(unix))]
fn replace_registry_file(tmp_path: &Path, path: &Path) -> io::Result<()> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(tmp_path, path)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn with_registry_lock<T>(f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let _guard = REGISTRY_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    f()
}

fn capture_process_identity_or_unproven(
    pid: u32,
    expected_process_group_id: Option<u32>,
    capture: impl FnOnce(u32, Option<u32>, u32) -> io::Result<Option<ProcessIdentity>>,
) -> Option<ProcessIdentity> {
    match capture(pid, expected_process_group_id, std::process::id()) {
        Ok(identity) => identity,
        Err(error) => {
            warn!(
                pid,
                error = %ErrorChain(&error),
                "Could not prove agent process birth identity; registry cleanup will remain fail-closed"
            );
            None
        }
    }
}

#[cfg(target_os = "macos")]
fn capture_process_identity(
    pid: u32,
    expected_process_group_id: Option<u32>,
    expected_parent_pid: u32,
) -> io::Result<Option<ProcessIdentity>> {
    use std::ffi::c_void;
    use std::mem::{MaybeUninit, size_of};

    let pid_i32 =
        i32::try_from(pid).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "process pid exceeds i32"))?;
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let info_size = i32::try_from(size_of::<libc::proc_bsdinfo>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "proc_bsdinfo size exceeds i32"))?;
    let read = unsafe {
        libc::proc_pidinfo(
            pid_i32,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast::<c_void>(),
            info_size,
        )
    };
    if read != info_size {
        return Err(io::Error::last_os_error());
    }
    let info = unsafe { info.assume_init() };
    if info.pbi_pid != pid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("proc_pidinfo returned pid {} for requested pid {pid}", info.pbi_pid),
        ));
    }
    if info.pbi_ppid != expected_parent_pid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "process parent changed during registration: expected {expected_parent_pid}, observed {}",
                info.pbi_ppid
            ),
        ));
    }
    if let Some(expected) = expected_process_group_id
        && info.pbi_pgid != expected
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "process group changed during registration: expected {expected}, observed {}",
                info.pbi_pgid
            ),
        ));
    }

    let mut path_buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let path_len = unsafe {
        libc::proc_pidpath(
            pid_i32,
            path_buffer.as_mut_ptr().cast::<c_void>(),
            path_buffer.len() as u32,
        )
    };
    if path_len <= 0 {
        return Err(io::Error::last_os_error());
    }
    let path_len = usize::try_from(path_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid proc_pidpath length"))?;
    let nul_index = path_buffer[..path_len.min(path_buffer.len())]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(path_len.min(path_buffer.len()));
    let executable_path = std::str::from_utf8(&path_buffer[..nul_index])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "process path is not UTF-8"))?
        .to_owned();
    if executable_path.is_empty() || !Path::new(&executable_path).is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "process path is empty or not absolute",
        ));
    }

    let start_time_us = info
        .pbi_start_tvsec
        .checked_mul(1_000_000)
        .and_then(|seconds| seconds.checked_add(info.pbi_start_tvusec))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process start time overflow"))?;

    Ok(Some(ProcessIdentity {
        platform: "darwin".to_owned(),
        start_time: ProcessStartTime {
            kind: "unix_epoch_us".to_owned(),
            value: start_time_us.to_string(),
        },
        parent_pid: info.pbi_ppid,
        executable_path,
    }))
}

#[cfg(target_os = "linux")]
fn capture_process_identity(
    pid: u32,
    expected_process_group_id: Option<u32>,
    expected_parent_pid: u32,
) -> io::Result<Option<ProcessIdentity>> {
    let stat_path = PathBuf::from(format!("/proc/{pid}/stat"));
    let stat = fs::read_to_string(&stat_path)?;
    let fields = parse_linux_proc_stat(&stat)?;
    if fields.parent_pid != expected_parent_pid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "process parent changed during registration: expected {expected_parent_pid}, observed {}",
                fields.parent_pid
            ),
        ));
    }
    if let Some(expected) = expected_process_group_id
        && fields.process_group_id != expected
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "process group changed during registration: expected {expected}, observed {}",
                fields.process_group_id
            ),
        ));
    }
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let boot_id = boot_id.trim();
    if boot_id.is_empty() || boot_id.contains(':') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux boot id is empty or malformed",
        ));
    }
    let executable_path = fs::read_link(format!("/proc/{pid}/exe"))?;
    let executable_path = executable_path
        .to_str()
        .filter(|path| !path.is_empty() && Path::new(path).is_absolute())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process path is not absolute UTF-8"))?
        .to_owned();

    Ok(Some(ProcessIdentity {
        platform: "linux".to_owned(),
        start_time: ProcessStartTime {
            kind: "linux_boot_ticks".to_owned(),
            value: format!("{boot_id}:{}", fields.start_time_ticks),
        },
        parent_pid: fields.parent_pid,
        executable_path,
    }))
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct LinuxProcStatIdentity {
    parent_pid: u32,
    process_group_id: u32,
    start_time_ticks: u64,
}

#[cfg(target_os = "linux")]
fn parse_linux_proc_stat(stat: &str) -> io::Result<LinuxProcStatIdentity> {
    let close_paren = stat
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Linux proc stat has no command terminator"))?;
    let mut fields = stat[close_paren + 1..].split_whitespace();
    let _state = fields
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Linux proc stat has no state"))?;
    let parent_pid = parse_linux_proc_field(fields.next(), "parent pid")?;
    let process_group_id = parse_linux_proc_field(fields.next(), "process group id")?;
    for _ in 0..16 {
        fields
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Linux proc stat is truncated"))?;
    }
    let start_time_ticks = fields
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Linux proc stat has no start time"))?
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Linux proc start time is not numeric"))?;
    Ok(LinuxProcStatIdentity {
        parent_pid,
        process_group_id,
        start_time_ticks,
    })
}

#[cfg(target_os = "linux")]
fn parse_linux_proc_field(value: Option<&str>, name: &str) -> io::Result<u32> {
    value
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("Linux proc stat has no {name}")))?
        .parse::<u32>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("Linux proc {name} is not numeric")))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn capture_process_identity(
    _pid: u32,
    _expected_process_group_id: Option<u32>,
    _expected_parent_pid: u32,
) -> io::Result<Option<ProcessIdentity>> {
    // `register_session_process` rejects and proves cleanup for this
    // unsupported producer before any v2 registry entry is published.
    Ok(None)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn is_pid_alive(pid: u32) -> bool {
        let result = unsafe { libc::kill(pid as i32, 0) };
        result == 0 || !matches!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH))
    }

    fn sample_identity() -> ProcessIdentity {
        ProcessIdentity {
            platform: "darwin".into(),
            start_time: ProcessStartTime {
                kind: "unix_epoch_us".into(),
                value: "1723728000123456".into(),
            },
            parent_pid: 7,
            executable_path: "/usr/bin/agent".into(),
        }
    }

    fn sample_entry(pid: u32) -> RegisteredAgentProcess {
        RegisteredAgentProcess {
            pid,
            process_group_id: Some(pid),
            conversation_id: format!("conv-{pid}"),
            agent_type: AgentType::Acp.serde_name().into(),
            backend: Some("codex".into()),
            command_preview: Some("codex-acp".into()),
            registered_at_ms: 123,
            process_identity: Some(sample_identity()),
        }
    }

    #[test]
    fn registry_path_is_scoped_under_runtime_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = agent_process_registry_path(dir.path());
        assert_eq!(path, dir.path().join("runtime/agent-process-registry.json"));
    }

    #[test]
    fn register_then_unregister_updates_registry_file() {
        let dir = tempfile::tempdir().unwrap();
        let entry = sample_entry(42);

        register_agent_process(dir.path(), entry.clone()).unwrap();
        let path = agent_process_registry_path(dir.path());
        let registry = read_registry_file(&path).unwrap();
        assert_eq!(registry.version, PROCESS_REGISTRY_VERSION);
        assert_eq!(registry.processes, vec![entry.clone()]);

        RegisteredProcessLease {
            data_dir: dir.path().to_path_buf(),
            pid: entry.pid,
            registered_at_ms: entry.registered_at_ms,
            process_identity: entry.process_identity.clone(),
        }
        .unregister_after_absence_proof(Ok(()))
        .unwrap();
        let registry = read_registry_file(&path).unwrap();
        assert!(registry.processes.is_empty());
    }

    #[test]
    fn unproven_tree_absence_retains_exact_registry_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let entry = sample_entry(42);
        register_agent_process(dir.path(), entry.clone()).unwrap();
        let lease = RegisteredProcessLease {
            data_dir: dir.path().to_path_buf(),
            pid: entry.pid,
            registered_at_ms: entry.registered_at_ms,
            process_identity: entry.process_identity.clone(),
        };

        assert!(
            lease
                .unregister_after_absence_proof(Err(AgentError::internal("fixture keeps descendant alive")))
                .is_err()
        );
        let registry = read_registry_file(&agent_process_registry_path(dir.path())).unwrap();
        assert_eq!(registry.processes, vec![entry]);
    }

    #[test]
    fn registering_v2_preserves_unproven_v1_entries_for_fail_closed_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let path = agent_process_registry_path(dir.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            r#"{
  "version": 1,
  "processes": [{
    "pid": 41,
    "process_group_id": 41,
    "conversation_id": "legacy",
    "agent_type": "acp",
    "registered_at_ms": 100
  }]
}"#,
        )
        .unwrap();

        register_agent_process(dir.path(), sample_entry(42)).unwrap();
        let registry = read_registry_file(&path).unwrap();
        assert_eq!(registry.version, PROCESS_REGISTRY_VERSION);
        assert_eq!(registry.processes.len(), 2);
        assert_eq!(registry.processes[0].pid, 41);
        assert_eq!(registry.processes[0].process_identity, None);
        assert_eq!(registry.processes[1].process_identity, Some(sample_identity()));
    }

    #[test]
    fn registry_identity_is_closed_and_unknown_fields_reject() {
        let dir = tempfile::tempdir().unwrap();
        let path = agent_process_registry_path(dir.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut raw = serde_json::to_value(ProcessRegistry {
            version: PROCESS_REGISTRY_VERSION,
            processes: vec![sample_entry(42)],
        })
        .unwrap();
        raw["processes"][0]["process_identity"]["untrusted"] = serde_json::json!(true);
        fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();

        let error = read_registry_file(&path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("unknown field `untrusted`"));
    }

    #[test]
    fn registry_replace_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = agent_process_registry_path(dir.path());
        register_agent_process(dir.path(), sample_entry(41)).unwrap();
        register_agent_process(dir.path(), sample_entry(42)).unwrap();

        let names = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, vec![path.file_name().unwrap()]);
        let registry = read_registry_file(&path).unwrap();
        assert_eq!(registry.processes.len(), 2);
    }

    #[test]
    fn delayed_unregister_cannot_remove_a_reused_pid_registration() {
        let dir = tempfile::tempdir().unwrap();
        let old_entry = sample_entry(42);
        register_agent_process(dir.path(), old_entry.clone()).unwrap();

        let mut replacement = sample_entry(42);
        replacement.registered_at_ms += 1;
        replacement.process_identity.as_mut().unwrap().start_time.value = "1723728001123456".into();
        register_agent_process(dir.path(), replacement.clone()).unwrap();

        unregister_agent_process_if_matching(
            dir.path(),
            old_entry.pid,
            old_entry.registered_at_ms,
            old_entry.process_identity.as_ref(),
        )
        .unwrap();
        let registry = read_registry_file(&agent_process_registry_path(dir.path())).unwrap();
        assert_eq!(registry.processes, vec![replacement.clone()]);

        unregister_agent_process_if_matching(
            dir.path(),
            replacement.pid,
            replacement.registered_at_ms,
            replacement.process_identity.as_ref(),
        )
        .unwrap();
        let registry = read_registry_file(&agent_process_registry_path(dir.path())).unwrap();
        assert!(registry.processes.is_empty());
    }

    #[test]
    fn capture_failure_degrades_to_an_explicitly_unproven_identity() {
        let identity = capture_process_identity_or_unproven(42, Some(42), |_pid, _pgid, _ppid| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixture denies process inspection",
            ))
        });
        assert_eq!(identity, None);
    }

    #[test]
    fn failed_registry_write_cleans_up_the_spawned_process_tree() {
        let dir = tempfile::tempdir().unwrap();
        let entry = sample_entry(42);
        let result = finish_process_registration(
            dir.path(),
            &entry,
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixture denies registry write",
            )),
            Ok(()),
        );

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("fixture denies registry write")
        );
        assert!(!agent_process_registry_emergency_dir(dir.path()).exists());
    }

    #[test]
    fn failed_registry_write_with_unproven_cleanup_persists_emergency_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let entry = sample_entry(42);
        let result = finish_process_registration(
            dir.path(),
            &entry,
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixture denies registry write",
            )),
            Err(AgentError::internal("fixture process group remains observable")),
        );

        assert!(result.unwrap_err().to_string().contains("emergency evidence retained"));
        let emergency_dir = agent_process_registry_emergency_dir(dir.path());
        let files = fs::read_dir(&emergency_dir)
            .unwrap()
            .map(|item| item.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(files.len(), 1);
        let evidence: EmergencyProcessEvidence = serde_json::from_slice(&fs::read(&files[0]).unwrap()).unwrap();
        assert_eq!(evidence.version, 1);
        assert_eq!(evidence.reason, "registry_write_failed_cleanup_unproven");
        assert_eq!(evidence.process, entry);
    }

    #[test]
    fn windows_requires_proven_identity_before_registry_publication() {
        assert!(platform_requires_proven_process_identity("windows"));
        assert!(!platform_requires_proven_process_identity("macos"));
        assert!(!platform_requires_proven_process_identity("linux"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn startup_retirement_keeps_evidence_until_leader_and_descendant_group_are_absent() {
        use aionui_common::CommandSpec;
        use tokio::time::timeout;

        let data_dir = tempfile::tempdir().unwrap();
        let marker = tempfile::NamedTempFile::new().unwrap();
        let marker_path = marker.path().to_string_lossy().into_owned();
        let process = Arc::new(
            CliAgentProcess::spawn_for_sdk(
                CommandSpec {
                    command: "sh".into(),
                    args: vec![
                        "-c".into(),
                        "sleep 60 & child=$!; printf '%s' \"$child\" > \"$1\"; exit 0".into(),
                        "registry-startup-retirement".into(),
                        marker_path,
                    ],
                    env: vec![],
                    cwd: None,
                },
                data_dir.path(),
            )
            .await
            .unwrap(),
        );
        let lease = register_session_process(
            data_dir.path(),
            Arc::clone(&process),
            "conv-startup-retirement",
            AgentType::Acp,
            Some("fixture".into()),
            Some("fixture launcher".into()),
        )
        .await
        .unwrap();
        timeout(Duration::from_secs(5), process.wait_for_exit())
            .await
            .expect("leader should exit");
        let child_pid = fs::read_to_string(marker.path())
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        assert!(is_pid_alive(child_pid));
        assert_eq!(
            read_registry_file(&agent_process_registry_path(data_dir.path()))
                .unwrap()
                .processes
                .len(),
            1
        );

        lease.retire_startup_failure(&process).await.unwrap();

        assert!(!is_pid_alive(child_pid));
        assert!(
            read_registry_file(&agent_process_registry_path(data_dir.path()))
                .unwrap()
                .processes
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn registry_write_failure_proves_spawned_group_absent_before_returning() {
        use aionui_common::CommandSpec;

        let data_dir = tempfile::tempdir().unwrap();
        let registry_path = agent_process_registry_path(data_dir.path());
        fs::create_dir_all(registry_path.parent().unwrap()).unwrap();
        fs::write(&registry_path, b"not-json").unwrap();
        let marker = tempfile::NamedTempFile::new().unwrap();
        let marker_path = marker.path().to_string_lossy().into_owned();
        let process = Arc::new(
            CliAgentProcess::spawn_for_sdk(
                CommandSpec {
                    command: "sh".into(),
                    args: vec![
                        "-c".into(),
                        "sleep 60 & child=$!; printf '%s' \"$child\" > \"$1\"; wait".into(),
                        "registry-write-failure".into(),
                        marker_path,
                    ],
                    env: vec![],
                    cwd: None,
                },
                data_dir.path(),
            )
            .await
            .unwrap(),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while fs::read_to_string(marker.path()).unwrap().trim().is_empty() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let child_pid = fs::read_to_string(marker.path())
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();

        let error = register_session_process(
            data_dir.path(),
            Arc::clone(&process),
            "conv-registry-failure",
            AgentType::Acp,
            Some("fixture".into()),
            Some("fixture launcher".into()),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("Failed to register agent process"));
        assert!(!is_pid_alive(child_pid));
        assert!(!agent_process_registry_emergency_dir(data_dir.path()).exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn captures_exact_macos_birth_parent_group_and_executable() {
        let pid = std::process::id();
        let process_group_id = unsafe { libc::getpgid(pid as i32) };
        let parent_pid = unsafe { libc::getppid() };
        assert!(process_group_id > 1);
        assert!(parent_pid > 0);

        let identity = capture_process_identity(pid, Some(process_group_id as u32), parent_pid as u32)
            .unwrap()
            .unwrap();
        assert_eq!(identity.platform, "darwin");
        assert_eq!(identity.start_time.kind, "unix_epoch_us");
        assert!(identity.start_time.value.parse::<u64>().unwrap() > 0);
        assert!(identity.parent_pid > 0);
        assert!(Path::new(&identity.executable_path).is_absolute());

        let mismatch = capture_process_identity(pid, Some(process_group_id as u32 + 1), parent_pid as u32);
        assert_eq!(mismatch.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_proc_stat_with_parenthesis_in_command() {
        let mut fields = vec!["S", "42", "123"];
        fields.extend(std::iter::repeat_n("0", 16));
        fields.push("98765");
        let stat = format!("123 (agent ) helper) {}", fields.join(" "));

        assert_eq!(
            parse_linux_proc_stat(&stat).unwrap(),
            LinuxProcStatIdentity {
                parent_pid: 42,
                process_group_id: 123,
                start_time_ticks: 98765,
            }
        );
    }
}
