//! Bootstrap layers shared by non-MCP subcommands.

use std::io::Read;
use std::path::Path;
use std::time::Instant;

use tracing::info;

use aionui_app::AppConfig;
use aionui_auth::LocalCapabilityVerifier;
use aionui_db::Database;

use crate::cli::Cli;

use super::builtin_skills::materialize_builtin_skills;
use super::tracing_init::{LogGuards, init_tracing};
use super::work_dir::resolve_work_dir;
use super::{BootstrapError, BootstrapErrorCode};

/// Resolved environment needed by all non-MCP subcommands.
pub struct ServerEnvironment {
    /// Must be held alive for the process lifetime to flush log buffers.
    pub _log_guard: LogGuards,
    pub config: AppConfig,
}

/// Layer 1: Logging + config resolution.
///
/// Cheap, synchronous, no IO beyond creating the log directory.
/// All subcommands that need logging and config should call this first.
pub fn init_environment(cli: &Cli, merged_path: &str) -> Result<ServerEnvironment, BootstrapError> {
    let log_dir = cli.log_dir.clone().unwrap_or_else(|| cli.data_dir.join("logs"));
    let log_guard = init_tracing(&log_dir, cli.log_level.as_deref())?;

    info!(
        path_segments = merged_path.split(if cfg!(windows) { ';' } else { ':' }).count(),
        path_len = merged_path.len(),
        "startup: PATH ready"
    );

    let work_dir = resolve_work_dir(cli.work_dir.clone(), &cli.data_dir);

    // SAFETY: called before any service initialization; no concurrent reads.
    unsafe {
        std::env::set_var("AIONUI_WORK_DIR", &work_dir);
    }

    let local_capability = resolve_local_capability(cli)?;
    let local_origins = resolve_local_origins(cli)?;

    let config = AppConfig {
        host: cli.host.clone(),
        port: cli.port,
        data_dir: cli.data_dir.clone(),
        work_dir,
        app_version: cli.app_version.clone(),
        local: cli.local,
        local_capability,
        local_origins,
        allowed_roots: cli.allowed_root.clone(),
    };
    info!(
        "Running in {} mode — authentication is {}",
        if config.local { "local" } else { "remote" },
        if config.local { "capability-gated" } else { "JWT-gated" }
    );

    Ok(ServerEnvironment {
        _log_guard: log_guard,
        config,
    })
}

fn resolve_local_capability(cli: &Cli) -> Result<Option<LocalCapabilityVerifier>, BootstrapError> {
    if !cli.local {
        return Ok(None);
    }

    let path = cli.local_capability_file.as_deref().ok_or_else(|| {
        BootstrapError::new(
            BootstrapErrorCode::ConfigInvalid,
            "config.local_capability",
            "local mode requires an owner-only capability file",
        )
    })?;
    let mut file = open_local_capability_file(path)?;
    let mut raw = String::new();
    file.read_to_string(&mut raw).map_err(|error| {
        BootstrapError::new(
            BootstrapErrorCode::ConfigInvalid,
            "config.local_capability",
            "failed to read local capability file",
        )
        .with_source(error)
    })?;
    let capability = raw.trim_end_matches(['\r', '\n']);
    let verifier = LocalCapabilityVerifier::new(capability).map_err(|error| {
        BootstrapError::new(
            BootstrapErrorCode::ConfigInvalid,
            "config.local_capability",
            "local capability file is malformed",
        )
        .with_source(error)
    })?;
    Ok(Some(verifier))
}

fn open_local_capability_file(path: &Path) -> Result<std::fs::File, BootstrapError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|error| {
        BootstrapError::new(
            BootstrapErrorCode::ConfigInvalid,
            "config.local_capability",
            "failed to open local capability file",
        )
        .with_source(error)
    })?;
    let metadata = file.metadata().map_err(|error| {
        BootstrapError::new(
            BootstrapErrorCode::ConfigInvalid,
            "config.local_capability",
            "failed to inspect local capability file",
        )
        .with_source(error)
    })?;
    if !metadata.is_file() {
        return Err(BootstrapError::new(
            BootstrapErrorCode::ConfigInvalid,
            "config.local_capability",
            "local capability path must be a regular file",
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.mode() & 0o777 != 0o600 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(BootstrapError::new(
                BootstrapErrorCode::ConfigInvalid,
                "config.local_capability",
                "local capability file must be owned by this user with mode 0600",
            ));
        }
    }

    if !(32..=514).contains(&metadata.len()) {
        return Err(BootstrapError::new(
            BootstrapErrorCode::ConfigInvalid,
            "config.local_capability",
            "local capability file has an invalid size",
        ));
    }

    Ok(file)
}

fn resolve_local_origins(cli: &Cli) -> Result<Vec<String>, BootstrapError> {
    if !cli.local {
        return Ok(Vec::new());
    }
    let origins = if cli.local_origin.is_empty() {
        vec!["null".to_owned()]
    } else {
        cli.local_origin.clone()
    };
    if origins.iter().any(|origin| !is_allowed_local_origin(origin)) {
        return Err(BootstrapError::new(
            BootstrapErrorCode::ConfigInvalid,
            "config.local_origin",
            "local origin must be null or an exact loopback HTTP origin",
        ));
    }
    Ok(origins)
}

fn is_allowed_local_origin(origin: &str) -> bool {
    if origin == "null" {
        return true;
    }
    let Ok(url) = reqwest::Url::parse(origin) else {
        return false;
    };
    let loopback_host = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]" | "::1"));
    matches!(url.scheme(), "http" | "https")
        && loopback_host
        && url.port().is_some()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

/// Layer 2: Materialize builtin skills + initialize the database.
///
/// Requires only `data_dir`. Subcommands that need persistent state
/// (database, skill files) should call this after `init_environment`.
pub async fn init_data_layer(config: &AppConfig) -> Result<Database, BootstrapError> {
    let boot = Instant::now();

    materialize_builtin_skills(&config.data_dir).await.map_err(|e| {
        BootstrapError::new(
            BootstrapErrorCode::DataInitFailed,
            "data.builtin_skills",
            "failed to initialize application data",
        )
        .with_source(e)
        .with_field("dataDir", config.data_dir.display().to_string())
    })?;
    info!(
        elapsed_ms = boot.elapsed().as_millis(),
        "startup: builtin skills materialized"
    );

    let db_path = config.database_path();
    aionui_db::maybe_copy_legacy_database(&db_path).map_err(|e| {
        BootstrapError::new(
            BootstrapErrorCode::DataInitFailed,
            "data.legacy_db",
            "failed to initialize application data",
        )
        .with_source(e)
        .with_field("databasePath", db_path.display().to_string())
    })?;
    info!("Initializing database at {}", db_path.display());
    let database = aionui_db::init_database_staged(&db_path).await.map_err(|e| {
        let stage = e.stage();
        BootstrapError::new(
            BootstrapErrorCode::DataInitFailed,
            stage,
            "failed to initialize application data",
        )
        .with_source(e.into_source())
        .with_field("databasePath", db_path.display().to_string())
    })?;
    info!(elapsed_ms = boot.elapsed().as_millis(), "startup: database initialized");

    Ok(database)
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use std::os::unix::fs::PermissionsExt;

    use crate::cli::Cli;

    use super::*;

    #[test]
    fn database_stage_comes_from_db_boundary_error() {
        let err = aionui_db::DatabaseInitError::new(
            "database.migration",
            aionui_db::DbError::Migration(sqlx::migrate::MigrateError::VersionMismatch(42)),
        );

        assert_eq!(err.stage(), "database.migration");
    }

    #[test]
    fn database_schema_repair_stage_comes_from_db_boundary_error() {
        let err = aionui_db::DatabaseInitError::new(
            "database.schema_repair",
            aionui_db::DbError::Init("repair failed".into()),
        );

        assert_eq!(err.stage(), "database.schema_repair");
    }

    #[test]
    fn local_mode_requires_owner_only_capability_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("capability");
        std::fs::write(
            &path,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let cli = Cli::parse_from(["aioncore", "--local", "--local-capability-file", path.to_str().unwrap()]);

        let verifier = resolve_local_capability(&cli).unwrap().unwrap();
        assert!(verifier.verify("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn local_mode_rejects_group_readable_capability_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("capability");
        std::fs::write(
            &path,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let cli = Cli::parse_from(["aioncore", "--local", "--local-capability-file", path.to_str().unwrap()]);

        #[cfg(unix)]
        assert!(resolve_local_capability(&cli).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_mode_rejects_symlinked_capability_file() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("capability-target");
        let link = temp.path().join("capability-link");
        std::fs::write(
            &target,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &link).unwrap();
        let cli = Cli::parse_from(["aioncore", "--local", "--local-capability-file", link.to_str().unwrap()]);

        assert!(resolve_local_capability(&cli).is_err());
    }

    #[test]
    fn local_origins_are_exact_and_loopback_only() {
        assert!(is_allowed_local_origin("null"));
        assert!(is_allowed_local_origin("http://localhost:5173"));
        assert!(is_allowed_local_origin("https://127.0.0.1:4443"));
        assert!(!is_allowed_local_origin("*"));
        assert!(!is_allowed_local_origin("https://example.com"));
        assert!(!is_allowed_local_origin("http://localhost:5173/path"));
    }
}
