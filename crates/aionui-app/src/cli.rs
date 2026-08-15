//! CLI argument definitions for the `aioncore` binary.
//!
//! Kept separate from `main.rs` to isolate the clap surface (struct + enum +
//! attribute soup) from the runtime entry point. Visibility is `pub(crate)`
//! because only `main.rs` consumes it.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "aioncore", about = "AionUi Backend Server", version)]
pub(crate) struct Cli {
    /// Host address to listen on.
    #[arg(long, default_value_t = String::from(aionui_common::constants::DEFAULT_HOST))]
    pub host: String,

    /// Port number to listen on.
    #[arg(long, default_value_t = aionui_common::constants::DEFAULT_PORT)]
    pub port: u16,

    /// Data directory for database and file storage.
    #[arg(long, default_value = "data")]
    pub data_dir: PathBuf,

    /// Parent process ID used to terminate the backend when the desktop app dies.
    #[arg(long)]
    pub parent_pid: Option<u32>,

    /// Working directory for conversation workspaces.
    /// Falls back to AIONUI_WORK_DIR env, then to data-dir.
    #[arg(long)]
    pub work_dir: Option<PathBuf>,

    /// Host application version used for extension engine compatibility.
    #[arg(long, default_value_t = env!("CARGO_PKG_VERSION").to_string())]
    pub app_version: String,

    /// Run as an embedded loopback server using a per-launch capability.
    #[arg(long)]
    pub local: bool,

    /// Owner-only file containing the per-launch local capability.
    #[arg(long, requires = "local")]
    pub local_capability_file: Option<PathBuf>,

    /// Exact browser Origin allowed to call the local server. Repeatable.
    /// Defaults to `null`, the serialized Origin of the packaged file:// UI.
    #[arg(long, requires = "local")]
    pub local_origin: Vec<String>,

    /// Additional filesystem root exposed to file and office APIs. Repeatable.
    #[arg(long)]
    pub allowed_root: Vec<PathBuf>,

    /// Directory for log files. Defaults to {data-dir}/logs/.
    #[arg(long)]
    pub log_dir: Option<PathBuf>,

    /// Log level filter (e.g. "info", "debug", "info,aionui_mcp=trace").
    #[arg(long)]
    pub log_level: Option<String>,

    /// Managed runtime resource source selection.
    #[arg(long, value_enum, default_value_t = ManagedResourcesModeArg::Download)]
    pub managed_resources_mode: ManagedResourcesModeArg,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedResourcesModeArg {
    Bundled,
    Download,
}

impl From<ManagedResourcesModeArg> for aionui_runtime::ManagedResourcesMode {
    fn from(value: ManagedResourcesModeArg) -> Self {
        match value {
            ManagedResourcesModeArg::Bundled => Self::Bundled,
            ManagedResourcesModeArg::Download => Self::Download,
        }
    }
}

// `Mcp` prefix is load-bearing on Mcp* variants — clap derives kebab-case
// subcommand names (`mcp-bridge`, `mcp-guide-stdio`, `mcp-team-stdio`)
// that external callers (ACP agent CLI, team MCP bridge spec) depend on
// verbatim.
#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Stdio ↔ TCP bridge for the team MCP server (spawned by the ACP agent CLI).
    McpBridge,
    /// MCP stdio server for team-guide tools (spawned by the ACP agent CLI).
    McpGuideStdio,
    /// MCP stdio server for team tools (spawned by the ACP agent CLI).
    McpTeamStdio,
    /// Self-check: hydrate the agent registry, probe every CLI on `$PATH`,
    /// and print a per-agent availability table. Useful when the user
    /// reports "no agent works" — running this from the same shell the
    /// app launched from confirms whether each backend is detectable
    /// before involving server logs.
    Doctor,
    /// Prepare current-platform managed runtime resources under a bundle output root.
    PrepareManagedResources(PrepareManagedResourcesArgs),
    /// Native, bounded process-birth probe used by the signed desktop cleanup owner.
    ProcessIdentityProbe,
}

impl Command {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::McpBridge => "mcp-bridge",
            Self::McpGuideStdio => "mcp-guide-stdio",
            Self::McpTeamStdio => "mcp-team-stdio",
            Self::Doctor => "doctor",
            Self::PrepareManagedResources(_) => "prepare-managed-resources",
            Self::ProcessIdentityProbe => "process-identity-probe",
        }
    }

    pub(crate) fn need_runtime(&self) -> bool {
        matches!(self, Self::Doctor | Self::PrepareManagedResources(_))
    }
}

#[derive(clap::Args, Debug, Clone)]
pub(crate) struct PrepareManagedResourcesArgs {
    /// Bundle output root. Aioncore writes the managed resources under
    /// `<bundle-out>/{node,acp}/...` for packaging.
    #[arg(long)]
    pub bundle_out: PathBuf,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;
    use clap::error::ErrorKind;

    use super::{Cli, Command, ManagedResourcesModeArg, PrepareManagedResourcesArgs};

    #[test]
    fn long_version_flag_uses_workspace_package_version() {
        let result = Cli::try_parse_from(["aioncore", "--version"]);
        let err = match result {
            Ok(_) => panic!("expected --version to exit through clap DisplayVersion"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), ErrorKind::DisplayVersion);
        let rendered = err.to_string();
        assert!(
            rendered.contains("aioncore"),
            "version output should contain binary name, got: {rendered:?}"
        );
        assert!(
            rendered.contains(env!("CARGO_PKG_VERSION")),
            "version output should contain package version {}, got: {rendered:?}",
            env!("CARGO_PKG_VERSION")
        );
    }

    #[test]
    fn short_version_flag_uses_workspace_package_version() {
        let result = Cli::try_parse_from(["aioncore", "-V"]);
        let err = match result {
            Ok(_) => panic!("expected -V to exit through clap DisplayVersion"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), ErrorKind::DisplayVersion);
        let rendered = err.to_string();
        assert!(
            rendered.contains("aioncore"),
            "version output should contain binary name, got: {rendered:?}"
        );
        assert!(
            rendered.contains(env!("CARGO_PKG_VERSION")),
            "version output should contain package version {}, got: {rendered:?}",
            env!("CARGO_PKG_VERSION")
        );
    }

    #[test]
    fn prepare_managed_resources_accepts_bundle_out() {
        let cli = Cli::parse_from([
            "aioncore",
            "prepare-managed-resources",
            "--bundle-out",
            "/tmp/aioncore-bundle",
        ]);

        match cli.command {
            Some(Command::PrepareManagedResources(args)) => {
                assert_eq!(args.bundle_out, std::path::Path::new("/tmp/aioncore-bundle"));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn process_identity_probe_is_a_runtime_free_closed_subcommand() {
        let cli = Cli::parse_from(["aioncore", "process-identity-probe"]);
        let Some(command @ Command::ProcessIdentityProbe) = cli.command else {
            panic!("expected process-identity-probe subcommand");
        };
        assert_eq!(command.as_str(), "process-identity-probe");
        assert!(!command.need_runtime());
    }

    #[test]
    fn managed_resources_mode_defaults_to_download() {
        let cli = Cli::parse_from(["aioncore"]);
        assert_eq!(cli.managed_resources_mode, ManagedResourcesModeArg::Download);
    }

    #[test]
    fn managed_resources_mode_accepts_download() {
        let cli = Cli::parse_from(["aioncore", "--managed-resources-mode", "download"]);
        assert_eq!(cli.managed_resources_mode, ManagedResourcesModeArg::Download);
    }

    #[test]
    fn local_capability_and_origin_require_local_mode() {
        let capability_error = match Cli::try_parse_from(["aioncore", "--local-capability-file", "/tmp/capability"]) {
            Ok(_) => panic!("local capability file should require --local"),
            Err(error) => error,
        };
        assert_eq!(capability_error.kind(), clap::error::ErrorKind::MissingRequiredArgument);

        let origin_error = match Cli::try_parse_from(["aioncore", "--local-origin", "null"]) {
            Ok(_) => panic!("local origin should require --local"),
            Err(error) => error,
        };
        assert_eq!(origin_error.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn local_security_flags_are_repeatable() {
        let cli = Cli::parse_from([
            "aioncore",
            "--local",
            "--local-capability-file",
            "/tmp/capability",
            "--local-origin",
            "null",
            "--local-origin",
            "http://localhost:5173",
            "--allowed-root",
            "/tmp/workspace-a",
            "--allowed-root",
            "/tmp/workspace-b",
        ]);

        assert_eq!(cli.local_origin, ["null", "http://localhost:5173"]);
        assert_eq!(cli.allowed_root.len(), 2);
    }

    #[test]
    fn parent_pid_accepts_positive_integer() {
        let cli = Cli::parse_from(["aioncore", "--parent-pid", "4242"]);
        assert_eq!(cli.parent_pid, Some(4242));
    }

    #[test]
    fn command_as_str_returns_clap_subcommand_names() {
        let prepare_args = PrepareManagedResourcesArgs {
            bundle_out: PathBuf::from("/tmp/aioncore-bundle"),
        };

        let cases = [
            (Command::McpBridge, "mcp-bridge"),
            (Command::McpGuideStdio, "mcp-guide-stdio"),
            (Command::McpTeamStdio, "mcp-team-stdio"),
            (Command::Doctor, "doctor"),
            (
                Command::PrepareManagedResources(prepare_args),
                "prepare-managed-resources",
            ),
        ];

        for (command, expected) in cases {
            assert_eq!(command.as_str(), expected);
        }
    }

    #[test]
    fn prepare_managed_resources_requires_bundle_out() {
        let err = match Cli::try_parse_from(["aioncore", "prepare-managed-resources"]) {
            Ok(_) => panic!("prepare-managed-resources should require --bundle-out"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }
}
