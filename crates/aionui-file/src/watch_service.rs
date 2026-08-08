use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::warn;

use crate::error::FileError;
use aionui_api_types::WebSocketMessage;
use aionui_realtime::EventBroadcaster;

use crate::types::{FileWatchEvent, OfficeFileAddedEvent};

/// Debounce duration for file watch events.
const DEBOUNCE_DURATION: Duration = Duration::from_millis(200);

/// Office file extensions to match (lowercase).
const OFFICE_EXTENSIONS: &[&str] = &["pptx", "docx", "xlsx"];

// ---------------------------------------------------------------------------
// Pure helpers (testable without I/O)
// ---------------------------------------------------------------------------

/// Returns `true` if the file path has an Office document extension.
fn is_office_file(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| {
        let lower = ext.to_ascii_lowercase();
        OFFICE_EXTENSIONS.contains(&lower.as_str())
    })
}

/// Returns `true` if the file NAME matches the generated onboarding step-screen
/// convention: `onboarding.html` or `onboarding-<step>.html`, case-insensitive,
/// where `<step>` is one or more of `[a-z0-9-]`.
///
/// This mirrors, decision for decision, the frontend's eligibility pattern
/// (`useAutoPreviewOfficeFiles.ts` `ONBOARDING_STEP_FILE_RE` =
/// `/(^|[\\/])onboarding(?:-[a-z0-9-]+)?\.html$/i`) — deliberately in BOTH
/// directions: anything this emits, the renderer accepts, and anything the
/// renderer would accept, this emits. A one-sided widening here would broadcast
/// events the renderer refuses (dead traffic plus a debounce entry per file); a
/// one-sided narrowing would silently kill the feature again, which is the
/// defect class this function exists to end. `onboarding-.html` is a NO in the
/// frontend regex (the optional group requires at least one step character
/// after the hyphen) and is therefore a NO here too.
///
/// Matched on `file_name()`, not the full path — the watcher hands us absolute
/// paths, and the convention names a file, not a location. Kept SEPARATE from
/// [`is_office_file`] on purpose: Office extensions and the HTML name pattern
/// are two different rules that only meet at the emitter's filter. No `regex`
/// dependency; this is plain string work.
fn is_onboarding_step_screen(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    let Some(stem) = name.strip_suffix(".html") else {
        return false;
    };
    if stem == "onboarding" {
        return true;
    }
    let Some(step) = stem.strip_prefix("onboarding-") else {
        return false;
    };
    !step.is_empty()
        && step
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Maps a `notify::EventKind` to a human-readable event type string.
/// Returns `None` for events that should be silently skipped (e.g. access).
fn event_kind_to_str(kind: &EventKind) -> Option<&'static str> {
    match kind {
        EventKind::Modify(_) => Some("change"),
        EventKind::Create(_) => Some("create"),
        EventKind::Remove(_) => Some("remove"),
        EventKind::Any | EventKind::Other => Some("change"),
        EventKind::Access(_) => None,
    }
}

/// Returns `true` if enough time has elapsed since the last event for `key`.
/// Updates the timestamp when returning `true`.
fn should_emit(debounce: &DashMap<String, Instant>, key: &str) -> bool {
    let now = Instant::now();
    if let Some(last) = debounce.get(key)
        && now.duration_since(*last) < DEBOUNCE_DURATION
    {
        return false;
    }
    debounce.insert(key.to_owned(), now);
    true
}

/// Drop the debounce entries a stopped office watcher accumulated.
///
/// Office debounce keys are `office:{absolute file path}` (see the office
/// watcher callback). Until this existed they were removed NOWHERE:
/// `stop_all_watches` deliberately retains them (office watchers may still be
/// running when single-file watches are cleared), and `stop_office_watch`
/// dropped only the watcher — so the map kept one entry per file ever seen, for
/// the whole process lifetime. The right place to clean is where an office
/// watcher actually ENDS, scoped to ITS workspace.
///
/// The scope check is separator-aware on purpose: stopping `/ws` must not drop
/// entries of a still-running watcher on `/ws2`. Entries under a NESTED,
/// still-running workspace (`/ws/sub` inside `/ws`) are dropped with the outer
/// scope; the only cost is that one later event may pass the 200ms debounce
/// once more, and the renderer's known-set dedupe absorbs exactly that.
fn drop_office_debounce_scope(debounce: &DashMap<String, Instant>, workspace_key: &str) {
    let root = format!("office:{workspace_key}");
    debounce.retain(|key, _| {
        let Some(rest) = key.strip_prefix(root.as_str()) else {
            return true;
        };
        !(rest.is_empty() || rest.starts_with(std::path::MAIN_SEPARATOR))
    });
}

// ---------------------------------------------------------------------------
// FileWatchService
// ---------------------------------------------------------------------------

/// File-system watcher implementing [`crate::traits::IFileWatchService`].
///
/// Internally uses the `notify` crate for cross-platform file-system events.
///
/// - **Single-file watches** share one [`RecommendedWatcher`] instance; each
///   path is registered via `watch()` with [`RecursiveMode::NonRecursive`].
/// - **Workspace Office watches** each get their own watcher running in
///   [`RecursiveMode::Recursive`], filtering creation events for
///   `.pptx`/`.docx`/`.xlsx` files plus generated onboarding step-screens
///   (`onboarding.html` / `onboarding-<step>.html`, see
///   [`is_onboarding_step_screen`]). Any other `.html` never emits.
pub struct FileWatchService {
    broadcaster: Arc<dyn EventBroadcaster>,
    /// Shared watcher for all single-file watches.
    file_watcher: Mutex<RecommendedWatcher>,
    /// Set of canonical paths being watched (shared with the event handler).
    watched_files: Arc<DashMap<String, ()>>,
    /// Per-workspace Office watchers, keyed by canonical workspace path.
    office_watchers: Mutex<HashMap<String, RecommendedWatcher>>,
    /// Debounce timestamps shared with watcher callbacks.
    debounce: Arc<DashMap<String, Instant>>,
}

impl FileWatchService {
    /// Create a new watch service backed by the platform's recommended watcher.
    pub fn new(broadcaster: Arc<dyn EventBroadcaster>) -> Result<Self, FileError> {
        let watched_files: Arc<DashMap<String, ()>> = Arc::new(DashMap::new());
        let debounce: Arc<DashMap<String, Instant>> = Arc::new(DashMap::new());

        let bc = broadcaster.clone();
        let wf = watched_files.clone();
        let db = debounce.clone();

        let file_watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            let event = match res {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, "file watcher error");
                    return;
                }
            };

            let event_type = match event_kind_to_str(&event.kind) {
                Some(t) => t,
                None => return,
            };

            for path in &event.paths {
                let path_str = path.to_string_lossy().into_owned();
                if !wf.contains_key(&path_str) {
                    continue;
                }
                if !should_emit(&db, &path_str) {
                    continue;
                }
                let payload = FileWatchEvent {
                    file_path: path_str,
                    event_type: event_type.to_owned(),
                };
                let json = serde_json::to_value(&payload).unwrap_or_default();
                bc.broadcast(WebSocketMessage::new("fileWatch.fileChanged", json));
            }
        })
        .map_err(|e| FileError::Internal(format!("failed to create file watcher: {e}")))?;

        Ok(Self {
            broadcaster,
            file_watcher: Mutex::new(file_watcher),
            watched_files,
            office_watchers: Mutex::new(HashMap::new()),
            debounce,
        })
    }
}

#[async_trait::async_trait]
impl crate::traits::IFileWatchService for FileWatchService {
    async fn start_watch(&self, file_path: &str) -> Result<(), FileError> {
        let canonical = std::fs::canonicalize(file_path)
            .map_err(|e| FileError::NotFound(format!("cannot resolve path {file_path}: {e}")))?;
        let key = canonical.to_string_lossy().into_owned();

        // Idempotent: already watching → no-op.
        if self.watched_files.contains_key(&key) {
            return Ok(());
        }

        let mut watcher = self
            .file_watcher
            .lock()
            .map_err(|e| FileError::Internal(format!("file watcher lock poisoned: {e}")))?;
        watcher
            .watch(&canonical, RecursiveMode::NonRecursive)
            .map_err(|e| FileError::Internal(format!("failed to watch {file_path}: {e}")))?;
        self.watched_files.insert(key, ());
        Ok(())
    }

    async fn stop_watch(&self, file_path: &str) -> Result<(), FileError> {
        let canonical = std::fs::canonicalize(file_path).unwrap_or_else(|_| file_path.into());
        let key = canonical.to_string_lossy().into_owned();

        if self.watched_files.remove(&key).is_none() {
            return Ok(());
        }

        let mut watcher = self
            .file_watcher
            .lock()
            .map_err(|e| FileError::Internal(format!("file watcher lock poisoned: {e}")))?;
        // Ignore unwatch errors — the file may have been deleted.
        let _ = watcher.unwatch(&canonical);
        self.debounce.remove(&key);
        Ok(())
    }

    async fn stop_all_watches(&self) -> Result<(), FileError> {
        let mut watcher = self
            .file_watcher
            .lock()
            .map_err(|e| FileError::Internal(format!("file watcher lock poisoned: {e}")))?;

        for entry in self.watched_files.iter() {
            let path = std::path::PathBuf::from(entry.key().as_str());
            let _ = watcher.unwatch(&path);
        }
        self.watched_files.clear();
        // Clean file-watch debounce entries only (keep office ones).
        self.debounce.retain(|k, _| k.starts_with("office:"));
        Ok(())
    }

    async fn start_office_watch(&self, workspace: &str) -> Result<(), FileError> {
        let canonical = std::fs::canonicalize(workspace)
            .map_err(|e| FileError::NotFound(format!("cannot resolve workspace {workspace}: {e}")))?;
        let key = canonical.to_string_lossy().into_owned();

        {
            let watchers = self
                .office_watchers
                .lock()
                .map_err(|e| FileError::Internal(format!("office watcher lock poisoned: {e}")))?;
            if watchers.contains_key(&key) {
                return Ok(());
            }
        }

        let bc = self.broadcaster.clone();
        let db = self.debounce.clone();
        let ws = key.clone();

        let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            let event = match res {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, "office watcher error");
                    return;
                }
            };

            if !matches!(event.kind, EventKind::Create(_)) {
                return;
            }

            for path in &event.paths {
                // Two rules meet here, and only here: Office extensions, or the
                // onboarding step-screen NAME pattern. Arbitrary `.html` still
                // never emits — the pattern, not the extension, is the gate.
                if !is_office_file(path) && !is_onboarding_step_screen(path) {
                    continue;
                }
                let path_str = path.to_string_lossy().into_owned();
                let debounce_key = format!("office:{path_str}");
                if !should_emit(&db, &debounce_key) {
                    continue;
                }
                let payload = OfficeFileAddedEvent {
                    file_path: path_str,
                    workspace: ws.clone(),
                };
                let json = serde_json::to_value(&payload).unwrap_or_default();
                bc.broadcast(WebSocketMessage::new("workspaceOfficeWatch.fileAdded", json));
            }
        })
        .map_err(|e| FileError::Internal(format!("failed to create office watcher: {e}")))?;

        watcher
            .watch(&canonical, RecursiveMode::Recursive)
            .map_err(|e| FileError::Internal(format!("failed to watch workspace {workspace}: {e}")))?;

        let mut watchers = self
            .office_watchers
            .lock()
            .map_err(|e| FileError::Internal(format!("office watcher lock poisoned: {e}")))?;
        watchers.insert(key, watcher);
        Ok(())
    }

    async fn stop_office_watch(&self, workspace: &str) -> Result<(), FileError> {
        let canonical = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.into());
        let key = canonical.to_string_lossy().into_owned();

        let mut watchers = self
            .office_watchers
            .lock()
            .map_err(|e| FileError::Internal(format!("office watcher lock poisoned: {e}")))?;
        // Dropping the watcher stops watching.
        watchers.remove(&key);
        // This is the one place an office watcher actually ENDS, so this is
        // where its debounce entries go too (see `drop_office_debounce_scope`).
        // Deliberately unconditional: a double-stop finds nothing to remove, and
        // a stop for a never-started workspace has no entries either way.
        drop_office_debounce_scope(&self.debounce, &key);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{AccessKind, CreateKind, ModifyKind, RemoveKind};
    use std::path::PathBuf;

    // -- is_office_file --

    #[test]
    fn office_file_pptx() {
        assert!(is_office_file(Path::new("/ws/slides.pptx")));
    }

    #[test]
    fn office_file_docx() {
        assert!(is_office_file(Path::new("/ws/report.docx")));
    }

    #[test]
    fn office_file_xlsx() {
        assert!(is_office_file(Path::new("/ws/data.xlsx")));
    }

    #[test]
    fn office_file_case_insensitive() {
        assert!(is_office_file(Path::new("/ws/FILE.PPTX")));
        assert!(is_office_file(Path::new("/ws/Doc.Docx")));
    }

    #[test]
    fn non_office_file_txt() {
        assert!(!is_office_file(Path::new("/ws/readme.txt")));
    }

    #[test]
    fn non_office_file_pdf() {
        assert!(!is_office_file(Path::new("/ws/paper.pdf")));
    }

    #[test]
    fn no_extension() {
        assert!(!is_office_file(Path::new("/ws/Makefile")));
    }

    // -- event_kind_to_str --

    #[test]
    fn modify_event_maps_to_change() {
        assert_eq!(
            event_kind_to_str(&EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Content))),
            Some("change")
        );
    }

    #[test]
    fn create_event_maps_to_create() {
        assert_eq!(event_kind_to_str(&EventKind::Create(CreateKind::File)), Some("create"));
    }

    #[test]
    fn remove_event_maps_to_remove() {
        assert_eq!(event_kind_to_str(&EventKind::Remove(RemoveKind::File)), Some("remove"));
    }

    #[test]
    fn any_event_maps_to_change() {
        assert_eq!(event_kind_to_str(&EventKind::Any), Some("change"));
    }

    #[test]
    fn other_event_maps_to_change() {
        assert_eq!(event_kind_to_str(&EventKind::Other), Some("change"));
    }

    #[test]
    fn access_event_is_skipped() {
        assert_eq!(event_kind_to_str(&EventKind::Access(AccessKind::Read)), None);
    }

    // -- should_emit (debounce) --

    #[test]
    fn first_emit_returns_true() {
        let db = DashMap::new();
        assert!(should_emit(&db, "/tmp/a.txt"));
    }

    #[test]
    fn immediate_second_emit_returns_false() {
        let db = DashMap::new();
        assert!(should_emit(&db, "/tmp/a.txt"));
        assert!(!should_emit(&db, "/tmp/a.txt"));
    }

    #[test]
    fn different_keys_are_independent() {
        let db = DashMap::new();
        assert!(should_emit(&db, "/tmp/a.txt"));
        assert!(should_emit(&db, "/tmp/b.txt"));
    }

    #[test]
    fn emit_after_debounce_duration() {
        let db = DashMap::new();
        assert!(should_emit(&db, "/tmp/a.txt"));

        // Simulate time passing by manually backdating the entry.
        db.insert(
            "/tmp/a.txt".to_owned(),
            Instant::now() - DEBOUNCE_DURATION - Duration::from_millis(1),
        );
        assert!(should_emit(&db, "/tmp/a.txt"));
    }

    // -- is_office_file edge cases --

    #[test]
    fn dotfile_with_office_ext() {
        assert!(is_office_file(Path::new("/ws/.hidden.docx")));
    }

    #[test]
    fn nested_path_office_file() {
        assert!(is_office_file(Path::new("/ws/deep/nested/dir/report.xlsx")));
    }

    #[test]
    fn empty_path() {
        assert!(!is_office_file(&PathBuf::new()));
    }

    // -- is_onboarding_step_screen --
    //
    // Every case below is the same verdict the frontend regex
    // (`ONBOARDING_STEP_FILE_RE`, useAutoPreviewOfficeFiles.ts) returns for the
    // same name. If one of these ever needs to change, change the frontend
    // pattern in the same commit — the two gates agreeing is the contract.

    #[test]
    fn onboarding_base_name_matches() {
        assert!(is_onboarding_step_screen(Path::new("/ws/onboarding.html")));
    }

    #[test]
    fn onboarding_step_name_matches() {
        assert!(is_onboarding_step_screen(Path::new("/ws/onboarding-schritt-2.html")));
    }

    #[test]
    fn onboarding_is_case_insensitive() {
        assert!(is_onboarding_step_screen(Path::new("/ws/Onboarding.HTML")));
        assert!(is_onboarding_step_screen(Path::new("/ws/ONBOARDING-STEP1.html")));
    }

    #[test]
    fn onboarding_needs_html_as_final_extension() {
        assert!(!is_onboarding_step_screen(Path::new("/ws/onboarding.html.txt")));
    }

    #[test]
    fn onboarding_prefix_must_start_the_name() {
        // No separator-free prefix: `mein-onboarding.html` is somebody's file,
        // not a generated step-screen.
        assert!(!is_onboarding_step_screen(Path::new("/ws/mein-onboarding.html")));
    }

    #[test]
    fn arbitrary_html_never_matches() {
        assert!(!is_onboarding_step_screen(Path::new("/ws/report.html")));
        assert!(!is_onboarding_step_screen(Path::new("/ws/index.htm")));
    }

    #[test]
    fn office_extensions_unaffected_by_the_new_rule() {
        // `notizen.docx` passes the OLD rule and fails the NEW one — the two
        // rules stay disjoint and only meet at the emitter's `||`.
        assert!(is_office_file(Path::new("/ws/notizen.docx")));
        assert!(!is_onboarding_step_screen(Path::new("/ws/notizen.docx")));
    }

    #[test]
    fn onboarding_trailing_hyphen_without_step_is_refused() {
        // Decided to mirror the frontend exactly: its optional group demands at
        // least one `[a-z0-9-]` AFTER the hyphen, so `onboarding-.html` is a NO
        // there — and a YES here would emit an event the renderer then refuses,
        // which is dead traffic by construction. `onboarding--.html` however IS
        // a YES on both sides (the step may itself contain hyphens).
        assert!(!is_onboarding_step_screen(Path::new("/ws/onboarding-.html")));
        assert!(is_onboarding_step_screen(Path::new("/ws/onboarding--.html")));
    }

    #[test]
    fn onboarding_step_charset_is_the_frontend_charset() {
        // `[a-z0-9-]` only — an underscore or a dot in the step is refused on
        // both sides.
        assert!(!is_onboarding_step_screen(Path::new("/ws/onboarding_x.html")));
        assert!(!is_onboarding_step_screen(Path::new("/ws/onboarding-a.b.html")));
        assert!(is_onboarding_step_screen(Path::new("/ws/onboarding-ollama.html")));
        assert!(is_onboarding_step_screen(Path::new("/ws/onboarding-3.html")));
    }

    // -- drop_office_debounce_scope --

    #[test]
    fn office_debounce_scope_removes_only_the_stopped_workspace() {
        let db = DashMap::new();
        let now = Instant::now();
        db.insert("office:/tmp/ws/a.docx".to_owned(), now);
        db.insert("office:/tmp/ws".to_owned(), now);
        db.insert("office:/tmp/ws2/b.docx".to_owned(), now);
        db.insert("/tmp/ws/plain-file-watch.txt".to_owned(), now);

        drop_office_debounce_scope(&db, "/tmp/ws");

        // The stopped workspace's entries (and its root key) are gone…
        assert!(!db.contains_key("office:/tmp/ws/a.docx"));
        assert!(!db.contains_key("office:/tmp/ws"));
        // …the sibling with the shared string prefix keeps its entry (separator
        // boundary, `/tmp/ws` vs `/tmp/ws2`)…
        assert!(db.contains_key("office:/tmp/ws2/b.docx"));
        // …and single-file watch keys are not office entries at all.
        assert!(db.contains_key("/tmp/ws/plain-file-watch.txt"));
    }

    /// A no-op broadcaster: the debounce tests below need a real service but no
    /// events.
    struct NullBroadcaster;

    impl aionui_realtime::EventBroadcaster for NullBroadcaster {
        fn broadcast(&self, _event: aionui_api_types::WebSocketMessage<serde_json::Value>) {}
    }

    #[tokio::test]
    async fn stopping_an_office_watcher_drops_its_debounce_entries_and_only_its_own() {
        let svc = FileWatchService::new(std::sync::Arc::new(NullBroadcaster)).unwrap();
        let ws_a = tempfile::tempdir().unwrap();
        let ws_b = tempfile::tempdir().unwrap();
        let key_a = std::fs::canonicalize(ws_a.path()).unwrap().to_string_lossy().into_owned();
        let key_b = std::fs::canonicalize(ws_b.path()).unwrap().to_string_lossy().into_owned();

        use crate::traits::IFileWatchService;
        svc.start_office_watch(ws_a.path().to_str().unwrap()).await.unwrap();
        svc.start_office_watch(ws_b.path().to_str().unwrap()).await.unwrap();

        // Seed the entries the watcher callbacks would have written (the same
        // `office:{path}` shape `should_emit` receives in the callback).
        let now = Instant::now();
        svc.debounce
            .insert(format!("office:{key_a}{}x.docx", std::path::MAIN_SEPARATOR), now);
        svc.debounce
            .insert(format!("office:{key_b}{}y.docx", std::path::MAIN_SEPARATOR), now);

        // While BOTH watchers run, nothing is removed.
        assert_eq!(svc.debounce.len(), 2);

        // Stopping A removes exactly A's entries; B — still running — keeps its
        // debounce state.
        svc.stop_office_watch(ws_a.path().to_str().unwrap()).await.unwrap();
        assert!(!svc.debounce.contains_key(&format!("office:{key_a}{}x.docx", std::path::MAIN_SEPARATOR)));
        assert!(svc.debounce.contains_key(&format!("office:{key_b}{}y.docx", std::path::MAIN_SEPARATOR)));
    }
}
