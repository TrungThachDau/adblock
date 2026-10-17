use super::models::{SERVICE_DISPLAY_NAME, SERVICE_NAME};
use crate::divert;
use crate::ipc::{run_ipc_server, EngineState, EventBroadcaster};
use crate::rules::RuleStore;
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

define_windows_service!(ffi_service_main, my_service_main);

fn my_service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        error!("Service execution error: {:?}", e);
    }
}

pub fn dispatch_service() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

pub fn run_service(_arguments: Vec<OsString>) -> windows_service::Result<()> {
    let (stop_tx, stop_rx) = oneshot::channel();
    let stop_tx = Arc::new(parking_lot::Mutex::new(Some(stop_tx)));

    let stop_tx_clone = Arc::clone(&stop_tx);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(tx) = stop_tx_clone.lock().take() {
                    let _ = tx.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        windows_service::Error::Winapi(std::io::Error::new(std::io::ErrorKind::Other, e))
    })?;

    let state = Arc::new(EngineState::new());
    let rule_store = Arc::new(parking_lot::RwLock::new(RuleStore::new()));
    let broadcaster = EventBroadcaster::new(1024);

    // Try candidate rules files on disk
    for candidate in &[
        "spec/testdata/sample_list.txt",
        "spec/test-data/rules.txt",
        "C:\\ProgramData\\Adblock\\rules.txt",
    ] {
        if Path::new(candidate).exists() {
            let _ = rule_store.write().load_file(Path::new(candidate));
            break;
        }
    }

    // Spawn divert worker thread in background (fail-open if driver fails)
    let divert_state = Arc::clone(&state);
    let divert_rules = Arc::clone(&rule_store);
    let divert_broadcaster = broadcaster.clone();
    std::thread::Builder::new()
        .name("windivert-worker".into())
        .spawn(move || {
            divert::run_packet_loop(divert_state, divert_rules, divert_broadcaster);
        })
        .ok();

    // Run IPC server in background runtime until stop signal from SCM
    rt.block_on(async {
        let ipc_state = Arc::clone(&state);
        let ipc_rules = Arc::clone(&rule_store);
        let ipc_broadcaster = broadcaster.clone();

        tokio::spawn(async move {
            run_ipc_server(ipc_state, ipc_rules, ipc_broadcaster).await;
        });

        // Wait for SCM stop signal
        let _ = stop_rx.await;
        state.stop_requested.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

pub fn install_service() -> Result<(), Box<dyn std::error::Error>> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let current_exe = env::current_exe()?;
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: current_exe,
        launch_arguments: vec![OsString::from("--service")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    manager.create_service(&service_info, ServiceAccess::empty())?;
    println!("Service '{}' installed successfully.", SERVICE_NAME);
    Ok(())
}

pub fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE)?;
    let _ = service.stop();
    service.delete()?;
    println!("Service '{}' uninstalled successfully.", SERVICE_NAME);
    Ok(())
}

pub fn start_service() -> Result<(), Box<dyn std::error::Error>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    service.start::<&std::ffi::OsStr>(&[])?;
    println!("Service '{}' started.", SERVICE_NAME);
    Ok(())
}

pub fn stop_service() -> Result<(), Box<dyn std::error::Error>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP)?;
    service.stop()?;
    println!("Service '{}' stopped.", SERVICE_NAME);
    Ok(())
}

pub fn find_rules_file(args: &[String]) -> Option<PathBuf> {
    if let Some(index) = args.iter().position(|arg| arg == "--rules") {
        return args.get(index + 1).map(PathBuf::from);
    }

    let mut roots = Vec::new();
    if let Ok(exe) = env::current_exe() {
        roots.extend(exe.ancestors().map(Path::to_path_buf));
    }
    if let Ok(current_dir) = env::current_dir() {
        roots.extend(current_dir.ancestors().map(Path::to_path_buf));
    }

    for root in roots {
        for relative in ["spec/test-data/rules.txt", "spec/testdata/sample_list.txt"] {
            let candidate = root.join(relative);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    env::var_os("ProgramData")
        .map(PathBuf::from)
        .map(|path| path.join("Adblock/rules.txt"))
        .filter(|path| path.is_file())
}

pub fn run_console_mode(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    info!("==========================================");
    info!(" Adblock Engine (WinDivert 2.x) - Rust   ");
    info!(" Mode: Console (Debug / Interactive)      ");
    info!("==========================================");

    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        let state = Arc::new(EngineState::new());
        let rule_store = Arc::new(parking_lot::RwLock::new(RuleStore::new()));
        let broadcaster = EventBroadcaster::new(1024);

        if let Some(rules_path) = find_rules_file(args) {
            match rule_store.write().load_file(&rules_path) {
                Ok(loaded) => info!("Loaded {} rules from {}", loaded, rules_path.display()),
                Err(error) => error!("Failed to load rules from {}: {}", rules_path.display(), error),
            }
        } else {
            error!("No rules file found; place rules.txt in ProgramData\\Adblock or alongside spec\\test-data.");
        }

        // Spawn WinDivert packet filtering worker thread (fail-open)
        let divert_state = Arc::clone(&state);
        let divert_rules = Arc::clone(&rule_store);
        let divert_broadcaster = broadcaster.clone();
        std::thread::Builder::new()
            .name("windivert-worker".into())
            .spawn(move || {
                divert::run_packet_loop(divert_state, divert_rules, divert_broadcaster);
            })?;

        // Spawn periodic stats broadcast (every 2 seconds)
        let stats_state = Arc::clone(&state);
        let stats_broadcaster = broadcaster.clone();
        tokio::spawn(async move {
            let mut last_snapshot = stats_state.stats.snapshot();
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if stats_state.stop_requested.load(Ordering::Relaxed) {
                    break;
                }
                let current = stats_state.stats.snapshot();
                if current.dns_queries != last_snapshot.dns_queries
                    || current.tls_queries != last_snapshot.tls_queries
                    || current.quic_dropped != last_snapshot.quic_dropped
                {
                    stats_broadcaster.send_stats(current.clone());
                    last_snapshot = current;
                }
            }
        });

        // Run IPC server in background
        let ipc_state = Arc::clone(&state);
        let ipc_rules = Arc::clone(&rule_store);
        let ipc_broadcaster = broadcaster.clone();
        tokio::spawn(async move {
            run_ipc_server(ipc_state, ipc_rules, ipc_broadcaster).await;
        });

        info!("Engine is running and ready. Press Ctrl+C to shut down.");

        // Wait for Ctrl+C
        let _ = tokio::signal::ctrl_c().await;
        info!("Shutdown requested. Terminating packet loop...");
        state.stop_requested.store(true, Ordering::Relaxed);

        tokio::time::sleep(Duration::from_millis(500)).await;
        info!("Engine stopped.");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}
