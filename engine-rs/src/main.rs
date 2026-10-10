#[macro_use]
extern crate windows_service;

use adblock_engine_rs::divert;
use adblock_engine_rs::ipc::{run_ipc_server, EngineState, EventBroadcaster};
use adblock_engine_rs::rules::RuleStore;
use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub const SERVICE_NAME: &str = "AdblockEngine";
pub const SERVICE_DISPLAY_NAME: &str = "Adblock Filtering Engine (WinDivert 2.x)";

define_windows_service!(ffi_service_main, my_service_main);

fn my_service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        error!("Service execution error: {:?}", e);
    }
}

fn run_service(_arguments: Vec<OsString>) -> windows_service::Result<()> {
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

fn install_service() -> Result<(), Box<dyn std::error::Error>> {
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

fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE)?;
    let _ = service.stop();
    service.delete()?;
    println!("Service '{}' uninstalled successfully.", SERVICE_NAME);
    Ok(())
}

fn start_service() -> Result<(), Box<dyn std::error::Error>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    service.start::<&std::ffi::OsStr>(&[])?;
    println!("Service '{}' started.", SERVICE_NAME);
    Ok(())
}

fn stop_service() -> Result<(), Box<dyn std::error::Error>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP)?;
    service.stop()?;
    println!("Service '{}' stopped.", SERVICE_NAME);
    Ok(())
}

fn run_console_mode(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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

        // Parse optional --rules argument
        let mut rules_path = String::from("../spec/test-data/rules.txt");
        let mut i = 1;
        while i < args.len() {
            if args[i] == "--rules" && i + 1 < args.len() {
                rules_path = args[i + 1].clone();
                i += 1;
            }
            i += 1;
        }

        if Path::new(&rules_path).exists() {
            if let Ok(loaded) = rule_store.write().load_file(Path::new(&rules_path)) {
                info!("Loaded {} rules from {}", loaded, rules_path);
            }
        } else if Path::new("spec/testdata/sample_list.txt").exists() {
            if let Ok(loaded) = rule_store.write().load_file(Path::new("spec/testdata/sample_list.txt")) {
                info!("Loaded {} rules from spec/testdata/sample_list.txt", loaded);
            }
        } else if Path::new("spec/test-data/rules.txt").exists() {
            if let Ok(loaded) = rule_store.write().load_file(Path::new("spec/test-data/rules.txt")) {
                info!("Loaded {} rules from spec/test-data/rules.txt", loaded);
            }
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|a| a == "--install") {
        return install_service();
    }
    if args.iter().any(|a| a == "--uninstall") {
        return uninstall_service();
    }
    if args.iter().any(|a| a == "--start") {
        return start_service();
    }
    if args.iter().any(|a| a == "--stop") {
        return stop_service();
    }

    let is_console_explicit = args.iter().any(|a| a == "--console" || a == "-c");
    let is_service_explicit = args.iter().any(|a| a == "--service");

    if is_service_explicit {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
        return Ok(());
    }

    if !is_console_explicit {
        // Try starting via Windows SCM; if not launched by SCM, fallback to console mode
        match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
            Ok(()) => return Ok(()),
            Err(windows_service::Error::Winapi(ref e)) if e.raw_os_error() == Some(1063) => {
                // Error 1063: ERROR_FAILED_SERVICE_CONTROLLER_CONNECT -> Interactive console execution
            }
            Err(e) => {
                eprintln!("SCM dispatcher note: {}. Falling back to console mode.", e);
            }
        }
    }

    // Run interactive console mode for debugging
    run_console_mode(&args)
}
