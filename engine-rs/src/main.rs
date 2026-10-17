use adblock_engine_rs::service::{
    dispatch_service, install_service, run_console_mode, start_service, stop_service,
    uninstall_service,
};
use std::env;

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
        dispatch_service()?;
        return Ok(());
    }

    if !is_console_explicit {
        // Try starting via Windows SCM; if not launched by SCM, fallback to console mode
        match dispatch_service() {
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
