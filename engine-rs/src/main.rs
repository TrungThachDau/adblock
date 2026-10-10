use adblock_engine_rs::divert;
use adblock_engine_rs::ipc::{run_ipc_server, EngineState, EventBroadcaster};
use adblock_engine_rs::rules::RuleStore;
use std::env;

use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing default subscriber");

    info!("==========================================");
    info!(" Adblock Engine (WinDivert 2.x) - Rust   ");
    info!("==========================================");

    let state = Arc::new(EngineState::new());
    let rule_store = Arc::new(parking_lot::RwLock::new(RuleStore::new()));
    let broadcaster = EventBroadcaster::new(1024);

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let mut rules_path = String::from("../spec/test-data/rules.txt");

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--rules" && i + 1 < args.len() {
            rules_path = args[i + 1].clone();
            i += 1;
        }
        i += 1;
    }

    // Try loading initial rules if file exists
    if Path::new(&rules_path).exists() {
        let loaded = rule_store.write().load_file(Path::new(&rules_path))?;
        info!("Loaded {} rules from {}", loaded, rules_path);
    } else if Path::new("spec/test-data/rules.txt").exists() {
        let loaded = rule_store.write().load_file(Path::new("spec/test-data/rules.txt"))?;
        info!("Loaded {} rules from spec/test-data/rules.txt", loaded);
    } else {
        info!("No initial rules file found. Starting with empty ruleset.");
    }

    // Spawn WinDivert packet filtering worker thread
    let divert_state = Arc::clone(&state);
    let divert_rules = Arc::clone(&rule_store);
    let divert_broadcaster = broadcaster.clone();
    std::thread::Builder::new()
        .name("windivert-worker".into())
        .spawn(move || {
            divert::run_packet_loop(divert_state, divert_rules, divert_broadcaster);
        })?;

    // Spawn periodic stats update broadcaster (every 2 seconds)
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
    tokio::signal::ctrl_c().await?;
    info!("Shutdown requested. Terminating packet divert loop...");
    state.stop_requested.store(true, Ordering::Relaxed);

    tokio::time::sleep(Duration::from_millis(500)).await;
    info!("Engine stopped.");
    Ok(())
}
