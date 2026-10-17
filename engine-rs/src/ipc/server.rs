use super::handlers::handle_request_line;
use super::models::{EngineState, EventBroadcaster, PIPE_NAME_APP, PIPE_NAME_LEGACY};
use crate::rules::SharedRuleStore;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::windows::named_pipe::ServerOptions;
use tracing::{error, info, warn};

pub async fn run_ipc_server(
    state: Arc<EngineState>,
    rules: SharedRuleStore,
    broadcaster: EventBroadcaster,
) {
    info!("Starting IPC server on Named Pipes: {} and {}", PIPE_NAME_APP, PIPE_NAME_LEGACY);

    let state1 = Arc::clone(&state);
    let rules1 = Arc::clone(&rules);
    let broadcaster1 = broadcaster.clone();
    tokio::spawn(async move {
        listen_pipe(PIPE_NAME_APP, state1, rules1, broadcaster1).await;
    });

    listen_pipe(PIPE_NAME_LEGACY, state, rules, broadcaster).await;
}

async fn listen_pipe(
    pipe_name: &str,
    state: Arc<EngineState>,
    rules: SharedRuleStore,
    broadcaster: EventBroadcaster,
) {
    let mut server_options = ServerOptions::new();
    server_options.first_pipe_instance(false);

    loop {
        match create_pipe_server(&server_options, pipe_name) {
            Ok(server) => {
                let state_clone = Arc::clone(&state);
                let rules_clone = Arc::clone(&rules);
                let broadcaster_clone = broadcaster.clone();

                match server.connect().await {
                    Ok(()) => {
                        tokio::spawn(async move {
                            handle_client(server, state_clone, rules_clone, broadcaster_clone).await;
                        });
                    }
                    Err(e) => {
                        warn!("Pipe client connect error on {}: {}", pipe_name, e);
                    }
                }
            }
            Err(e) => {
                error!("Failed to create named pipe {}: {}", pipe_name, e);
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        }
    }
}

fn create_pipe_server(
    options: &ServerOptions,
    pipe_name: &str,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use std::ffi::c_void;
    use std::ptr;
    use windows_sys::Win32::Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SECURITY_ATTRIBUTES,
    };

    let sddl: Vec<u16> = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut security_descriptor: *mut c_void = ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut security_descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security_descriptor,
        bInheritHandle: 0,
    };
    let attributes_ptr = (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>();
    let result = unsafe { options.create_with_security_attributes_raw(pipe_name, attributes_ptr) };
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(security_descriptor);
    }
    result
}

async fn handle_client(
    stream: tokio::net::windows::named_pipe::NamedPipeServer,
    state: Arc<EngineState>,
    rules: SharedRuleStore,
    broadcaster: EventBroadcaster,
) {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = TokioBufReader::new(reader).lines();
    let mut rx = broadcaster.subscribe();

    loop {
        tokio::select! {
            line_result = lines.next_line() => {
                match line_result {
                    Ok(Some(line)) => {
                        let response_str = handle_request_line(&line, &state, &rules, &broadcaster).await;
                        if writer.write_all(format!("{}\n", response_str).as_bytes()).await.is_err() {
                            break;
                        }
                    }
                    _ => break, // Client disconnected or error
                }
            }
            // Push events to connected client
            event_result = rx.recv() => {
                if let Ok(event_json) = event_result {
                    if writer.write_all(format!("{}\n", event_json).as_bytes()).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
}
