//! Lumo Daemon - Privilege daemon for executing privileged operations via Unix socket.

use std::env;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::signal;
use tokio::sync::Notify;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use lumo_daemon::auth::NonceStore;
use lumo_daemon::config::Settings;
use lumo_daemon::socket::SocketListener;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const NAME: &str = env!("CARGO_PKG_NAME");

fn main() -> ExitCode {
    // Parse command line arguments (simple std::env approach)
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return ExitCode::SUCCESS;
    }

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("{} {}", NAME, VERSION);
        return ExitCode::SUCCESS;
    }

    // Get config path from --config argument or default
    let config_path = get_config_path(&args);

    // Load configuration
    let settings = match Settings::load(&config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error loading configuration: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Initialize logging based on configuration
    if let Err(e) = init_logging(&settings) {
        eprintln!("Error initializing logging: {}", e);
        return ExitCode::FAILURE;
    }

    // Print startup banner
    info!("Starting {} v{}", NAME, VERSION);
    info!("Configuration loaded from: {}", config_path);
    info!("Socket path: {}", settings.socket.path.display());
    info!("Log level: {}", settings.logging.level);

    // Run the async main
    let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    match runtime.block_on(async_main(settings, config_path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %e, "Daemon failed");
            ExitCode::FAILURE
        }
    }
}

/// Async main function.
async fn async_main(
    settings: Settings,
    config_path: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let settings = Arc::new(std::sync::RwLock::new(settings));

    // Create the nonce store for replay attack prevention
    let nonce_ttl = Duration::from_secs(settings.read().unwrap().security.nonce_ttl_seconds);
    let nonce_store = Arc::new(NonceStore::new(nonce_ttl));

    // Start the nonce cleanup task
    nonce_store.start_cleanup_task(Duration::from_secs(60));

    // Create and bind the socket listener
    let settings_snapshot = settings.read().unwrap().clone();
    let listener =
        SocketListener::bind(Arc::new(settings_snapshot), Arc::clone(&nonce_store)).await?;

    // Create shutdown notification
    let shutdown = Arc::new(Notify::new());
    let shutdown_for_run = Arc::clone(&shutdown);

    // Run the listener with graceful shutdown
    loop {
        tokio::select! {
            result = listener.run(Arc::clone(&shutdown_for_run)) => {
                if let Err(e) = result {
                    error!(error = %e, "Socket listener failed");
                    return Err(e.into());
                }
                break;
            }
            _ = shutdown_signal() => {
                info!("Shutdown signal received, initiating graceful shutdown...");
                shutdown.notify_waiters();

                // Wait for connections to drain with timeout
                let drain_timeout = Duration::from_secs(30);
                match tokio::time::timeout(drain_timeout, listener.wait_for_drain()).await {
                    Ok(()) => info!("Graceful shutdown complete"),
                    Err(_) => warn!(
                        "Shutdown timeout after {}s, some connections may be terminated",
                        drain_timeout.as_secs()
                    ),
                }
                break;
            }
            _ = reload_signal() => {
                info!("Reload signal received, reloading configuration...");
                match Settings::load(&config_path) {
                    Ok(new_settings) => {
                        match settings.write() {
                            Ok(mut guard) => {
                                *guard = new_settings;
                                info!("Configuration reloaded successfully");
                            }
                            Err(e) => {
                                error!(error = %e, "Failed to acquire settings lock for reload");
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to reload configuration, keeping existing settings");
                    }
                }
            }
        }
    }

    info!("Daemon stopped");
    Ok(())
}

/// Wait for a shutdown signal (SIGTERM or SIGINT).
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

/// Wait for a reload signal (SIGHUP).
#[cfg(unix)]
async fn reload_signal() {
    signal::unix::signal(signal::unix::SignalKind::hangup())
        .expect("Failed to install SIGHUP handler")
        .recv()
        .await;
}

/// No-op reload signal for non-Unix platforms.
#[cfg(not(unix))]
async fn reload_signal() {
    std::future::pending::<()>().await;
}

/// Print help message.
fn print_help() {
    println!(
        r#"{} {}
Lumo privilege daemon for executing privileged operations via Unix socket.

USAGE:
    {} [OPTIONS]

OPTIONS:
    -c, --config <PATH>    Path to configuration file
                           [default: /etc/lumo/daemon.toml]
    -h, --help             Print help information
    -V, --version          Print version information
"#,
        NAME, VERSION, NAME
    );
}

/// Get configuration file path from command line arguments.
fn get_config_path(args: &[String]) -> String {
    for (i, arg) in args.iter().enumerate() {
        if (arg == "--config" || arg == "-c") && i + 1 < args.len() {
            return args[i + 1].clone();
        }
        if let Some(path) = arg.strip_prefix("--config=") {
            return path.to_string();
        }
    }
    // Default path
    "/etc/lumo/daemon.toml".to_string()
}

/// Initialize logging based on settings.
fn init_logging(settings: &Settings) -> Result<(), Box<dyn std::error::Error>> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&settings.logging.level));

    match settings.logging.format.to_lowercase().as_str() {
        "json" => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json())
                .init();
        }
        _ => {
            // Default to pretty format
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().pretty())
                .init();
        }
    }

    Ok(())
}
