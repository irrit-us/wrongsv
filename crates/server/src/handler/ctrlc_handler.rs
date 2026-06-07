use tracing::info;


use super::*;

pub(crate) fn install_ctrlc_handler(shutdown: ShutdownSignal) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = ctrlc::set_handler(move || {
        if !shutdown.is_shutdown_requested() {
            eprintln!("received interrupt signal, shutting down gracefully...");
            info!("received interrupt signal, shutting down gracefully...");
            shutdown.shutdown();
        } else {
            eprintln!("second interrupt — forcing exit");
            std::process::exit(1);
        }
    }) && !matches!(e, ctrlc::Error::MultipleHandlers)
    {
        return Err(format!("failed to set Ctrl-C handler: {e}").into());
    }
    Ok(())
}
