//! Command registry for dispatching requests to handlers.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, info};

use crate::error::{CommandErrorKind, DaemonError};
use crate::templates::TemplateEngine;

use super::database::{CreateDatabaseCommand, CreateDatabaseUserCommand, DropDatabaseCommand};
use super::file::{
    CreateDirectoryCommand, DeleteFileCommand, SetPermissionsCommand, WriteFileCommand,
    WriteTemplateCommand,
};
use super::nginx::{DisableNginxSiteCommand, EnableNginxSiteCommand, TestNginxConfigCommand};
use super::package::{
    AddRepositoryCommand, InstallPackageCommand, RemovePackageCommand, UpdatePackageCommand,
};
use super::php::{
    InstallPhpExtensionCommand, InstallPhpVersionCommand, RemovePhpExtensionCommand,
    RemovePhpVersionCommand, WritePhpIniCommand,
};
use super::service::{
    DisableServiceCommand, EnableServiceCommand, ReloadServiceCommand, RestartServiceCommand,
    StartServiceCommand, StatusServiceCommand, StopServiceCommand,
};
use super::ssl::{InstallCertificateCommand, RequestLetsEncryptCommand};
use super::system::{MetricsCommand, PingCommand};
use super::traits::Command;
use super::types::{CommandParams, CommandResult, ExecutionContext};
use super::user::{CreateUserCommand, DeleteUserCommand};
use crate::auth::NonceStore;
use crate::socket::ConnectionMetrics;

/// Registry of all available commands.
#[derive(Clone)]
pub struct CommandRegistry {
    commands: HashMap<&'static str, Arc<dyn Command>>,
}

impl CommandRegistry {
    /// Create a new command registry with all built-in commands.
    ///
    /// Requires a TemplateEngine for template-based commands,
    /// and optionally metrics/nonce_store for the metrics command.
    pub fn new(
        template_engine: Arc<TemplateEngine>,
        metrics: Option<Arc<ConnectionMetrics>>,
        nonce_store: Option<Arc<NonceStore>>,
    ) -> Self {
        let mut registry = Self {
            commands: HashMap::new(),
        };

        // System commands
        registry.register(Arc::new(PingCommand));
        if let (Some(metrics), Some(nonce_store)) = (metrics, nonce_store) {
            registry.register(Arc::new(MetricsCommand::new(metrics, nonce_store)));
        }

        // File commands
        registry.register(Arc::new(WriteFileCommand));
        registry.register(Arc::new(DeleteFileCommand));
        registry.register(Arc::new(CreateDirectoryCommand));
        registry.register(Arc::new(SetPermissionsCommand));
        registry.register(Arc::new(WriteTemplateCommand::new(template_engine)));

        // Service commands
        registry.register(Arc::new(StartServiceCommand));
        registry.register(Arc::new(StopServiceCommand));
        registry.register(Arc::new(RestartServiceCommand));
        registry.register(Arc::new(ReloadServiceCommand));
        registry.register(Arc::new(EnableServiceCommand));
        registry.register(Arc::new(DisableServiceCommand));
        registry.register(Arc::new(StatusServiceCommand));

        // Package commands
        registry.register(Arc::new(InstallPackageCommand));
        registry.register(Arc::new(RemovePackageCommand));
        registry.register(Arc::new(UpdatePackageCommand));
        registry.register(Arc::new(AddRepositoryCommand));

        // Database commands
        registry.register(Arc::new(CreateDatabaseCommand));
        registry.register(Arc::new(CreateDatabaseUserCommand));
        registry.register(Arc::new(DropDatabaseCommand));

        // SSL commands
        registry.register(Arc::new(InstallCertificateCommand));
        registry.register(Arc::new(RequestLetsEncryptCommand));

        // PHP commands
        registry.register(Arc::new(InstallPhpVersionCommand));
        registry.register(Arc::new(RemovePhpVersionCommand));
        registry.register(Arc::new(InstallPhpExtensionCommand));
        registry.register(Arc::new(RemovePhpExtensionCommand));
        registry.register(Arc::new(WritePhpIniCommand));

        // Nginx commands
        registry.register(Arc::new(EnableNginxSiteCommand));
        registry.register(Arc::new(DisableNginxSiteCommand));
        registry.register(Arc::new(TestNginxConfigCommand));

        // User commands
        registry.register(Arc::new(CreateUserCommand));
        registry.register(Arc::new(DeleteUserCommand));

        info!(
            count = registry.commands.len(),
            "Command registry initialized"
        );

        registry
    }

    /// Register a command.
    fn register(&mut self, command: Arc<dyn Command>) {
        let name = command.name();
        debug!(command = name, "Registering command");
        self.commands.insert(name, command);
    }

    /// Get a command by name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn Command>> {
        self.commands.get(name).cloned()
    }

    /// Dispatch a request to the appropriate command handler.
    pub fn dispatch(
        &self,
        ctx: &ExecutionContext,
        command_name: &str,
        params: CommandParams,
    ) -> Result<CommandResult, DaemonError> {
        // Look up the command
        let command = self
            .commands
            .get(command_name)
            .ok_or_else(|| DaemonError::Command {
                kind: CommandErrorKind::UnknownCommand {
                    name: command_name.to_string(),
                },
            })?;

        // Validate parameters
        command.validate(&params)?;

        // Execute the command
        command.execute(ctx, params)
    }

    /// List all registered command names.
    pub fn list_commands(&self) -> Vec<&'static str> {
        self.commands.keys().copied().collect()
    }
}

impl Default for CommandRegistry {
    fn default() -> Self {
        // Use an empty template engine for default - mainly for testing
        // No metrics command in default (no metrics/nonce_store)
        Self::new(Arc::new(TemplateEngine::empty()), None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PeerInfo;
    use uuid::Uuid;

    fn create_test_context() -> ExecutionContext {
        ExecutionContext::new(
            Uuid::new_v4(),
            PeerInfo {
                uid: 1000,
                gid: 1000,
                pid: 12345,
            },
            1234567890,
            "test.command".to_string(),
        )
    }

    #[test]
    fn test_registry_has_commands() {
        let registry = CommandRegistry::default();
        // System commands
        assert!(registry.get("system.ping").is_some());
        // File commands
        assert!(registry.get("file.write").is_some());
        assert!(registry.get("file.write_template").is_some());
        // Service commands
        assert!(registry.get("service.start").is_some());
        assert!(registry.get("service.stop").is_some());
        assert!(registry.get("service.restart").is_some());
        assert!(registry.get("service.reload").is_some());
        assert!(registry.get("service.enable").is_some());
        assert!(registry.get("service.disable").is_some());
        assert!(registry.get("service.status").is_some());
        // Package commands
        assert!(registry.get("package.install").is_some());
        assert!(registry.get("package.remove").is_some());
        assert!(registry.get("package.update").is_some());
        assert!(registry.get("package.add_repository").is_some());
        // Database commands
        assert!(registry.get("database.create_db").is_some());
        assert!(registry.get("database.create_user").is_some());
        assert!(registry.get("database.drop_db").is_some());
        // SSL commands
        assert!(registry.get("ssl.install_cert").is_some());
        assert!(registry.get("ssl.request_letsencrypt").is_some());
        // PHP commands
        assert!(registry.get("php.install_version").is_some());
        assert!(registry.get("php.remove_version").is_some());
        assert!(registry.get("php.install_extension").is_some());
        assert!(registry.get("php.remove_extension").is_some());
        assert!(registry.get("php.write_ini").is_some());
        // Nginx commands
        assert!(registry.get("nginx.enable_site").is_some());
        assert!(registry.get("nginx.disable_site").is_some());
        assert!(registry.get("nginx.test_config").is_some());
        // User commands
        assert!(registry.get("user.create").is_some());
        assert!(registry.get("user.delete").is_some());
        // Non-existent command
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_dispatch_unknown_command() {
        let registry = CommandRegistry::default();
        let ctx = create_test_context();
        let params = CommandParams::new(serde_json::json!({}));

        let result = registry.dispatch(&ctx, "unknown.command", params);
        assert!(matches!(
            result,
            Err(DaemonError::Command {
                kind: CommandErrorKind::UnknownCommand { .. }
            })
        ));
    }

    #[test]
    fn test_dispatch_ping() {
        let registry = CommandRegistry::default();
        let ctx = create_test_context();
        let params = CommandParams::new(serde_json::json!({}));

        let result = registry.dispatch(&ctx, "system.ping", params);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_registry_with_metrics() {
        use std::time::Duration;

        let metrics = Arc::new(ConnectionMetrics::new());
        let nonce_store = Arc::new(NonceStore::new(Duration::from_secs(60)));

        let registry = CommandRegistry::new(
            Arc::new(TemplateEngine::empty()),
            Some(metrics),
            Some(nonce_store),
        );

        // Should have the metrics command
        assert!(registry.get("system.metrics").is_some());
    }
}
